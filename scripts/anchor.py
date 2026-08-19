#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Continuous Bitcoin anchoring for the public GRIP decision chain.

The chain is idr-public.jsonl (one JSON line per shipped decision). Anchoring
works in cumulative batches: batch K commits the RFC-6962 Merkle root over the
FIRST K raw lines of the file, and a manifest carrying that root is stamped
into the Bitcoin blockchain via the reference OpenTimestamps client. Anybody
can recompute the root from the public file alone (scripts/verify-anchors.js),
so the anchor binds the exact public bytes — not a summary someone else made.

Pipeline stages (each idempotent by construction — a repeat run with an
unchanged chain makes zero new calendar/blockchain calls for the same batch):

  check    arithmetic verification of everything on disk: chain linkage, every
           manifest's root recomputes from the public lines, state monotonicity.
  stamp    anchor the newest eligible cumulative prefix (policy: --min-new
           entries since the last anchor, or --max-age-hours staleness). Builds
           the deterministic manifest, stamps it with the reference ots client
           (public calendar servers — no keys, no credentials), records it as
           pending.
  upgrade  advance pending proofs to Bitcoin block attestations (ots upgrade),
           then confirm each attested block against >= 2 independent block-header
           sources that must agree EXACTLY — a verdict is never manufactured.
  report   human-readable status of every anchor.

Monotone rule: an anchor may only move pending -> confirmed, and only when the
ots client computed the attestation AND the independent header sources agree.
Nothing here ever fakes a confirmation, and nothing ever re-stamps a manifest
whose bytes already exist (content-addressed idempotency).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CHAIN_FILE = REPO / "idr-public.jsonl"
ANCHORS_DIR = REPO / "anchors"
STATE_FILE = ANCHORS_DIR / "state.json"
LATEST_FILE = ANCHORS_DIR / "latest.json"

MANIFEST_SCHEMA = "grip-decision-chain-anchor-manifest/1"
STATE_SCHEMA = "grip-decision-chain-anchor-state/1"

MIN_NEW_DEFAULT = 25
MAX_AGE_HOURS_DEFAULT = 24

#: Two independent block explorers. A confirmation needs them to agree EXACTLY
#: on hash + merkle root + timestamp; disagreement means "unverified", never a
#: majority vote. (Same tier-2 discipline as grasp.storage.ots.)
HEADER_SOURCES: tuple[tuple[str, str], ...] = (
    ("blockstream.info", "https://blockstream.info/api"),
    ("mempool.space", "https://mempool.space/api"),
)
MIN_AGREEING = 2
HTTP_TIMEOUT = 15

#: ots client output shapes seen in the wild (0.7.x wording first, older second).
_ATTEST_RE = re.compile(
    r"check that Bitcoin block (\d+) has merkleroot ([0-9a-fA-F]{64})")
_ATTEST_RE_LEGACY = re.compile(
    r"Bitcoin block (\d+) has merkleroot ([0-9a-fA-F]{64})")


# ---------------------------------------------------------------------------
# RFC 6962 Merkle tree (pure stdlib; domain-separated leaves 0x00 / nodes 0x01)
# ---------------------------------------------------------------------------

def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _mth(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return _leaf_hash(leaves[0])
    k = 1
    while k < n:
        k <<= 1
    k >>= 1
    return _node_hash(_mth(leaves[:k]), _mth(leaves[k:]))


def merkle_root(leaves: list[bytes]) -> str:
    """Hex RFC-6962 root committing to every leaf, in order."""
    return _mth(leaves).hex()


# ---------------------------------------------------------------------------
# Chain + state IO
# ---------------------------------------------------------------------------

def load_lines(path: Path = CHAIN_FILE) -> list[str]:
    """Raw JSONL lines without the trailing newline — the exact leaf bytes."""
    return path.read_text(encoding="utf-8").splitlines()


def parse_rows(lines: list[str]) -> list[dict]:
    return [json.loads(l) for l in lines]


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_state() -> dict:
    if STATE_FILE.exists():
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    return {"schema": STATE_SCHEMA, "anchors": []}


def write_state(state: dict) -> None:
    _atomic_write(STATE_FILE, json.dumps(state, indent=2, sort_keys=True) + "\n")


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def manifest_path(anchor: dict) -> Path:
    return REPO / anchor["manifest"]


def proof_path(anchor: dict) -> Path:
    return REPO / anchor["proof"]


# ---------------------------------------------------------------------------
# Verification (monotone: a failing check halts the pipeline)
# ---------------------------------------------------------------------------

def check_chain(lines: list[str]) -> list[str]:
    errors: list[str] = []
    try:
        rows = parse_rows(lines)
    except (json.JSONDecodeError, ValueError) as exc:
        return [f"idr-public.jsonl is not parseable: {exc}"]
    prev = None
    for i, row in enumerate(rows):
        got = row.get("prev_sha")
        if got != prev:
            errors.append(
                f"chain BROKEN at entry {i + 1}: prev_sha {got!r} != {prev!r}")
            break
        prev = row.get("sha")
    return errors


def check_anchor_arithmetic(anchor: dict, lines: list[str]) -> list[str]:
    """Every anchor must recompute its root from the public lines alone."""
    errors: list[str] = []
    k = anchor.get("rows")
    if not isinstance(k, int) or k < 1 or k > len(lines):
        return [f"anchor rows {k!r} is not a valid prefix length (chain has {len(lines)})"]
    manifest = manifest_path(anchor)
    if not manifest.exists():
        return [f"manifest missing: {anchor.get('manifest')}"]
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"manifest unreadable {anchor.get('manifest')}: {exc}"]
    declared = data.get("canonical_merkle_root_rfc6962")
    recomputed = merkle_root([l.encode("utf-8") for l in lines[:k]])
    if declared != recomputed:
        errors.append(
            f"manifest {anchor.get('manifest')} declares root {declared!r} but "
            f"the first {k} public lines recompute to {recomputed!r}")
    if data.get("rows") != k:
        errors.append(f"manifest {anchor.get('manifest')} rows field "
                      f"{data.get('rows')!r} != state rows {k}")
    if not proof_path(anchor).exists():
        errors.append(f"proof missing: {anchor.get('proof')}")
    return errors


def check_state(state: dict, lines: list[str]) -> list[str]:
    errors: list[str] = []
    anchors = state.get("anchors")
    if not isinstance(anchors, list) or not anchors:
        return ["state has no anchors — run stamp first"]
    seen_rows: list[int] = []
    for anchor in anchors:
        status = anchor.get("status")
        if status not in ("pending", "confirmed"):
            errors.append(f"anchor rows={anchor.get('rows')} has bad status {status!r}")
        errors.extend(check_anchor_arithmetic(anchor, lines))
        seen_rows.append(anchor.get("rows"))
    if seen_rows != sorted(seen_rows) or len(set(seen_rows)) != len(seen_rows):
        errors.append("anchor rows must be strictly increasing (cumulative batches)")
    return errors


def run_check(state: dict | None = None, lines: list[str] | None = None) -> int:
    if lines is None:
        lines = load_lines()
    if state is None:
        state = read_state()
    errors = check_chain(lines) + check_state(state, lines)
    if errors:
        for e in errors:
            print(f"CHECK FAIL: {e}")
        return 2
    print(f"CHECK OK: chain of {len(lines)} entries links; "
          f"{len(state.get('anchors', []))} anchor(s) verify arithmetically")
    return 0


# ---------------------------------------------------------------------------
# Manifest building (deterministic — no timestamps inside the stamped bytes)
# ---------------------------------------------------------------------------

def build_manifest(lines: list[str], k: int, prev_rows: int) -> dict:
    head = json.loads(lines[k - 1])
    return {
        "schema": MANIFEST_SCHEMA,
        "artifact": "grip-public-decision-chain",
        "rows": k,
        "prev_rows": prev_rows,
        "canonical_merkle_root_rfc6962": merkle_root(
            [l.encode("utf-8") for l in lines[:k]]),
        "leaf_definition": ("each exact JSONL line of idr-public.jsonl, in "
                            "order — the first rows lines"),
        "chain_head_sha": head.get("sha"),
        "chain_head_ts": head.get("ts"),
        "verify": ("recompute the RFC-6962 Merkle root over the first rows "
                   "raw lines of idr-public.jsonl; it must equal "
                   "canonical_merkle_root_rfc6962. Then run 'ots info' on this "
                   "file's .ots proof — or scripts/verify-anchors.js — to "
                   "check the Bitcoin commitment of this manifest."),
    }


def manifest_bytes(manifest: dict) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def find_anchor(state: dict, rows: int) -> dict | None:
    for a in state.get("anchors", []):
        if a.get("rows") == rows:
            return a
    return None


# ---------------------------------------------------------------------------
# ots client wrappers
# ---------------------------------------------------------------------------

def ots_available() -> bool:
    return shutil.which("ots") is not None


def run_ots(argv: list[str], timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["ots"] + argv, capture_output=True, text=True, timeout=timeout,
            check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(["ots"] + argv, -1, "", str(exc))


# ---------------------------------------------------------------------------
# stamp — anchor the newest eligible cumulative prefix
# ---------------------------------------------------------------------------

def stamp(min_new: int, max_age_hours: float) -> int:
    lines = load_lines()
    total = len(lines)
    if not total:
        print("stamp: chain is empty — nothing to anchor")
        return 0
    state = read_state()
    if run_check(state, lines) != 0:
        return 2
    if not ots_available():
        print("stamp: the OpenTimestamps client (ots) is not on PATH — "
              "install it: pip install opentimestamps-client")
        return 1

    last = max((a["rows"] for a in state["anchors"]), default=0)
    if total <= last:
        print(f"stamp: up to date — {total} entries, all anchored up to {last}")
        return 0

    unanchored = parse_rows(lines[last:])
    age_hours = _age_hours(unanchored[0].get("ts"))
    new_count = total - last
    eligible = new_count >= min_new or (age_hours is not None
                                        and age_hours >= max_age_hours)
    if not eligible:
        print(f"stamp: {new_count} new entr(ies) (oldest {age_hours:.1f}h old) "
              f"— below min-new={min_new} and max-age={max_age_hours}h; waiting")
        return 0

    k = total
    root = merkle_root([l.encode("utf-8") for l in lines[:k]])
    existing = find_anchor(state, k)
    if existing is not None and existing.get("merkle_root") == root:
        print(f"stamp: batch rows={k} already anchored "
              f"({existing.get('status')}) — idempotent skip")
        return 0

    manifest = build_manifest(lines, k, prev_rows=last)
    path = ANCHORS_DIR / f"anchor-manifest-{k}.json"
    proof = path.with_suffix(".json.ots")
    path.write_bytes(manifest_bytes(manifest))

    stamped = False
    for attempt in (1, 2, 3):
        done = run_ots(["stamp", str(path)], timeout=150)
        if done.returncode == 0 and proof.exists():
            stamped = True
            break
        print(f"stamp: attempt {attempt} failed (rc={done.returncode}); retrying…")
        time.sleep(8)
    if not stamped:
        print("stamp: ots stamp failed after 3 attempts — calendar servers "
              "unreachable; try again later (no state changed)")
        return 1

    anchor = {
        "rows": k,
        "merkle_root": root,
        "manifest": f"anchors/anchor-manifest-{k}.json",
        "proof": f"anchors/anchor-manifest-{k}.json.ots",
        "status": "pending",
        "stamped_utc": now_utc(),
        "prev_rows": last,
    }
    state["anchors"].append(anchor)
    write_state(state)
    write_latest(state, total)
    print(f"stamp: anchored rows=1..{k} — root {root} submitted to the OTS "
          f"calendars (Bitcoin attestation lands within hours; upgrade "
          f"records it)")
    return 0


def _age_hours(ts: str | None) -> float | None:
    try:
        t = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - t).total_seconds() / 3600.0


# ---------------------------------------------------------------------------
# upgrade — advance pending proofs to Bitcoin attestations (verified honestly)
# ---------------------------------------------------------------------------

def _attested_pairs(manifest: Path, proof: Path) -> list[tuple[int, str]]:
    done = run_ots(["--no-bitcoin", "verify", "-f", str(manifest), str(proof)],
                   timeout=150)
    text = (done.stdout or "") + (done.stderr or "")
    pairs = [(int(h), r.lower()) for h, r in _ATTEST_RE.findall(text)]
    if not pairs:
        pairs = [(int(h), r.lower()) for h, r in _ATTEST_RE_LEGACY.findall(text)]
    return pairs


def _fetch_height(source: str, base: str, height: int) -> dict:
    """One explorer's view of a block header. ok=False carries the reason."""
    try:
        block_hash = _http_get(f"{base}/block-height/{height}")
        if not re.fullmatch(r"[0-9a-f]{64}", block_hash):
            return {"source": source, "ok": False,
                    "error": f"expected a block hash, got {block_hash[:32]!r}"}
        data = json.loads(_http_get(f"{base}/block/{block_hash}"))
        return {"source": source, "ok": True, "block_hash": block_hash,
                "merkleroot": str(data["merkle_root"]).lower(),
                "time": int(data["timestamp"])}
    except Exception as exc:  # noqa: BLE001 — classified, never silently dropped
        return {"source": source, "ok": False, "error": _describe_error(exc)}


def _http_get(url: str) -> str:
    if not url.startswith("https://"):
        raise ValueError("header sources must be https")
    req = urllib.request.Request(url, headers={"User-Agent": "grasp-ots/1"})
    with _OPENER.open(req, timeout=HTTP_TIMEOUT) as resp:
        return resp.read().decode("utf-8", "replace").strip()


class _RefusedRedirect(urllib.error.HTTPError):
    pass


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise _RefusedRedirect(
                newurl, code, "refusing a redirect to a non-https header "
                "source…", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirects)


def _describe_error(exc: Exception) -> str:
    if isinstance(exc, _RefusedRedirect):
        return str(exc.reason)
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(exc, urllib.error.URLError):
        return f"unreachable ({exc.reason})"
    if isinstance(exc, json.JSONDecodeError):
        return "malformed JSON"
    if isinstance(exc, KeyError):
        return f"response missing field {exc}"
    if isinstance(exc, TimeoutError):
        return "timed out"
    if isinstance(exc, ValueError):
        return str(exc)
    return type(exc).__name__


def _confirm_block(height: int, claimed_root: str) -> dict | None:
    """>= 2 sources must agree EXACTLY and match the proof's computed root."""
    answers = [_fetch_height(name, base, height)
               for name, base in HEADER_SOURCES]
    seen = [a for a in answers if a["ok"]]
    if len(seen) < MIN_AGREEING:
        print(f"  block {height}: only {len(seen)}/{len(HEADER_SOURCES)} "
              "sources answered — not confirmed")
        return None
    key = ("block_hash", "merkleroot", "time")
    first = seen[0]
    if any(tuple(h[k] for k in key) != tuple(first[k] for k in key)
           for h in seen[1:]):
        print(f"  block {height}: header sources DISAGREE — not confirmed")
        return None
    if first["merkleroot"] != claimed_root:
        print(f"  block {height}: MERKLEROOT MISMATCH — the proof commits to "
              f"{claimed_root} but the block really carries {first['merkleroot']}")
        return None
    return {
        "block_hash": first["block_hash"],
        "block_time_utc": datetime.fromtimestamp(
            first["time"], tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": [a["source"] for a in seen],
    }


def upgrade() -> int:
    lines = load_lines()
    total = len(lines)
    state = read_state()
    if run_check(state, lines) != 0:
        return 2
    if not ots_available():
        print("upgrade: ots client not on PATH")
        return 1
    changed = False
    for anchor in state["anchors"]:
        if anchor.get("status") == "confirmed":
            continue
        manifest = manifest_path(anchor)
        proof = proof_path(anchor)
        done = run_ots(["upgrade", str(proof)], timeout=300)
        # Note: a FRESH pending proof makes the ots upgrade subcommand exit
        # non-zero ("timestamp not complete" — the calendar has not merged
        # it yet). That is an honest state, not a pipeline failure: the
        # attestation parse below is the source of truth, so it always runs.
        if done.returncode != 0:
            print(f"upgrade: rows={anchor['rows']} — ots upgrade rc="
                  f"{done.returncode} (normal for fresh pending proofs); "
                  "parse still runs")
        pairs = _attested_pairs(manifest, proof)
        if not pairs:
            print(f"upgrade: rows={anchor['rows']} — still a calendar "
                  "commitment, no Bitcoin attestation yet")
            continue
        confirmed: dict | None = None
        for height, merkleroot in sorted(pairs):
            verdict = _confirm_block(height, merkleroot)
            if verdict is not None:
                confirmed = {"block": height, "merkleroot": merkleroot,
                             **verdict}
        if confirmed is None:
            print(f"upgrade: rows={anchor['rows']} — attestations found but "
                  "none passed the independent header check; staying pending")
            continue
        anchor["status"] = "confirmed"
        anchor["bitcoin_blocks"] = sorted(h for h, _ in pairs)
        anchor["confirmed_block"] = confirmed["block"]
        anchor["block_hash"] = confirmed["block_hash"]
        anchor["block_time_utc"] = confirmed["block_time_utc"]
        anchor["confirmed_sources"] = confirmed["sources"]
        anchor["confirmed_at_utc"] = now_utc()
        changed = True
        print(f"upgrade: rows={anchor['rows']} CONFIRMED in Bitcoin block "
              f"{confirmed['block']} ({confirmed['block_time_utc']}) via "
              f"{len(confirmed['sources'])} agreeing header sources")
    if changed:
        write_state(state)
    write_latest(state, total)
    return 0


# ---------------------------------------------------------------------------
# latest.json — the page's machine-readable summary
# ---------------------------------------------------------------------------

def write_latest(state: dict, total_rows: int) -> None:
    anchors = state.get("anchors", [])
    confirmed = [a for a in anchors if a.get("status") == "confirmed"]
    pending = [a for a in anchors if a.get("status") == "pending"]
    latest_confirmed = max(confirmed, key=lambda a: a["rows"]) if confirmed else None
    pending_anchor = max(pending, key=lambda a: a["rows"]) if pending else None
    latest = {
        "schema": STATE_SCHEMA,
        "generated_at": now_utc(),
        "total_rows": total_rows,
        "anchored_rows": max((a["rows"] for a in anchors), default=0),
        "latest_confirmed": latest_confirmed,
        "pending_anchor": pending_anchor,
        "history": sorted(anchors, key=lambda a: a["rows"], reverse=True),
    }
    _atomic_write(LATEST_FILE, json.dumps(latest, indent=2, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# report / CLI
# ---------------------------------------------------------------------------

def report() -> int:
    lines = load_lines()
    state = read_state()
    print(f"chain: {len(lines)} entries")
    for a in sorted(state.get("anchors", []), key=lambda x: x["rows"]):
        block = a.get("confirmed_block")
        print(f"  rows=1..{a['rows']:<6} {a['status']:<9} "
              f"root={a['merkle_root'][:16]}… "
              + (f"block={block} ({a.get('block_time_utc', '?')})" if block
                 else f"stamped {a.get('stamped_utc', '?')}"))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="anchor.py",
        description="Continuous Bitcoin anchoring for the public decision chain")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="verify chain + anchor arithmetic on disk")
    p_stamp = sub.add_parser("stamp", help="anchor the newest eligible batch")
    p_stamp.add_argument("--min-new", type=int, default=MIN_NEW_DEFAULT)
    p_stamp.add_argument("--max-age-hours", type=float,
                         default=MAX_AGE_HOURS_DEFAULT)
    sub.add_parser("upgrade", help="advance pending proofs to Bitcoin blocks")
    sub.add_parser("report", help="print anchor status")

    args = parser.parse_args(argv)
    if args.command == "check":
        return run_check()
    if args.command == "stamp":
        return stamp(args.min_new, args.max_age_hours)
    if args.command == "upgrade":
        return upgrade()
    if args.command == "report":
        return report()
    return 2


if __name__ == "__main__":
    sys.exit(main())
