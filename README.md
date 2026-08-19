# GRIP — Decision Chain

A public, order-evident record of the decisions [GRIP](https://github.com/CodeTonight-SA/GRIP)'s
AI shipped to its own codebase — and a way for anyone to check that the record hasn't been
tampered with.

**Live view:** https://codetonight-sa.github.io/grip-decision-chain/

## What's in it

[`idr-public.jsonl`](./idr-public.jsonl) — one row per shipped commit:

```json
{"sha": "...", "subject": "feat(precog): P6 — warm-start reads signed context-chain", "ts": "2026-06-10T11:12:51+02:00", "prev_sha": "..."}
```

Four fields, by construction — the commit hash, its one-line subject, its timestamp, and the
hash of the entry before it. **No code, no diffs, no file paths, no client data.** It's an
allowlist, not a redaction: nothing else can leak because nothing else is ever written.

## What it proves

`prev_sha` links every row to the one before it, so the file is **order-evident**: removing or
reordering any entry leaves a visible gap. It proves **order integrity and append-history** —
the decisions are real commits, in the order they happened, with nothing quietly dropped.

It is **not** an independent cryptographic signature, and while GRIP's source stays private it
doesn't let an outsider confirm each hash against the repository. It lets you confirm the chain
is internally consistent and unbroken.

## Verify it yourself

No dependencies:

```bash
curl -sO https://codetonight-sa.github.io/grip-decision-chain/idr-public.jsonl
curl -sO https://codetonight-sa.github.io/grip-decision-chain/verify.js
node verify.js idr-public.jsonl
# → chain OK · N entries        (exit 0)
# → chain BROKEN at entry K     (exit 1)
```

To verify the Bitcoin anchors too (still no dependencies, no Bitcoin node):

```bash
curl -sO https://codetonight-sa.github.io/grip-decision-chain/verify-anchors.js
mkdir -p anchors
curl -sO --output-dir anchors https://codetonight-sa.github.io/grip-decision-chain/anchors/state.json
node verify-anchors.js idr-public.jsonl anchors
# → chain OK · anchors OK — every anchor root recomputes from the public chain
```

Or open the [live view](https://codetonight-sa.github.io/grip-decision-chain/) — the same check
runs in your browser on load, and you can paste [`verify.js`](./verify.js) into the console to
re-run it against the loaded chain.

## How it stays current

Rows are appended by [`lib/idr_public_emitter.py`](https://github.com/CodeTonight-SA/GRIP) in the
GRIP repo (idempotent by sha — a commit is never recorded twice), then synced here. The chain
only ever grows; it is never rewritten.

## How it stays anchored

The chain is committed to Bitcoin in **cumulative batches** via OpenTimestamps. Batch K anchors
the RFC-6962 Merkle root over the first K raw lines of `idr-public.jsonl`, so the root is
recomputable by anyone from the public file alone. A GitHub Actions pipeline in this repo
(`.github/workflows/anchor.yml` + `scripts/anchor.py`):

- **stamps** a new batch when >= 25 entries accumulate since the last anchor (or after 24 h of
  staleness), submitting the manifest to the public OTS calendar servers — no keys, no credentials;
- **upgrades** pending proofs to Bitcoin attestations (usually within hours) and records the
  confirmed block only after >= 2 independent block explorers agree **exactly** with the proof's
  computed root — a confirmation is never fabricated;
- **publishes** everything here: `anchors/anchor-manifest-<K>.json` + its `.ots` proof,
  `anchors/state.json` (full history) and `anchors/latest.json` (what the live page shows).

The first anchor (rows 1–501, root `0bba0792…a7f1bcb4`) was stamped 2026-07-06 and confirmed in
Bitcoin block **956992** (2026-07-07). Every later batch extends the coverage; the live page shows
the newest confirmed block and any pending batch. Check any proof with the reference client:

```bash
ots info anchors/anchor-manifest-501-2026-07-06.json.ots
```

---

*GRIP — General Reasoning & Intelligence Platform. This is GRIP dogfooding its own decision-record
mechanism on itself: why did the AI do this, visibly.*
