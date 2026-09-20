#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
//
// browser-path.js — regression tests for verify.js's BROWSER console path,
// runnable in plain Node (no browser, no dependencies).
//
// How: verify.js decides it is in a browser when `process` is undefined and
// `window` exists. Running its source in a vm context that has no `process`
// but a stubbed `window`, `fetch` and WebCrypto takes exactly the code path a
// reader's console paste takes. The Merkle roots the fixtures expect are
// computed here with an INDEPENDENT RFC-6962 implementation (node:crypto), so
// a broken tree construction in verify.js cannot certify itself.
//
// Scenarios (S2 is the round-3 council concern this file pins):
//   S1 happy path        links OK + root + anchor OK + newer-entries caveat
//   S2 truncated chain   ANCHOR MISMATCH naming truncation — NOT "unavailable"
//   S3 tampered prefix   ANCHOR MISMATCH on root inequality
//   S4 malformed anchor  rows:-1 rejected -> honest skip
//   S5 fetch failure     honest skip
//   S6 broken link       chain BROKEN at the right entry
//   S7 redacted row      leaf_sha256 honoured inside the anchored prefix
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const nodeCrypto = require('crypto');

const SOURCE = fs.readFileSync(path.join(__dirname, '..', 'verify.js'), 'utf8');

// --- independent RFC 6962 reference (mirrors scripts/anchor.py) -------------
function leafHash(buf) {
  return nodeCrypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x00]), buf])).digest();
}
function nodeHash(l, r) {
  return nodeCrypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x01]), l, r])).digest();
}
// Reference leafOf mirrors the redaction contract (commit 0418738): a row the
// shield rewrote after anchoring carries leaf_sha256 = the pre-redaction leaf
// hash, which stands in for the served bytes.
function refLeafOf(line) {
  try {
    const row = JSON.parse(line);
    if (row && typeof row.leaf_sha256 === 'string' && /^[0-9a-f]{64}$/.test(row.leaf_sha256)) {
      return Buffer.from(row.leaf_sha256, 'hex');
    }
  } catch (e) { /* torn line: hash the bytes */ }
  return leafHash(Buffer.from(line, 'utf8'));
}
function mth(leafHashes) {
  const n = leafHashes.length;
  if (n === 0) return nodeCrypto.createHash('sha256').digest();
  if (n === 1) return leafHashes[0];
  let k = 1;
  while (k < n) k <<= 1;
  k >>= 1;
  return nodeHash(mth(leafHashes.slice(0, k)), mth(leafHashes.slice(k)));
}
const refRootHex = (lines) => mth(lines.map(refLeafOf)).toString('hex');

// --- fixture: a five-row chain with valid links -----------------------------
function fixtureRows() {
  const rows = [];
  let prev = null;
  for (let i = 1; i <= 5; i++) {
    const sha = String(i).repeat(40).slice(0, 40);
    rows.push({ sha, subject: 'decision ' + i, ts: '2026-09-20T0' + i + ':00:00+00:00', prev_sha: prev });
    prev = sha;
  }
  return rows;
}
const rawOf = (rows) => rows.map((r) => JSON.stringify(r));

// --- run verify.js's browser path in a process-free context -----------------
async function runBrowserPath({ rows, raw, latest, fetchFails }) {
  const lines = [];
  const push = (...a) => lines.push(a.join(' '));
  const sandbox = {
    console: { log: push, warn: push, error: push },
    window: {
      GRIP_CHAIN: rows,
      GRIP_CHAIN_RAW: raw,
      crypto: { subtle: nodeCrypto.webcrypto.subtle },
    },
    TextEncoder,
    fetch: async () => {
      if (fetchFails) throw new Error('network down');
      return { ok: true, json: async () => ({ latest_confirmed: latest }) };
    },
  };
  vm.createContext(sandbox);
  vm.runInContext(SOURCE, sandbox, { filename: 'verify.js' });
  // The IIFE's browser path is async and unawaited; settle by quiescence.
  // Three consecutive quiet ticks are required before believing it is done —
  // a single-tick check raced a slow first WebCrypto digest and flaked
  // (observed 2026-09-24: S1 lost every line after the sync links output).
  let before = -1;
  let quiet = 0;
  for (let i = 0; i < 80 && quiet < 3; i++) {
    quiet = lines.length === before ? quiet + 1 : 0;
    before = lines.length;
    await new Promise((r) => setTimeout(r, 100));
  }
  return lines.join('\n');
}

// --- scenarios --------------------------------------------------------------
const checks = [];
function expect(name, out, mustHave, mustNotHave) {
  const missing = mustHave.filter((s) => !out.includes(s));
  const present = (mustNotHave || []).filter((s) => out.includes(s));
  const ok = missing.length === 0 && present.length === 0;
  checks.push({ name, ok, missing, present, out });
  console.log((ok ? 'PASS ' : 'FAIL ') + name);
  if (!ok) {
    if (missing.length) console.log('  missing: ' + JSON.stringify(missing));
    if (present.length) console.log('  must-not-have present: ' + JSON.stringify(present));
    console.log('  output was:\n' + out.replace(/^/gm, '  | '));
  }
}

(async function main() {
  const rows = fixtureRows();
  const raw = rawOf(rows);
  const goodAnchor = {
    rows: 3,
    merkle_root: refRootHex(raw.slice(0, 3)),
    confirmed_block: 970001,
  };

  // S1 — happy path: anchored prefix matches the published root.
  expect('S1 happy path', await runBrowserPath({ rows, raw, latest: goodAnchor }), [
    'links OK   · 5 entries',
    'root       · RFC-6962 SHA-256 over all 5 lines: ' + refRootHex(raw),
    'anchor OK  · rows 1..3 recompute exactly to the published anchor root (manifest: Bitcoin block 970001)',
    '2 newer entries are link-checked only',
    'chain OK   · links consistent · anchored prefix matches the published root',
  ]);

  // S2 — truncation: the anchor covers more rows than the page loaded.
  // Round-3 fix: must say MISMATCH/truncated, never "unavailable"/"skipped".
  expect('S2 truncated chain', await runBrowserPath({
    rows, raw, latest: { ...goodAnchor, rows: 8 },
  }), [
    'ANCHOR MISMATCH: the published anchor covers 8 rows but this page loaded only 5',
    'truncated relative to what was anchored',
  ], ['unavailable', 'skipped']);

  // S3 — tamper inside the anchored prefix: bytes change, root does not match.
  const tamperedRows = fixtureRows();
  tamperedRows[1].subject = 'TAMPERED decision 2';
  const tamperedRaw = rawOf(tamperedRows);
  expect('S3 tampered prefix', await runBrowserPath({
    rows: tamperedRows, raw: tamperedRaw, latest: goodAnchor,
  }), [
    'ANCHOR MISMATCH: rows 1..3 recompute to',
    'but the published anchor root is ' + goodAnchor.merkle_root,
  ], ['anchor OK']);

  // S4 — malformed anchor: negative rows must be rejected, not coerced.
  expect('S4 malformed anchor rows:-1', await runBrowserPath({
    rows, raw, latest: { ...goodAnchor, rows: -1 },
  }), [
    'no usable anchors/latest.json — cryptographic comparison skipped',
  ], ['anchor OK', 'ANCHOR MISMATCH']);

  // S5 — fetch failure: honest skip, no crash.
  expect('S5 fetch failure', await runBrowserPath({
    rows, raw, latest: goodAnchor, fetchFails: true,
  }), [
    'no usable anchors/latest.json — cryptographic comparison skipped',
  ], ['anchor OK', 'ANCHOR MISMATCH']);

  // S7 — redacted row INSIDE the anchored prefix (the 0418738 contract): row 2
  // is rewritten post-anchor and carries leaf_sha256 = its pre-redaction leaf
  // hash. The anchored root is the PRE-redaction one; a verifier honouring
  // leaf_sha256 recomputes it from the served bytes. The live chain carries 25
  // such rows from line 106 — inside rows 1..1505 of the confirmed anchor.
  const redactedRows = fixtureRows();
  const originalLeaf = refLeafOf(JSON.stringify(redactedRows[1]));
  redactedRows[1] = {
    sha: redactedRows[1].sha,
    subject: '[redacted]',
    ts: redactedRows[1].ts,
    prev_sha: redactedRows[1].prev_sha,
    leaf_sha256: originalLeaf.toString('hex'),
  };
  const redactedRaw = rawOf(redactedRows);
  const preRedactionRoot = refRootHex(rawOf(fixtureRows()).slice(0, 3));
  expect('S7 redacted row in anchored prefix', await runBrowserPath({
    rows: redactedRows, raw: redactedRaw,
    latest: { rows: 3, merkle_root: preRedactionRoot, confirmed_block: 970001 },
  }), [
    'anchor OK  · rows 1..3 recompute exactly to the published anchor root (manifest: Bitcoin block 970001)',
  ], ['ANCHOR MISMATCH']);

  // S6 — broken link: prev_sha of entry 4 does not match entry 3.
  const brokenRows = fixtureRows();
  brokenRows[3].prev_sha = 'f'.repeat(40);
  expect('S6 broken link', await runBrowserPath({
    rows: brokenRows, raw: rawOf(brokenRows), latest: goodAnchor,
  }), [
    'chain BROKEN at entry 4 (prev_sha does not match the prior entry)',
  ], ['links OK', 'anchor OK']);

  const failed = checks.filter((c) => !c.ok);
  console.log(failed.length
    ? 'browser-path: ' + failed.length + ' of ' + checks.length + ' scenarios FAILED'
    : 'browser-path: all ' + checks.length + ' scenarios pass');
  process.exit(failed.length ? 1 : 0);
})().catch((e) => {
  console.error('browser-path FAIL: ' + (e && e.stack ? e.stack : e));
  process.exit(1);
});
