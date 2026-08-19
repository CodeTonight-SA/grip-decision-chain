#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 CodeTonight SA
//
// verify-anchors.js — node-free verification of the decision chain AND its
// Bitcoin anchors. "Node-free" means no Bitcoin node and no network at all:
// every check below is pure arithmetic over files you already downloaded.
//
// It verifies:
//   1. the chain links (prev_sha of each entry equals the previous sha),
//   2. every anchor manifest's RFC-6962 Merkle root recomputes exactly from
//      the first K raw lines of idr-public.jsonl,
//   3. every manifest and OTS proof file exists (check the Bitcoin
//      attestation itself with the reference client: ots info PROOF).
//
// Usage:
//   curl -sO https://codetonight-sa.github.io/grip-decision-chain/idr-public.jsonl
//   curl -sO https://codetonight-sa.github.io/grip-decision-chain/verify-anchors.js
//   mkdir -p anchors && curl -sO --output-dir anchors https://codetonight-sa.github.io/grip-decision-chain/anchors/state.json
//   node verify-anchors.js idr-public.jsonl anchors
//
//   # -> chain OK · anchors OK       (exit 0)
//   # -> chain BROKEN / anchor FAIL  (exit 1)
'use strict';

async function main() {
  // Dual-mode loader: works as CommonJS AND as an ES module, so a stray
  // package.json with "type": "module" in the working directory can never
  // silently neuter the verifier.
  let fs, path, crypto;
  if (typeof require === 'function') {
    fs = require('fs'); path = require('path'); crypto = require('crypto');
  } else {
    fs = await import('node:fs');
    path = await import('node:path');
    crypto = await import('node:crypto');
  }

  function leafHash(buf) {
    return crypto.createHash('sha256')
      .update(Buffer.concat([Buffer.from([0x00]), buf])).digest();
  }
  function nodeHash(left, right) {
    return crypto.createHash('sha256')
      .update(Buffer.concat([Buffer.from([0x01]), left, right])).digest();
  }
  // RFC 6962 Merkle Tree Hash — same construction scripts/anchor.py uses.
  function mth(leaves) {
    const n = leaves.length;
    if (n === 0) return crypto.createHash('sha256').digest();
    if (n === 1) return leafHash(leaves[0]);
    let k = 1;
    while (k < n) k <<= 1;
    k >>= 1;
    return nodeHash(mth(leaves.slice(0, k)), mth(leaves.slice(k)));
  }
  function merkleRootHex(lines) {
    return mth(lines.map((l) => Buffer.from(l, 'utf8'))).toString('hex');
  }
  function rootShort(root) {
    return root.slice(0, 12) + '…' + root.slice(-8);
  }

  const chainPath = process.argv[2] || 'idr-public.jsonl';
  const anchorsDir = process.argv[3] || 'anchors';
  const statePath = path.join(anchorsDir, 'state.json');

  let text, lines;
  try {
    text = fs.readFileSync(chainPath, 'utf8');
  } catch (e) {
    console.error('FAIL: cannot read ' + chainPath + ' — ' + e.message);
    process.exit(1);
  }
  lines = text.split('\n').filter((l) => l.length > 0);
  if (!lines.length) {
    console.error('FAIL: chain is empty');
    process.exit(1);
  }

  // 1 — chain linkage.
  let prev = null;
  let rows;
  try {
    rows = lines.map((l) => JSON.parse(l));
  } catch (e) {
    console.error('FAIL: idr-public.jsonl is not parseable — ' + e.message);
    process.exit(1);
  }
  for (let i = 0; i < rows.length; i++) {
    if ((rows[i].prev_sha ?? null) !== prev) {
      console.error('chain BROKEN at entry ' + (i + 1) + ': prev_sha '
        + JSON.stringify(rows[i].prev_sha) + ' != ' + JSON.stringify(prev));
      process.exit(1);
    }
    prev = rows[i].sha;
  }
  console.log('chain OK · ' + rows.length + ' entries · every prev-hash links');

  // 2 — anchor manifests recompute from the public lines alone.
  let state;
  try {
    state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  } catch (e) {
    console.error('FAIL: cannot read ' + statePath + ' — ' + e.message);
    process.exit(1);
  }
  const anchors = (state && Array.isArray(state.anchors)) ? state.anchors : [];
  if (!anchors.length) {
    console.error('FAIL: no anchors recorded in ' + statePath);
    process.exit(1);
  }
  let bad = 0;
  for (const anchor of anchors) {
    const k = anchor.rows;
    const declared = anchor.merkle_root;
    const recomputed = merkleRootHex(lines.slice(0, k));
    if (declared !== recomputed) {
      bad++;
      console.error('anchor FAIL rows=1..' + k + ': manifest declares root '
        + declared + ' but the first ' + k + ' public lines recompute to '
        + recomputed);
      continue;
    }
    const manifestPath = path.join(anchorsDir, path.basename(anchor.manifest || ''));
    const proofPath = path.join(anchorsDir, path.basename(anchor.proof || ''));
    const manifestOk = fs.existsSync(manifestPath);
    const proofOk = fs.existsSync(proofPath);
    if (!manifestOk || !proofOk) {
      bad++;
      console.error('anchor FAIL rows=1..' + k + ': missing file(s) — '
        + (manifestOk ? '' : 'manifest ') + (proofOk ? '' : 'proof'));
      continue;
    }
    let manifest;
    try {
      manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    } catch (e) {
      bad++;
      console.error('anchor FAIL rows=1..' + k + ': manifest unreadable');
      continue;
    }
    if (manifest.canonical_merkle_root_rfc6962 !== declared) {
      bad++;
      console.error('anchor FAIL rows=1..' + k + ': manifest root field '
        + manifest.canonical_merkle_root_rfc6962 + ' != state root ' + declared);
      continue;
    }
    const suffix = anchor.status === 'confirmed'
      ? ' · Bitcoin-confirmed in block ' + anchor.confirmed_block
        + ' (' + anchor.block_time_utc + ')'
      : ' · stamped ' + anchor.stamped_utc + ' — awaiting Bitcoin attestation';
    console.log('anchor OK  rows=1..' + String(k).padEnd(6)
      + rootShort(declared) + suffix);
  }
  if (bad) {
    console.error('anchors BROKEN · ' + bad + ' failing anchor(s)');
    process.exit(1);
  }
  console.log('anchors OK · ' + anchors.length + ' anchor(s) · every root '
    + 'recomputes from the public chain · check each Bitcoin attestation '
    + 'node-free with: ots info PROOF');
}

main().catch((e) => {
  console.error('verify-anchors FAIL: ' + (e && e.message ? e.message : e));
  process.exit(1);
});
