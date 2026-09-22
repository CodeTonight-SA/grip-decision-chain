// GRIP decision-chain verifier — zero dependencies, no network.
//
//   Node:    node verify.js [idr-public.jsonl] [anchorsDir]
//   Browser: paste this whole file into the console on the decision-chain page;
//            it re-checks the chain the page already loaded.
//
// What it checks, in order:
//   1. LINKS  — the first row's prev_sha is null and every later row's prev_sha
//               equals the prior row's sha (mirrors lib/idr_public_emitter
//               .verify_chain). This is internal consistency of the supplied
//               prev-hash references ONLY — not proof of historical order,
//               completeness, or append-only history, and not cryptography.
//               Those properties come from the anchor comparison below.
//   2. ROOT   — recomputes the RFC-6962 Merkle root (SHA-256) over the raw
//               chain lines. Real cryptography, from the public bytes alone.
//   3. ANCHOR — if the published anchors are available (anchors/latest.json or
//               anchors/state.json beside the chain), recomputes the root over
//               the anchored prefix and compares it to the PUBLISHED anchor
//               root. A match means the first K entries are byte-for-byte the
//               data that manifest anchors. Whether that root truly sits in
//               Bitcoin is the OTS proof's claim — this file does not check it;
//               verify the attestation itself with: ots verify <manifest>.json.ots
//
// verify-anchors.js remains the full audit (every batch, every manifest);
// this file is the quick check, and it never claims more than it ran.
(function () {
  'use strict';

  var IS_NODE = typeof process !== 'undefined' && process.versions && process.versions.node;

  function walkLinks(rows) {
    var prev = null;
    for (var i = 0; i < rows.length; i++) {
      var ps = rows[i].prev_sha == null ? null : rows[i].prev_sha;
      if (ps !== prev) return { valid: false, brokeAt: i };
      prev = rows[i].sha;
    }
    return { valid: true, brokeAt: -1 };
  }

  function reportLinks(rows, log, err) {
    var link = walkLinks(rows);
    if (!link.valid) {
      err('chain BROKEN at entry ' + (link.brokeAt + 1) +
        ' (prev_sha does not match the prior entry)');
      return false;
    }
    log('links OK   · ' + rows.length +
      ' entries · every prev-hash links (internal consistency)');
    return true;
  }

  // --- Node path -------------------------------------------------------------

  // Dual-mode loader (same trick as verify-anchors.js): works as CommonJS AND
  // as an ES module, so a stray package.json with "type": "module" in the
  // working directory can never silently neuter the verifier.
  async function loadNodeModules() {
    if (typeof require === 'function') {
      return { fs: require('fs'), path: require('path'), crypto: require('crypto') };
    }
    return {
      fs: await import('node:fs'),
      path: await import('node:path'),
      crypto: await import('node:crypto'),
    };
  }

  // RFC 6962 Merkle Tree Hash — same construction as scripts/anchor.py and
  // verify-anchors.js. Returns a hex-root function over raw utf-8 lines.
  function makeRootHex(crypto) {
    function leafHash(buf) {
      return crypto.createHash('sha256')
        .update(Buffer.concat([Buffer.from([0x00]), buf])).digest();
    }
    function nodeHash(l, r) {
      return crypto.createHash('sha256')
        .update(Buffer.concat([Buffer.from([0x01]), l, r])).digest();
    }
    // Leaf hash of one published line. A row the redaction shield rewrote
    // AFTER it was anchored carries leaf_sha256 = SHA-256(0x00 || the exact
    // pre-redaction line); that value stands in for the leaf so the anchored
    // root still recomputes without the redacted text. Untouched rows have no
    // such field and hash from their served bytes exactly as before.
    function leafOf(line) {
      try {
        var row = JSON.parse(line);
        if (row && typeof row.leaf_sha256 === 'string' && /^[0-9a-f]{64}$/.test(row.leaf_sha256)) {
          return Buffer.from(row.leaf_sha256, 'hex');
        }
      } catch (e) { /* torn line: hash the bytes as served */ }
      return leafHash(Buffer.from(line, 'utf8'));
    }
    function mth(leafHashes) {
      var n = leafHashes.length;
      if (n === 0) return crypto.createHash('sha256').digest();
      if (n === 1) return leafHashes[0];
      var k = 1;
      while (k < n) k <<= 1;
      k >>= 1;
      return nodeHash(mth(leafHashes.slice(0, k)), mth(leafHashes.slice(k)));
    }
    return function rootHex(lines) {
      return mth(lines.map(leafOf)).toString('hex');
    };
  }

  function readChain(fs, file) {
    var text;
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch (e) {
      console.error('FAIL: cannot read ' + file + ' — ' + e.message);
      process.exit(1);
    }
    var lines = text.split('\n').filter(function (l) { return l.length > 0; });
    if (!lines.length) { console.error('FAIL: chain is empty'); process.exit(1); }
    try {
      return { lines: lines, rows: lines.map(function (l) { return JSON.parse(l); }) };
    } catch (e) {
      console.error('FAIL: ' + file + ' is not parseable — ' + e.message);
      process.exit(1);
    }
  }

  function readJsonQuiet(fs, p) {
    try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { return null; }
  }

  // Truthiness is not validation: rows must be a positive safe integer (slice
  // silently coerces -1 or 1.5 into a different prefix) and the root must be a
  // well-formed SHA-256 hex digest before any coverage claim is built on them.
  function isValidAnchor(a) {
    return !!a && Number.isSafeInteger(a.rows) && a.rows > 0 &&
      typeof a.merkle_root === 'string' && /^[0-9a-f]{64}$/.test(a.merkle_root);
  }

  // The newest CONFIRMED anchor: latest.json's tip, else the highest-rows
  // confirmed entry in state.json. Null when no VALID anchor is readable.
  function findLatestAnchor(fs, path, anchorsDir) {
    var lj = readJsonQuiet(fs, path.join(anchorsDir, 'latest.json'));
    if (lj && isValidAnchor(lj.latest_confirmed)) return lj.latest_confirmed;
    var st = readJsonQuiet(fs, path.join(anchorsDir, 'state.json'));
    if (!st || !Array.isArray(st.anchors)) return null;
    var conf = st.anchors.filter(function (a) {
      return isValidAnchor(a) && a.status === 'confirmed';
    });
    if (!conf.length) return null;
    return conf.reduce(function (a, b) { return a.rows > b.rows ? a : b; });
  }

  function reportNoAnchors(anchorsDir) {
    console.log('anchors    · no usable anchor in "' + anchorsDir +
      '" (missing or malformed) — cryptographic comparison skipped.');
    console.log('             fetch anchors/latest.json beside the chain and re-run,');
    console.log('             or run verify-anchors.js for the full anchor audit.');
    console.log('chain OK   · links internally consistent · root computed · anchor comparison NOT run');
  }

  function compareAnchor(rootHex, lines, latest) {
    if (latest.rows > lines.length) {
      console.error('ANCHOR MISMATCH: the attested anchor covers ' + latest.rows +
        ' rows but the chain has only ' + lines.length +
        ' — this chain is truncated relative to what was anchored');
      return false;
    }
    var prefixRoot = rootHex(lines.slice(0, latest.rows));
    if (prefixRoot !== latest.merkle_root) {
      console.error('ANCHOR MISMATCH: rows 1..' + latest.rows + ' recompute to');
      console.error('  ' + prefixRoot);
      console.error('  but the published anchor root is');
      console.error('  ' + latest.merkle_root);
      return false;
    }
    console.log('anchor OK  · rows 1..' + latest.rows +
      ' recompute exactly to the published anchor root' +
      (latest.confirmed_block ? ' (manifest: Bitcoin block ' + latest.confirmed_block + ')' : ''));
    var beyond = lines.length - latest.rows;
    if (beyond > 0) {
      console.log('             ' + beyond +
        ' newer entries are link-checked only until the next anchor batch.');
    }
    return true;
  }

  async function nodeMain() {
    var mods = await loadNodeModules();
    var rootHex = makeRootHex(mods.crypto);
    var file = process.argv[2] || 'idr-public.jsonl';
    // Default anchors live BESIDE the chain file, not under the caller's cwd.
    var anchorsDir = process.argv[3] ||
      mods.path.join(mods.path.dirname(mods.path.resolve(file)), 'anchors');
    var chain = readChain(mods.fs, file);
    if (!reportLinks(chain.rows, console.log, console.error)) process.exit(1);
    console.log('root       · RFC-6962 SHA-256 over all ' + chain.lines.length +
      ' lines: ' + rootHex(chain.lines));
    var latest = findLatestAnchor(mods.fs, mods.path, anchorsDir);
    if (!latest) { reportNoAnchors(anchorsDir); process.exit(0); }
    if (!compareAnchor(rootHex, chain.lines, latest)) process.exit(1);
    console.log('chain OK   · ' + chain.rows.length +
      ' entries · links consistent · anchored prefix matches the published root');
    console.log('             this file does NOT check the Bitcoin attestation — do that with:');
    console.log('             ots verify ' + (latest.proof || anchorsDir + '/<manifest>.json.ots'));
    process.exit(0);
  }

  // --- Browser console path --------------------------------------------------

  // Async RFC-6962 root over TextEncoder leaves, via WebCrypto (SubtleCrypto).
  function makeSubtleRoot() {
    var enc = new TextEncoder();
    function sha(b) { return window.crypto.subtle.digest('SHA-256', b); }
    function cat() {
      var bs = Array.prototype.slice.call(arguments);
      var out = new Uint8Array(bs.reduce(function (s, b) { return s + b.length; }, 0));
      var o = 0;
      bs.forEach(function (b) { out.set(b, o); o += b.length; });
      return out;
    }
    async function mth(ls) {
      var n = ls.length;
      if (n === 0) return new Uint8Array(await sha(new Uint8Array(0)));
      if (n === 1) return new Uint8Array(await sha(cat(new Uint8Array([0]), ls[0])));
      var k = 1;
      while (k < n) k <<= 1;
      k >>= 1;
      return new Uint8Array(await sha(cat(new Uint8Array([1]),
        await mth(ls.slice(0, k)), await mth(ls.slice(k)))));
    }
    function hex(u8) { return Array.from(u8).map(function (b) { return b.toString(16).padStart(2, '0'); }).join(''); }
    return {
      leavesOf: function (raw) { return raw.map(function (l) { return enc.encode(l); }); },
      rootHex: async function (leaves) { return hex(await mth(leaves)); },
    };
  }

  async function fetchLatestAnchor() {
    try {
      var r = await fetch('anchors/latest.json', { cache: 'no-store' });
      if (!r.ok) return null;
      var j = await r.json();
      return (j && isValidAnchor(j.latest_confirmed)) ? j.latest_confirmed : null;
    } catch (e) { return null; }
  }

  async function browserCompare(subtle, leaves, total, latest) {
    var prefix = await subtle.rootHex(leaves.slice(0, latest.rows));
    if (prefix !== latest.merkle_root) {
      console.log('ANCHOR MISMATCH: rows 1..' + latest.rows + ' recompute to ' +
        prefix + ' but the published anchor root is ' + latest.merkle_root);
      return;
    }
    console.log('anchor OK  · rows 1..' + latest.rows +
      ' recompute exactly to the published anchor root (manifest: Bitcoin block ' +
      latest.confirmed_block + ')');
    if (total > latest.rows) {
      console.log('             ' + (total - latest.rows) +
        ' newer entries are link-checked only until the next anchor batch.');
    }
    console.log('chain OK   · links consistent · anchored prefix matches the published root');
    console.log('             the Bitcoin attestation itself is not checked here — ots verify <manifest>.json.ots');
  }

  async function browserMain() {
    var rows = window.GRIP_CHAIN;
    if (!rows) {
      console.warn('Open this on the GRIP decision-chain page first — the chain loads there.');
      return;
    }
    if (!reportLinks(rows, console.log, console.log)) return;
    var raw = window.GRIP_CHAIN_RAW;
    if (!raw || !raw.length || !(window.crypto && window.crypto.subtle)) {
      console.log('root       · raw chain lines unavailable in this page build — ' +
        'reload the page, or run the Node path for the cryptographic check');
      return;
    }
    var subtle = makeSubtleRoot();
    var leaves = subtle.leavesOf(raw);
    subtle.rootHex(leaves).then(function (full) {
      console.log('root       · RFC-6962 SHA-256 over all ' + raw.length + ' lines: ' + full);
    });
    var latest = await fetchLatestAnchor();
    if (!latest) {
      console.log('anchors    · no usable anchors/latest.json — cryptographic comparison ' +
        'skipped; run verify-anchors.js for the full audit');
      return;
    }
    if (latest.rows > raw.length) {
      console.log('ANCHOR MISMATCH: the published anchor covers ' + latest.rows +
        ' rows but this page loaded only ' + raw.length +
        ' — the chain is truncated relative to what was anchored');
      return;
    }
    await browserCompare(subtle, leaves, raw.length, latest);
  }

  if (IS_NODE) {
    nodeMain().catch(function (e) {
      console.error('verify FAIL: ' + (e && e.message ? e.message : e));
      process.exit(1);
    });
  } else if (typeof window !== 'undefined') {
    browserMain();
  }
})();
