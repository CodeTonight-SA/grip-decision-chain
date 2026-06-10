// GRIP decision-chain verifier — zero dependencies.
//
//   Node:    node verify.js idr-public.jsonl
//   Browser: paste this whole file into the console on the decision-chain page;
//            it reads the chain the page already loaded (window.GRIP_CHAIN).
//
// It mirrors lib/idr_public_emitter.verify_chain exactly: the first row's
// prev_sha must be null, and every later row's prev_sha must equal the prior
// row's sha. A removed or reordered entry breaks the chain at a reported index.
(function () {
  function verifyChain(rows) {
    var prev = null;
    for (var i = 0; i < rows.length; i++) {
      var ps = rows[i].prev_sha == null ? null : rows[i].prev_sha;
      if (ps !== prev) return { valid: false, brokeAt: i };
      prev = rows[i].sha;
    }
    return { valid: true, brokeAt: -1 };
  }

  function report(rows) {
    var r = verifyChain(rows);
    if (r.valid) {
      console.log('chain OK · ' + rows.length + ' entries');
      return 0;
    }
    console.log('chain BROKEN at entry ' + (r.brokeAt + 1) +
      ' (prev_sha does not match the prior commit)');
    return 1;
  }

  // --- Node CLI path ---
  if (typeof process !== 'undefined' && process.argv && typeof require === 'function') {
    var file = process.argv[2] || 'idr-public.jsonl';
    var text = require('fs').readFileSync(file, 'utf8');
    var rows = text.split('\n')
      .filter(function (l) { return l.trim(); })
      .map(function (l) { return JSON.parse(l); });
    process.exit(report(rows));
    return;
  }

  // --- Browser console path ---
  if (typeof window !== 'undefined') {
    if (!window.GRIP_CHAIN) {
      console.warn('Open this on the GRIP decision-chain page first — the chain loads there.');
    } else {
      report(window.GRIP_CHAIN);
    }
  }
})();
