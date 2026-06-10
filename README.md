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

Or open the [live view](https://codetonight-sa.github.io/grip-decision-chain/) — the same check
runs in your browser on load, and you can paste [`verify.js`](./verify.js) into the console to
re-run it against the loaded chain.

## How it stays current

Rows are appended by [`lib/idr_public_emitter.py`](https://github.com/CodeTonight-SA/GRIP) in the
GRIP repo (idempotent by sha — a commit is never recorded twice), then synced here. The chain
only ever grows; it is never rewritten.

---

*GRIP — General Reasoning & Intelligence Platform. This is GRIP dogfooding its own decision-record
mechanism on itself: why did the AI do this, visibly.*
