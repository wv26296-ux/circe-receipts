# CIRCE — Offline‑Verifiable Receipts for AI Agent Actions

This repo is a tiny **offline verification kit** for a simple primitive:

> Treat an agent run more like a **signed transaction** than a log stream.

A receipt is a **canonical JSON artifact** that records what an agent decided / did / produced, and can be validated **offline** without trusting logs, consoles, or the issuer’s infrastructure.

## Files

- `hn_receipt.json` — example signed receipt (should verify ✅)
- `hn_receipt_tampered.json` — same receipt with a mutation (should fail ❌)
- `verify_receipt.py` — standalone verifier (Ed25519 + SHA‑256)
- `requirements.txt` — Python dependency list
- `LICENSE` — MIT

---

## Quick start (60 seconds)

### 1) Install requirements

```bash
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
```

### 2) Verify the receipt (no network)

```bash
python verify_receipt.py hn_receipt.json
python verify_receipt.py hn_receipt_tampered.json
```

Expected:
- `hn_receipt.json` → `"ok": true`
- `hn_receipt_tampered.json` → `"ok": false`

---

## What is verified

The verifier checks two things:

1) **Ed25519 signature** over the canonicalized `signed_block`  
2) `public_hash` equals `SHA-256(canonical_bytes(signed_block))`

If `signed_block` is mutated, **both** the signature check and hash check fail.

### What is signed

Only `signed_block` is signed (after canonicalization). Everything else is treated as *metadata* and can be changed without affecting verification **unless** it changes the `signed_block`.

This keeps the trust boundary explicit and avoids “mystery fields” silently changing what’s being attested.

---

## Canonicalization (why signatures don’t randomly break)

Signing/verifying operates on a deterministic byte string:

- stable key ordering (`sort_keys=True`)
- no whitespace (`separators=(',', ':')`)
- UTF‑8 encoding

This is **JCS‑style / RFC 8785‑inspired canonicalization intent** so the same `signed_block` yields the same bytes across runtimes/languages.

> Note: the goal here is deterministic bytes. If you have strong opinions about strict RFC 8785 compliance or alternative canonicalization rules, please critique.

---

## Dependencies

- Python 3.9+ recommended
- `cryptography` (for Ed25519)

Everything else is Python standard library.

---

## Scope (what this repo is and isn’t)

This repo is intentionally focused on **receipt integrity + offline verification**, not:
- policy semantics / rule engines
- storage / ledgers / Merkle logs
- key management infrastructure

Those layers can sit *around* this primitive, but aren’t required to validate a receipt offline.

---

## Feedback wanted

I’d appreciate feedback on:
- threat‑model gaps / failure modes
- receipt schema design (what should/shouldn’t be signed)
- how this behaves in real agent pipelines (streaming, tool calls, partial failures, retries)
