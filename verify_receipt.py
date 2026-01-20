#!/usr/bin/env python3
import argparse
import json
import hashlib
import sys
import unicodedata
from decimal import Decimal
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


# -------------------------
# RFC 8785 (JCS) CANONICALIZATION
# -------------------------

def _normalize(obj):
    """
    Apply RFC 8785 normalization rules:
    - Unicode NFC normalization for strings
    - Reject non-canonical numbers (floats, NaN, Infinity)
    - Deterministic traversal
    """
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)

    if isinstance(obj, bool) or obj is None:
        return obj

    if isinstance(obj, int):
        return obj

    if isinstance(obj, float):
        raise ValueError("RFC 8785 forbids floating-point numbers")

    if isinstance(obj, Decimal):
        if not obj.is_finite():
            raise ValueError("RFC 8785 forbids NaN or Infinity")
        # Normalize Decimal to canonical string form
        return obj.normalize()

    if isinstance(obj, list):
        return [_normalize(x) for x in obj]

    if isinstance(obj, dict):
        return {str(k): _normalize(v) for k, v in obj.items()}

    raise TypeError(f"Unsupported type for canonicalization: {type(obj)}")


def canonical_bytes(obj) -> bytes:
    """
    RFC 8785 canonical JSON serialization:
    - UTF-8
    - Sorted keys
    - No insignificant whitespace
    - NFC-normalized strings
    - Canonical numbers only
    """
    normalized = _normalize(obj)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


# -------------------------
# CRYPTO PRIMITIVES
# -------------------------

def verify_ed25519(pubkey_hex: str, msg: bytes, sig_hex: str) -> bool:
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
    try:
        pk.verify(bytes.fromhex(sig_hex), msg)
        return True
    except InvalidSignature:
        return False


# -------------------------
# RECEIPT VERIFICATION
# -------------------------

def verify_receipt(receipt: dict) -> dict:
    signed_block = receipt.get("signed_block")
    signature = receipt.get("signature")
    pubkey = receipt.get("public_key") or receipt.get("publicKey")

    if not signed_block or not signature or not pubkey:
        return {"ok": False, "error": "missing signed_block/signature/public_key"}

    try:
        signed_bytes = canonical_bytes(signed_block)
    except Exception as e:
        return {"ok": False, "error": f"canonicalization_error: {e}"}

    sig_ok = verify_ed25519(pubkey, signed_bytes, signature)

    computed_hash = hashlib.sha256(signed_bytes).hexdigest()
    claimed_hash = receipt.get("public_hash") or receipt.get("publicHash")
    hash_ok = (claimed_hash == computed_hash)

    out = {
        "ok": bool(sig_ok and hash_ok),
        "signature_ok": sig_ok,
        "public_hash_ok": hash_ok,
        "claimed_public_hash": claimed_hash,
        "computed_public_hash": computed_hash,
        "canonical_signed_block_sha256": computed_hash,
    }

    return out


# -------------------------
# CLI
# -------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("receipt_json", help="Path to receipt.json")
    args = ap.parse_args()

    with open(args.receipt_json, "r", encoding="utf-8") as f:
        receipt = json.load(f)

    out = verify_receipt(receipt)
    print(json.dumps(out, indent=2))
    sys.exit(0 if out.get("ok") else 1)


if __name__ == "__main__":
    main()
