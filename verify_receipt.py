#!/usr/bin/env python3
import argparse, json, hashlib, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def canonical_bytes(obj) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def verify_ed25519(pubkey_hex: str, msg: bytes, sig_hex: str) -> bool:
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
    try:
        pk.verify(bytes.fromhex(sig_hex), msg)
        return True
    except InvalidSignature:
        return False


def verify_receipt(receipt: dict) -> dict:
    # 1) signature verification for receipt signed_block
    signed_block = receipt.get("signed_block")
    signature = receipt.get("signature")
    pubkey = receipt.get("public_key") or receipt.get("publicKey")
    if not signed_block or not signature or not pubkey:
        return {"ok": False, "error": "missing signed_block/signature/public_key"}

    signed_bytes = canonical_bytes(signed_block)
    sig_ok = verify_ed25519(pubkey, signed_bytes, signature)

    # 2) public_hash recompute (hash of canonical signed_block)
    computed_hash = hashlib.sha256(signed_bytes).hexdigest()
    claimed_hash = receipt.get("public_hash") or receipt.get("publicHash")
    hash_ok = (claimed_hash == computed_hash)

    # base verifier output (only checks actually performed)
    out = {
        "ok": bool(sig_ok and hash_ok),
        "signature_ok": sig_ok,
        "public_hash_ok": hash_ok,
        "claimed_public_hash": claimed_hash,
        "computed_public_hash": computed_hash,
        "canonical_signed_block_sha256": computed_hash,
    }

    # 3) optional: verify bundle double-signing if present
    if receipt.get("bundle_signature") and receipt.get("bundle_signed_block"):
        bundle_sig_ok = None
        bundle_hash_ok = None
        computed_bundle_hash = None
        claimed_bundle_hash = receipt.get("bundle_hash")

        try:
            payload = receipt.get("payload")
            if payload is not None:
                computed_bundle_hash = hashlib.sha256(
                    canonical_bytes(payload)
                ).hexdigest()
                if claimed_bundle_hash:
                    bundle_hash_ok = (claimed_bundle_hash == computed_bundle_hash)

            blk = receipt.get("bundle_signed_block")
            bundle_sig_ok = verify_ed25519(
                pubkey,
                canonical_bytes(blk),
                receipt["bundle_signature"],
            )
        except Exception:
            bundle_sig_ok = False

        out.update({
            "bundle_signature_ok": bundle_sig_ok,
            "bundle_hash_ok": bundle_hash_ok,
            "claimed_bundle_hash": claimed_bundle_hash,
            "computed_bundle_hash": computed_bundle_hash,
        })

    return out


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
