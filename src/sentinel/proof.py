from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_payload(payload: dict[str, Any], key: bytes) -> str:
    if len(key) < 32:
        raise ValueError("receipt signing key must contain at least 32 bytes")
    return hmac.new(key, canonical_json(payload), hashlib.sha256).hexdigest()


def verify_signature(payload: dict[str, Any], signature: str, key: bytes) -> bool:
    if len(key) < 32 or not signature:
        return False
    return hmac.compare_digest(sign_payload(payload, key), signature)


def receipt_signing_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    """Return the exact receipt fields covered by the HMAC, excluding signature."""
    return {key: value for key, value in receipt.items() if key != "signature"}


def verify_receipt_signature(receipt: dict[str, Any], key: bytes) -> bool:
    signature = receipt.get("signature")
    return isinstance(signature, str) and verify_signature(receipt_signing_payload(receipt), signature, key)
