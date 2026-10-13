from __future__ import annotations
import hashlib

def idempotency_key(advisory_id: str, package: str, repository: str) -> str:
    parts = (advisory_id.strip().lower(), package.strip().lower(), repository.strip().lower())
    if any(not part for part in parts):
        raise ValueError("advisory, package and repository are required")
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()
