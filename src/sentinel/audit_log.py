from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERBS = {"prove", "fix", "attack", "ship", "receipt"}

def append_audit(path: Path, *, actor: str, action: str, verb: str, correlation_id: str, decision: str, details: dict[str, Any]) -> None:
    if verb not in VERBS:
        raise ValueError("verb must be one of prove/fix/attack/ship/receipt")
    record = {"who": actor, "what": action, "when": datetime.now(timezone.utc).isoformat(), "verb": verb, "correlation_id": correlation_id, "decision": decision, "details": details}
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
