from __future__ import annotations
import json
from pathlib import Path
from typing import Any
import yaml
from jsonschema import Draft202012Validator

class PolicyError(ValueError):
    pass

def load_policy(policy_path: Path, schema_path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        errors = sorted(Draft202012Validator(schema).iter_errors(raw), key=lambda e: list(map(str, e.path)))
        if errors:
            raise PolicyError("invalid policy: " + "; ".join(e.message for e in errors))
        if not isinstance(raw, dict):
            raise PolicyError("policy root must be an object")
        return raw
    except (OSError, yaml.YAMLError, json.JSONDecodeError) as exc:
        raise PolicyError(f"policy load failed: {exc}") from exc
