from __future__ import annotations
from typing import Any
from sentinel.models import Finding, Tier

def autonomy_tier(finding: Finding, policy: dict[str, Any]) -> Tier:
    """Evaluate ordered policy rules; no model-generated tier is accepted."""
    for rule in policy["autonomy"]["rules"]:
        when = rule["when"]
        if "change_type" in when and finding.change_type == when["change_type"]:
            return Tier(rule["tier"])
        patterns = when.get("paths_match", [])
        if any(_path_matches(path, pattern) for path in finding.paths for pattern in patterns):
            return Tier(rule["tier"])
    return Tier.LOW if finding.change_type in {"patch", "minor", "patch_or_minor"} else Tier.HIGH

def _path_matches(path: str, pattern: str) -> bool:
    if pattern.endswith("**"):
        return path.startswith(pattern[:-2])
    return path == pattern
