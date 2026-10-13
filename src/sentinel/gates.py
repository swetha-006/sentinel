from __future__ import annotations
import hashlib
import json
from pathlib import PurePosixPath
from typing import Any, Iterable
from sentinel.models import Decision, DecisionKind

def _decision(kind: DecisionKind, reason: str, inputs: Any) -> Decision:
    encoded = json.dumps(inputs, sort_keys=True, separators=(",", ":"), default=str).encode()
    return Decision(decision=kind, reason_code=reason, inputs_hash=hashlib.sha256(encoded).hexdigest())

def change_gate(paths: Iterable[str], existing_test_changes: bool, open_mrs: int, kill_switch: bool, policy: dict[str, Any]) -> Decision:
    changed = tuple(sorted(set(paths)))
    guard = policy["guardrails"]
    if kill_switch:
        return _decision(DecisionKind.DENY, "KILL_SWITCH_ACTIVE", {"paths": changed})
    if len(changed) > guard["max_files_changed"]:
        return _decision(DecisionKind.DENY, "FILE_LIMIT_EXCEEDED", {"paths": changed, "limit": guard["max_files_changed"]})
    forbidden = guard["forbidden_paths"]
    if any(_matches(path, pattern) for path in changed for pattern in forbidden):
        return _decision(DecisionKind.DENY, "FORBIDDEN_PATH", {"paths": changed, "forbidden": forbidden})
    if existing_test_changes and not guard["allow_existing_test_changes"]:
        return _decision(DecisionKind.DENY, "EXISTING_TEST_MODIFIED", {"paths": changed})
    if open_mrs >= guard["max_open_sentinel_mrs"]:
        return _decision(DecisionKind.NEEDS_HUMAN, "OPEN_MR_CAP_REACHED", {"open_mrs": open_mrs, "limit": guard["max_open_sentinel_mrs"]})
    return _decision(DecisionKind.ALLOW, "CHANGE_WITHIN_POLICY", {"paths": changed, "open_mrs": open_mrs})

def proof_gate(before_failed: bool | None, after_passed: bool | None, existing_tests_passed: bool | None) -> Decision:
    inputs = {"before_failed": before_failed, "after_passed": after_passed, "existing_tests_passed": existing_tests_passed}
    if None in inputs.values():
        return _decision(DecisionKind.DENY, "PROOF_INPUT_MISSING", inputs)
    if before_failed is not True:
        return _decision(DecisionKind.DENY, "PROOF_NOT_REPRODUCED", inputs)
    if after_passed is not True or existing_tests_passed is not True:
        return _decision(DecisionKind.DENY, "PROOF_OR_REGRESSION_FAILED", inputs)
    return _decision(DecisionKind.ALLOW, "PROOF_RED_THEN_GREEN", inputs)

def scan_gate(scans: Iterable[dict[str, str]]) -> Decision:
    values = tuple(scans)
    if not values or any(not s.get("scanner") or not s.get("status") or not s.get("report_digest") for s in values):
        return _decision(DecisionKind.DENY, "SCAN_EVIDENCE_MISSING", values)
    bad = [s for s in values if s["status"].lower() not in {"clean", "passed", "no_new_findings"}]
    return _decision(DecisionKind.DENY, "SCAN_NOT_CLEAN", values) if bad else _decision(DecisionKind.ALLOW, "SCANS_ACCEPTED", values)

def _matches(path: str, pattern: str) -> bool:
    p = PurePosixPath(path)
    if pattern.endswith("/**"):
        return path.startswith(pattern[:-3] + "/") or path == pattern[:-3]
    return p.match(pattern)
