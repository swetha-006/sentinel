from sentinel.gates import change_gate, proof_gate, scan_gate
from sentinel.models import DecisionKind

def test_change_gate_allows_safe_change(policy: dict[str, object]) -> None:
    assert change_gate(["src/lib.py"], False, 0, False, policy).decision == DecisionKind.ALLOW

def test_kill_switch_denies(policy: dict[str, object]) -> None:
    assert change_gate(["src/lib.py"], False, 0, True, policy).reason_code == "KILL_SWITCH_ACTIVE"

def test_existing_test_modification_denied(policy: dict[str, object]) -> None:
    assert change_gate(["tests/test_x.py"], True, 0, False, policy).reason_code == "EXISTING_TEST_MODIFIED"

def test_open_mr_cap_needs_human(policy: dict[str, object]) -> None:
    assert change_gate([], False, 3, False, policy).decision == DecisionKind.NEEDS_HUMAN

def test_proof_requires_red_then_green() -> None:
    assert proof_gate(True, True, True).decision == DecisionKind.ALLOW
    assert proof_gate(False, True, True).decision == DecisionKind.DENY
    assert proof_gate(True, None, True).reason_code == "PROOF_INPUT_MISSING"

def test_scan_gate_missing_and_dirty() -> None:
    assert scan_gate([]).decision == DecisionKind.DENY
    assert scan_gate([{"scanner":"SAST","status":"failed","report_digest":"abc"}]).decision == DecisionKind.DENY
    assert scan_gate([{"scanner":"SAST","status":"clean","report_digest":"abc"}]).decision == DecisionKind.ALLOW
