import json
from pathlib import Path
from sentinel.models import Decision, DecisionKind, ProofReceipt, Tier
from sentinel.proof import sign_payload, verify_signature
from sentinel.receipt import write_receipt

def test_signature_round_trip() -> None:
    payload = {"decision":"allow", "proof":{"before_failed":True,"after_passed":True}}
    signature = sign_payload(payload, b"test-key-which-is-long-enough-for-security")
    assert verify_signature(payload, signature, b"test-key-which-is-long-enough-for-security")
    assert not verify_signature(payload, signature, b"wrong-key-which-is-long-enough-for-security")

def test_receipt_outputs_three_formats(tmp_path: Path) -> None:
    decision = Decision(decision=DecisionKind.ALLOW, reason_code="TEST", inputs_hash="abc")
    r = ProofReceipt(correlation_id="corr", idempotency_key="key", finding={"id":"CVE-X"}, autonomy_tier=Tier.LOW, proof={"before_failed":True,"after_passed":True,"existing_tests_passed":True}, scans=(), approvals=(), canary={"observed_minutes":10,"error_rate":0.0,"p95_latency_regression":0.0,"promote":False}, decision=decision, signed_off_by="test", signature="sig")
    write_receipt(r, tmp_path)
    assert set(p.name for p in tmp_path.iterdir()) == {"receipt.json","receipt.md","receipt.html"}
    assert json.loads((tmp_path / "receipt.json").read_text())["decision"]["reason_code"] == "TEST"
    assert "Sentinel Proof Receipt" in (tmp_path / "receipt.html").read_text()
