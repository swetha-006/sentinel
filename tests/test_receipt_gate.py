from __future__ import annotations

from typing import Any

from sentinel.proof import sign_payload
from sentinel.receipt import authorize_receipt

POLICY: dict[str, Any] = {"slo": {"canary_minutes": 10, "error_rate_max": 0.01, "p95_latency_regression_max": 0.20}}


def valid_data() -> dict[str, Any]:
    data: dict[str, Any] = {
        "schema_version": 1,
        "correlation_id": "corr-123",
        "idempotency_key": "key-123",
        "finding": {"advisory_id": "CVE-TEST", "package": "demo"},
        "autonomy_tier": "low",
        "proof": {"before_failed": True, "after_passed": True, "existing_tests_passed": True, "test_name": "test_exploit"},
        "scans": [{"scanner": name, "status": "clean", "report_digest": "sha256:" + "a" * 64} for name in ["sast", "dependency", "secret", "container", "sbom"]],
        "approvals": [],
        "canary": {"observed_minutes": 10, "error_rate": 0.0, "p95_latency_regression": 0.0, "promote": True},
        "decision": {"decision": "allow", "reason_code": "ALL_GATES_PASSED", "inputs_hash": "sha256:def"},
        "signed_off_by": "policy",
    }
    data["signature"] = sign_payload(data, b"x" * 32)
    return data


def test_signed_complete_receipt_allows() -> None:
    data = valid_data()
    assert authorize_receipt(data, b"x" * 32, POLICY) == (True, "SIGNED_RECEIPT_ACCEPTED")


def test_tampered_receipt_denied() -> None:
    data = valid_data()
    data["canary"]["promote"] = False
    assert authorize_receipt(data, b"x" * 32, POLICY) == (False, "RECEIPT_SIGNATURE_INVALID")


def test_missing_scanner_denied_even_if_signed() -> None:
    data = valid_data()
    data["scans"] = data["scans"][:-1]
    unsigned = {k: v for k, v in data.items() if k != "signature"}
    data["signature"] = sign_payload(unsigned, b"x" * 32)
    assert authorize_receipt(data, b"x" * 32, POLICY) == (False, "REQUIRED_SCANNER_MISSING")


def test_non_promotable_decision_denied() -> None:
    data = valid_data()
    data["decision"]["decision"] = "needs_human"
    unsigned = {k: v for k, v in data.items() if k != "signature"}
    data["signature"] = sign_payload(unsigned, b"x" * 32)
    assert authorize_receipt(data, b"x" * 32, POLICY) == (False, "RECEIPT_DECISION_NOT_ALLOW")


def test_high_tier_requires_approval_at_each_stage() -> None:
    data = valid_data()
    data["autonomy_tier"] = "high"
    unsigned = {k: v for k, v in data.items() if k != "signature"}
    data["signature"] = sign_payload(unsigned, b"x" * 32)
    assert authorize_receipt(data, b"x" * 32, POLICY) == (False, "HIGH_TIER_APPROVAL_MISSING")
    data["approvals"] = [
        {"actor": "reviewer", "stage": stage, "approved": True, "timestamp": "2026-10-13T00:00:00Z"}
        for stage in ["prove", "fix", "attack", "ship"]
    ]
    unsigned = {k: v for k, v in data.items() if k != "signature"}
    data["signature"] = sign_payload(unsigned, b"x" * 32)
    assert authorize_receipt(data, b"x" * 32, POLICY) == (True, "SIGNED_RECEIPT_ACCEPTED")


def test_slo_exact_threshold_is_allowed_and_breach_denied() -> None:
    data = valid_data()
    data["canary"]["error_rate"] = 0.01
    data["canary"]["p95_latency_regression"] = 0.20
    unsigned = {k: v for k, v in data.items() if k != "signature"}
    data["signature"] = sign_payload(unsigned, b"x" * 32)
    assert authorize_receipt(data, b"x" * 32, POLICY) == (True, "SIGNED_RECEIPT_ACCEPTED")
    data["canary"]["error_rate"] = 0.010001
    unsigned = {k: v for k, v in data.items() if k != "signature"}
    data["signature"] = sign_payload(unsigned, b"x" * 32)
    assert authorize_receipt(data, b"x" * 32, POLICY) == (False, "ERROR_RATE_BREACH")

def test_non_string_scanner_status_is_denied() -> None:
    data = valid_data()
    data["scans"][0]["status"] = 123
    unsigned = {k: v for k, v in data.items() if k != "signature"}
    data["signature"] = sign_payload(unsigned, b"x" * 32)

    assert authorize_receipt(data, b"x" * 32, POLICY) == (
        False,
        "RECEIPT_SCHEMA_INVALID",
    )

def test_non_string_high_tier_approval_stage_is_denied() -> None:
    data = valid_data()
    data["autonomy_tier"] = "high"
    data["approvals"] = [
        {
            "actor": "reviewer",
            "stage": 123,
            "approved": True,
            "timestamp": "2026-10-13T00:00:00Z",
        }
    ]
    unsigned = {k: v for k, v in data.items() if k != "signature"}
    data["signature"] = sign_payload(unsigned, b"x" * 32)

    assert authorize_receipt(data, b"x" * 32, POLICY) == (
        False,
        "RECEIPT_SCHEMA_INVALID",
    )
