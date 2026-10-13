from sentinel.models import DecisionKind, SLOMetrics
from sentinel.slo import evaluate_slo

def test_slo_exact_threshold_passes(policy: dict[str, object]) -> None:
    m = SLOMetrics(error_rate=0.01, p95_latency_regression=0.20, observed_minutes=10)
    assert evaluate_slo(m, policy).decision == DecisionKind.ALLOW

def test_slo_breach_denies(policy: dict[str, object]) -> None:
    m = SLOMetrics(error_rate=0.0101, p95_latency_regression=0.0, observed_minutes=10)
    assert evaluate_slo(m, policy).reason_code == "ERROR_RATE_BREACH"

def test_missing_or_short_canary_denies(policy: dict[str, object]) -> None:
    assert evaluate_slo(None, policy).decision == DecisionKind.DENY
    assert evaluate_slo(SLOMetrics(error_rate=0, p95_latency_regression=0, observed_minutes=9), policy).reason_code == "CANARY_WINDOW_INCOMPLETE"
