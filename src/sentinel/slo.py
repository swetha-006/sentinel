from __future__ import annotations

from typing import Any

from sentinel.models import Decision, DecisionKind, SLOMetrics
from sentinel.gates import _decision

def evaluate_slo(metrics: SLOMetrics | None, policy: dict[str, Any]) -> Decision:
    if metrics is None:
        return _decision(DecisionKind.DENY, "SLO_METRICS_MISSING", None)
    slo = policy["slo"]
    inputs = {"metrics": metrics.model_dump(), "thresholds": slo}
    if metrics.observed_minutes < slo["canary_minutes"]:
        return _decision(DecisionKind.DENY, "CANARY_WINDOW_INCOMPLETE", inputs)
    if metrics.error_rate > slo["error_rate_max"]:
        return _decision(DecisionKind.DENY, "ERROR_RATE_BREACH", inputs)
    if metrics.p95_latency_regression > slo["p95_latency_regression_max"]:
        return _decision(DecisionKind.DENY, "P95_REGRESSION_BREACH", inputs)
    return _decision(DecisionKind.ALLOW, "SLO_WITHIN_LIMITS", inputs)
