from sentinel.models import DecisionKind
from sentinel.orchestrator import AttemptState, retry_decision

def test_two_attempts_then_human() -> None:
    assert retry_decision(AttemptState(1, "failed")).decision == DecisionKind.ALLOW
    assert retry_decision(AttemptState(2, "failed")).decision == DecisionKind.NEEDS_HUMAN

def test_retry_limit_cannot_be_increased() -> None:
    assert retry_decision(AttemptState(0, "x"), max_attempts=3).decision == DecisionKind.DENY
