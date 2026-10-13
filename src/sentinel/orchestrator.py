from __future__ import annotations
from dataclasses import dataclass
from sentinel.models import Decision, DecisionKind
from sentinel.gates import _decision

@dataclass(frozen=True)
class AttemptState:
    attempts: int
    last_reason: str

def retry_decision(state: AttemptState, max_attempts: int = 2) -> Decision:
    inputs = {"attempts": state.attempts, "max_attempts": max_attempts, "last_reason": state.last_reason}
    if max_attempts < 1 or max_attempts > 2 or state.attempts < 0:
        return _decision(DecisionKind.DENY, "INVALID_RETRY_STATE", inputs)
    if state.attempts >= max_attempts:
        return _decision(DecisionKind.NEEDS_HUMAN, "ATTEMPT_LIMIT_ESCALATE", inputs)
    return _decision(DecisionKind.ALLOW, "RETRY_WITHIN_LIMIT", inputs)
