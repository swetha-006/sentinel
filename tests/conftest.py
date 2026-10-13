from pathlib import Path
import pytest
from sentinel.policy import load_policy

ROOT = Path(__file__).resolve().parents[1]
@pytest.fixture
def policy() -> dict[str, object]:
    return load_policy(ROOT / ".sentinel/policy.yml", ROOT / ".sentinel/policy.schema.json")
