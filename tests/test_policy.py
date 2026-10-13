from pathlib import Path
import pytest
from sentinel.policy import PolicyError, load_policy

def test_policy_schema_validates() -> None:
    root = Path(__file__).resolve().parents[1]
    assert load_policy(root / ".sentinel/policy.yml", root / ".sentinel/policy.schema.json")["version"] == 1

def test_invalid_policy_fails_closed(tmp_path: Path) -> None:
    p, s = tmp_path / "policy.yml", tmp_path / "schema.json"
    p.write_text("version: 9\n", encoding="utf-8")
    s.write_text('{"type":"object","required":["version"],"properties":{"version":{"const":1}}}', encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(p, s)
