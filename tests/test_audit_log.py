import json
from pathlib import Path
import pytest
from sentinel.audit_log import append_audit

def test_audit_appends_structured_records(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    append_audit(p, actor="test", action="gate", verb="ship", correlation_id="c", decision="deny", details={})
    append_audit(p, actor="test", action="gate", verb="ship", correlation_id="c", decision="deny", details={})
    rows = [json.loads(x) for x in p.read_text().splitlines()]
    assert len(rows) == 2 and rows[0]["verb"] == "ship"

def test_audit_rejects_extra_verbs(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        append_audit(tmp_path / "audit", actor="x", action="x", verb="triage", correlation_id="c", decision="deny", details={})
