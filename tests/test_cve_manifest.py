from pathlib import Path


def test_controlled_target_documents_five_distinct_cves() -> None:
    manifest = Path("target-app/CVE-MANIFEST.md").read_text(encoding="utf-8")
    assert manifest.count("[CVE-") >= 5
    for package in ("PyYAML", "urllib3", "requests", "Jinja2", "python-multipart", "cryptography"):
        assert package in manifest
    assert "not be deployed" in manifest.lower()
    assert "Expected escalation" in manifest
