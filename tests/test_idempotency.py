import pytest
from sentinel.idempotency import idempotency_key

def test_stable_and_normalized_key() -> None:
    assert idempotency_key("CVE-X", "Pkg", "Org/Repo") == idempotency_key("cve-x", "pkg", "org/repo")
    assert idempotency_key("CVE-X", "pkg", "r") != idempotency_key("CVE-Y", "pkg", "r")

def test_empty_component_rejected() -> None:
    with pytest.raises(ValueError):
        idempotency_key("", "pkg", "r")
