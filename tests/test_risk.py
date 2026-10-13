from sentinel.models import Finding, Tier
from sentinel.risk import autonomy_tier

def test_major_is_high(policy: dict[str, object]) -> None:
    assert autonomy_tier(Finding(advisory_id="CVE-X", package="x", repository="r", change_type="major"), policy) == Tier.HIGH

def test_payment_path_is_high(policy: dict[str, object]) -> None:
    f = Finding(advisory_id="CVE-X", package="x", repository="r", change_type="patch", paths=("target-app/app.py",))
    assert autonomy_tier(f, policy) == Tier.HIGH

def test_minor_is_medium(policy: dict[str, object]) -> None:
    assert autonomy_tier(Finding(advisory_id="CVE-X", package="x", repository="r", change_type="minor"), policy) == Tier.MEDIUM
