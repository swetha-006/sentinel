from pathlib import Path
def test_golden_receipt_contract_is_documented() -> None:
    golden = Path(__file__).parent / "golden/receipt.md"
    assert "Sentinel Proof Receipt" in golden.read_text(encoding="utf-8")
