from fastapi.testclient import TestClient
from app import app, accounts, ledger

client = TestClient(app)
def setup_function() -> None:
    accounts.clear()
    accounts.update({"demo-account": 100_000})
    ledger.clear()

def test_health() -> None:
    assert client.get("/health").json() == {"status":"ok"}

def test_payment_debits_account_and_adds_ledger_entry() -> None:
    response = client.post("/payments", json={"account_id":"demo-account","amount_cents":2500,"currency":"USD"})
    assert response.status_code == 201
    assert client.get("/accounts/demo-account").json()["balance_cents"] == 97500
    assert client.get("/ledger").json()["count"] == 1

def test_payment_rejects_insufficient_funds() -> None:
    response = client.post("/payments", json={"account_id":"demo-account","amount_cents":100001})
    assert response.status_code == 409

def test_payment_rejects_unknown_account() -> None:
    assert client.post("/payments", json={"account_id":"missing","amount_cents":1}).status_code == 404
