from __future__ import annotations
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from uuid import uuid4

app = FastAPI(title="Controlled Payments Demo", version="0.1.0")
accounts: dict[str, int] = {"demo-account": 100_000}
ledger: list[dict[str, object]] = []

class PaymentRequest(BaseModel):
    account_id: str
    amount_cents: int = Field(gt=0, le=1_000_000)
    currency: str = Field(default="USD", pattern="^[A-Z]{3}$")

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

@app.get("/accounts/{account_id}")
def get_account(account_id: str) -> dict[str, object]:
    if account_id not in accounts:
        raise HTTPException(status_code=404, detail="account not found")
    return {"account_id": account_id, "balance_cents": accounts[account_id]}

@app.post("/payments", status_code=201)
def create_payment(payment: PaymentRequest) -> dict[str, object]:
    if payment.account_id not in accounts:
        raise HTTPException(status_code=404, detail="account not found")
    if accounts[payment.account_id] < payment.amount_cents:
        raise HTTPException(status_code=409, detail="insufficient funds")
    accounts[payment.account_id] -= payment.amount_cents
    item = {"payment_id": str(uuid4()), "account_id": payment.account_id, "amount_cents": payment.amount_cents, "currency": payment.currency, "status": "accepted"}
    ledger.append(item)
    return item

@app.get("/ledger")
def get_ledger() -> dict[str, object]:
    return {"items": ledger, "count": len(ledger)}
