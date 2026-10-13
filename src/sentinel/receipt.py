from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from sentinel.models import ProofReceipt
from sentinel.proof import sign_payload, verify_receipt_signature


def sign_receipt_data(data: dict[str, Any], key: bytes) -> dict[str, Any]:
    unsigned = {name: value for name, value in data.items() if name != "signature"}
    unsigned["signature"] = sign_payload(unsigned, key)
    return unsigned


def validate_receipt_data(data: dict[str, Any]) -> None:
    schema_path = Path(__file__).with_name("receipt.schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema).iter_errors(data))
    if errors:
        details = "; ".join(f"{list(error.path)}: {error.message}" for error in errors)
        raise ValueError("receipt schema validation failed: " + details)


def authorize_receipt(data: dict[str, Any], key: bytes, policy: dict[str, Any] | None = None) -> tuple[bool, str]:
    """Deterministic merge gate. Missing/invalid evidence is always a denial."""
    try:
        validate_receipt_data(data)
    except (OSError, ValueError, json.JSONDecodeError):
        return False, "RECEIPT_SCHEMA_INVALID"
    if not verify_receipt_signature(data, key):
        return False, "RECEIPT_SIGNATURE_INVALID"
    if policy is None:
        return False, "POLICY_INPUT_MISSING"
    proof = data.get("proof")
    if not isinstance(proof, dict) or proof.get("before_failed") is not True or proof.get("after_passed") is not True or proof.get("existing_tests_passed") is not True:
        return False, "PROOF_NOT_RED_THEN_GREEN"
    scans = data.get("scans")
    required_scanners = {"sast", "dependency", "secret", "container", "sbom"}
    if not isinstance(scans, list):
        return False, "SCAN_EVIDENCE_MISSING"
    scan_map = {str(item.get("scanner", "")).lower(): item for item in scans if isinstance(item, dict)}
    if not required_scanners.issubset(scan_map):
        return False, "REQUIRED_SCANNER_MISSING"
    for scanner in required_scanners:
        item = scan_map[scanner]
        digest = item.get("report_digest", "")
        if item.get("status", "").lower() not in {"clean", "passed", "no_new_findings"} or not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            return False, "SCAN_NOT_CLEAN_OR_DIGEST_INVALID"
    decision = data.get("decision", {})
    if decision.get("decision") != "allow":
        return False, "RECEIPT_DECISION_NOT_ALLOW"
    canary = data.get("canary")
    if not isinstance(canary, dict):
        return False, "CANARY_METRICS_MISSING"
    required_metrics = {"observed_minutes", "error_rate", "p95_latency_regression", "promote"}
    if not required_metrics.issubset(canary):
        return False, "CANARY_METRICS_MISSING"
    slo = policy.get("slo", {})
    if canary["observed_minutes"] < slo.get("canary_minutes", float("inf")):
        return False, "CANARY_WINDOW_INCOMPLETE"
    if canary["error_rate"] > slo.get("error_rate_max", -1):
        return False, "ERROR_RATE_BREACH"
    if canary["p95_latency_regression"] > slo.get("p95_latency_regression_max", -1):
        return False, "P95_REGRESSION_BREACH"
    if canary.get("promote") is not True:
        return False, "CANARY_NOT_PROMOTABLE"
    if data.get("autonomy_tier") == "high":
        approvals = data.get("approvals", [])
        required_stages = {"prove", "fix", "attack", "ship"}
        approved_stages = {item.get("stage", "").lower() for item in approvals if isinstance(item, dict) and item.get("approved") is True}
        if not required_stages.issubset(approved_stages):
            return False, "HIGH_TIER_APPROVAL_MISSING"
    return True, "SIGNED_RECEIPT_ACCEPTED"


def write_receipt(receipt: ProofReceipt, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    data = receipt.model_dump(mode="json")
    validate_receipt_data(data)
    (output_dir / "receipt.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    scans = "\n".join(f"| {s.scanner} | {s.status} | `{s.report_digest}` |" for s in receipt.scans) or "| none | missing | — |"
    approvals = "\n".join(f"| {a.actor} | {a.stage} | {a.approved} | {a.timestamp} |" for a in receipt.approvals) or "| none | missing | — |"
    md = f"""# Sentinel Proof Receipt

- Correlation: `{receipt.correlation_id}`
- Finding: `{json.dumps(receipt.finding, sort_keys=True)}`
- Autonomy Dial: **{receipt.autonomy_tier.value}**
- Decision: **{receipt.decision.decision.value}** (`{receipt.decision.reason_code}`)
- Signed off by: `{receipt.signed_off_by}`
- Signature: `{receipt.signature}`

## PROVE — failing then passing evidence

```json
{json.dumps(receipt.proof, indent=2, sort_keys=True)}
```

## ATTACK — scanner results

| Scanner | Status | Report digest |
|---|---|---|
{scans}

## ATTACK — approvals

| Actor | Stage | Approved | Timestamp |
|---|---|---|---|
{approvals}

## SHIP — canary metrics and decision

```json
{json.dumps(receipt.canary, indent=2, sort_keys=True)}
```
"""
    (output_dir / "receipt.md").write_text(md, encoding="utf-8")
    esc = html.escape
    scan_rows = "".join(f"<tr><td>{esc(s.scanner)}</td><td>{esc(s.status)}</td><td><code>{esc(s.report_digest)}</code></td></tr>" for s in receipt.scans) or "<tr><td colspan=3>Missing scan evidence</td></tr>"
    approval_rows = "".join(f"<tr><td>{esc(a.actor)}</td><td>{esc(a.stage)}</td><td>{str(a.approved).lower()}</td><td>{esc(a.timestamp)}</td></tr>" for a in receipt.approvals) or "<tr><td colspan=4>Missing approval evidence</td></tr>"
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Sentinel Proof Receipt</title><style>:root{{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:#20252b;background:#f5f6f7;--accent:#2457a7}}body{{max-width:960px;margin:32px auto;padding:0 18px}}header,section{{background:#fff;border:1px solid #d9dde2;border-radius:8px;padding:20px;margin:14px 0}}h1{{margin:0 0 8px;font-size:1.65rem}}h2{{font-size:1.08rem;border-bottom:1px solid #e2e5e9;padding-bottom:8px}}.accent{{color:var(--accent);font-weight:650}}table{{border-collapse:collapse;width:100%;font-size:.92rem}}th,td{{text-align:left;border-bottom:1px solid #e2e5e9;padding:9px;overflow-wrap:anywhere}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f5f6;padding:12px;border-radius:5px}}.decision{{font-size:1.2rem;font-weight:700}}code{{overflow-wrap:anywhere}}</style></head><body><header><h1>Sentinel Proof Receipt</h1><p>Correlation <code>{esc(receipt.correlation_id)}</code></p><p>Finding <code>{esc(json.dumps(receipt.finding, sort_keys=True))}</code></p><p>Autonomy Dial: <span class="accent">{esc(receipt.autonomy_tier.value)}</span></p><p class="decision">{esc(receipt.decision.decision.value)} · {esc(receipt.decision.reason_code)}</p><p>Signed off by <strong>{esc(receipt.signed_off_by)}</strong></p><p>HMAC-SHA256: <code>{esc(receipt.signature)}</code></p></header><section><h2>PROVE — executable evidence</h2><pre>{esc(json.dumps(receipt.proof,indent=2,sort_keys=True))}</pre></section><section><h2>ATTACK — scanner results</h2><table><thead><tr><th>Scanner</th><th>Status</th><th>Report digest</th></tr></thead><tbody>{scan_rows}</tbody></table></section><section><h2>ATTACK — approvals</h2><table><thead><tr><th>Actor</th><th>Stage</th><th>Approved</th><th>Timestamp</th></tr></thead><tbody>{approval_rows}</tbody></table></section><section><h2>SHIP — canary decision</h2><pre>{esc(json.dumps(receipt.canary,indent=2,sort_keys=True))}</pre></section></body></html>"""
    (output_dir / "receipt.html").write_text(page, encoding="utf-8")
