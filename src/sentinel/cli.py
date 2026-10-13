from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from pydantic import ValidationError

from sentinel.audit_log import append_audit
from sentinel.models import Finding, ProofReceipt
from sentinel.policy import PolicyError, load_policy
from sentinel.receipt import authorize_receipt, sign_receipt_data, validate_receipt_data, write_receipt
from sentinel.risk import autonomy_tier
from sentinel.triage import triage_finding
from sentinel.osv_client import OSVAPIClient


def _key_from_env(name: str) -> bytes:
    value = os.environ.get(name, "")
    if len(value.encode()) < 32:
        raise ValueError(f"environment variable {name} must be set to at least 32 bytes")
    return value.encode()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check-policy", help="Validate policy against the checked-in JSON Schema")
    check.add_argument("--policy", type=Path, default=Path(".sentinel/policy.yml"))
    check.add_argument("--schema", type=Path, default=Path(".sentinel/policy.schema.json"))
    triage = sub.add_parser("triage", help="Compute idempotency key and Autonomy Dial tier")
    triage.add_argument("--policy", type=Path, default=Path(".sentinel/policy.yml"))
    triage.add_argument("--schema", type=Path, default=Path(".sentinel/policy.schema.json"))
    triage.add_argument("--advisory", required=True)
    triage.add_argument("--package", required=True)
    triage.add_argument("--repository", required=True)
    triage.add_argument("--change-type", default="unknown")
    triage.add_argument("--path", action="append", default=[])
    triage.add_argument("--severity", default="unknown")
    triage.add_argument("--advisory-text", default="")
    osv = sub.add_parser("osv-query", help="Query public OSV API for a PyPI package/version")
    osv.add_argument("--package", required=True)
    osv.add_argument("--version", required=True)
    sign = sub.add_parser("sign-receipt", help="Sign an unsigned receipt JSON and render the three receipt formats")
    sign.add_argument("--input", type=Path, required=True)
    sign.add_argument("--output-dir", type=Path, default=Path("receipt"))
    sign.add_argument("--key-env", default="SENTINEL_RECEIPT_KEY")
    verify = sub.add_parser("verify-receipt", help="Verify signature and deterministic promotion requirements")
    verify.add_argument("--receipt", type=Path, default=Path("receipt/receipt.json"))
    verify.add_argument("--key-env", default="SENTINEL_RECEIPT_KEY")
    verify.add_argument("--policy", type=Path, default=Path(".sentinel/policy.yml"))
    verify.add_argument("--schema", type=Path, default=Path(".sentinel/policy.schema.json"))
    args = parser.parse_args(argv)
    try:
        if args.command == "osv-query":
            print(json.dumps(OSVAPIClient().query_advisory(args.package, args.version), sort_keys=True, indent=2))
            return 0
        if args.command in {"sign-receipt", "verify-receipt"}:
            key = _key_from_env(args.key_env)
            raw = json.loads(args.input.read_text(encoding="utf-8")) if args.command == "sign-receipt" else json.loads(args.receipt.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("receipt root must be a JSON object")
            if args.command == "sign-receipt":
                signed = sign_receipt_data(raw, key)
                validate_receipt_data(signed)
                receipt = ProofReceipt.model_validate(signed)
                write_receipt(receipt, args.output_dir)
                print(json.dumps({"verb": "receipt", "decision": "needs_human", "reason_code": "SIGNED_RECEIPT_CREATED_REQUIRES_GATE_VERIFICATION"}))
                return 0
            policy = load_policy(args.policy, args.schema)
            allowed, reason = authorize_receipt(raw, key, policy)
            print(json.dumps({"verb": "ship", "decision": "allow" if allowed else "deny", "reason_code": reason}, sort_keys=True))
            return 0 if allowed else 3
        policy_path = args.policy
        schema_path = args.schema
        policy = load_policy(policy_path, schema_path)
    except (PolicyError, OSError, ValueError, json.JSONDecodeError, ValidationError, RuntimeError) as exc:
        command = getattr(args, "command", "triage")
        verb = "ship" if command == "verify-receipt" else "receipt" if command == "sign-receipt" else "prove"
        print(json.dumps({"verb": verb, "decision": "deny", "reason_code": "INVALID_INPUT", "error": str(exc)}), file=sys.stderr)
        return 2
    if args.command == "check-policy":
        print(json.dumps({"verb": "prove", "decision": "allow", "reason_code": "POLICY_VALID"}))
        return 0
    finding = Finding(advisory_id=args.advisory, package=args.package, repository=args.repository, change_type=args.change_type, paths=tuple(args.path), severity=args.severity, advisory_text=args.advisory_text)
    details = triage_finding(finding)
    tier = autonomy_tier(finding, policy)
    print(json.dumps({"verb": "prove", "correlation_id": details["idempotency_key"][:16], "finding": details, "autonomy_tier": tier.value}, sort_keys=True))
    append_audit(Path(".sentinel/audit.jsonl"), actor="cli-user", action="triage-finding", verb="prove", correlation_id=details["idempotency_key"][:16], decision="triaged", details={"tier": tier.value, "key": details["idempotency_key"]})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
