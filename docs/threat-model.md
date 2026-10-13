# Threat model

| Threat | Attack path | Mitigation | Enforcing component |
|---|---|---|---|
| Malicious advisory content | Advisory includes instructions intended to redirect an agent | Treat prose as untrusted data; hash it; only deterministic code controls permissions | `triage.py`, `.gitlab/agents/` contract |
| Poisoned changelog | Changelog asks the agent to run commands or expose credentials | No shell execution of advisory prose; proposed changes go through diff and pipeline gates | agent contract, `gates.py`, CI |
| Test tampering | Agent edits/deletes an existing test to make the proof pass | Existing test modifications denied unless reviewed policy explicitly allows | `gates.py` |
| Token abuse | Prompt or malicious patch attempts to exfiltrate project token | Masked/protected scoped token; no secrets in prompts; protected branch and isolated runners | GitLab settings, adapter, CI |
| Runaway automation | Retry loop creates many issues/MRs | Stable idempotency key, open-MR cap, two attempts then human escalation, kill-switch | `idempotency.py`, `gates.py`, `orchestrator.py`, platform adapter |
| Supply-chain upgrade risk | New dependency version introduces regressions or a new vulnerability | Proof, existing tests, native scanners, SBOM, review and canary SLO | CI, `proof.py`, `slo.py`, receipt gate |
| Receipt tampering | Evidence altered after authorization | Canonical JSON HMAC and deterministic verification before gate acceptance | `proof.py`, `receipt.py` |
| Missing scanner evidence | A job silently skips or emits no report | Required scanner set and nonempty report digests; fail closed | `receipt.py`, protected CI gate |
| False exploitability claim | A vulnerable library is present but no app path invokes it | Distinguish package finding from reachable proof; escalate when no executable proof is possible | `CVE-MANIFEST.md`, policy, human review |
| Canary metric spoofing | Agent supplies fabricated healthy values | Only telemetry adapters may supply production metrics; local load data cannot authorize production | platform adapter, `slo.py` |

## Residual risk

HMAC uses a shared secret and does not provide asymmetric non-repudiation. Platform-specific branch protections, agent permissions, real scanner artifact validation and telemetry binding must be tested in the destination GitLab project. The demo app is deliberately vulnerable and must remain isolated.
