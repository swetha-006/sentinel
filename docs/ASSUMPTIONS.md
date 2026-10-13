# Assumptions and platform verification

Every file under `.gitlab/` is an adapter contract, not a claim of verified current GitLab Duo Agent Platform syntax. Before enabling it, check official GitLab documentation for the exact release in your group.

1. Agent and flow definition schema, supported fields, tool invocation and handoff syntax must be verified.
2. Trigger schema and available events for scheduled scans, new vulnerability report findings, issue labels and MCP advisory lookup must be verified.
3. The current GitLab-supported MCP client configuration and OSV server/transport must be configured; `OSVAPIClient` currently calls the public OSV HTTP API directly.
4. CI template names, analyzer availability and security report artifact formats vary by GitLab tier/version. Verify SAST, dependency scanning, secret detection, container scanning and SBOM support for your instance.
5. Configure a project-scoped token with only the API/repository permissions needed. Store it as masked and protected; do not make it available to untrusted fork pipelines or agents.
6. Protect the default branch and make the SHIP gate required. A successful pipeline artifact does not block a merge unless branch policy enforces it.
7. Configure production deployment credentials outside the agent environment. Agents must never read production secrets.
8. The receipt uses HMAC-SHA256; the key must be 32+ bytes and held in a protected secret store. HMAC is not non-repudiation because the verifier also possesses the secret.
9. The `sentinel-halt` issue label must be checked by the platform adapter before any write or deployment action. The core accepts a boolean kill-switch signal but cannot query GitLab without an adapter call.
10. Canary metrics must come from a real telemetry source, with baseline and canary windows defined consistently. The load script is a local demo utility, not a source of production SLO truth.
11. Cloud Run Terraform has not been applied. Validate IAM, APIs, image provenance, secret bindings, network exposure and rollback in a disposable project.
12. Dependency scanner findings are not automatically reachable exploits. The CVE manifest records known affected version ranges and caveats; confirm live findings with current OSV/vendor advisories.
