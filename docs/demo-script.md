# Three-minute demo shot list

Record a single screen capture, under three minutes. Show only real command output and actual GitLab pipeline artifacts; do not replace missing results with fabricated metrics.

- **0:00–0:20 — PROVE:** show the controlled target, CVE manifest and a proof test that fails before a fix. If a finding has no reachable proof, show the escalation decision instead.
- **0:20–0:45 — FIX:** show the proposed diff and the file/path gate. Demonstrate that changing an existing test is denied.
- **0:45–1:20 — ATTACK:** show GitLab-native scan jobs and report artifacts. Show missing scanner evidence causing a denial.
- **1:20–2:10 — SHIP:** show the policy-computed Autonomy Dial and a real canary metric sample. Show a threshold breach leading to denial/rollback; never use made-up production metrics.
- **2:10–2:50 — RECEIPT:** show receipt.json, receipt.md and receipt.html, then demonstrate that changing one field invalidates the signature and the merge gate denies it.
- **2:50–3:00:** state what remains human-approved and the limits of the controlled target.

Before recording, verify current Duo agent/flow/trigger syntax, ensure the GitLab project has actual pipeline history, and capture a real end-to-end run. A local unit test is not evidence that a GitLab integration works.
