<!-- VERIFY AGAINST CURRENT GITLAB DOCS -->
# Sentinel triggers

Intended trigger sources: scheduled scan; new finding in the vulnerability report; OSV advisory lookup through an MCP client; issue labeled `sentinel`. All triggers must check `sentinel-halt` before work and deduplicate by advisory + package + repository.

This is a trigger contract, not verified current GitLab trigger syntax.
