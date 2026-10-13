from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Protocol


class OSVLookup(Protocol):
    def query_advisory(self, package_name: str, version: str) -> dict[str, Any]: ...


class OSVAPIClient:
    """Uses the documented OSV query API. A GitLab MCP client can wrap this interface."""

    def __init__(self, endpoint: str = "https://api.osv.dev/v1/query") -> None:
        self.endpoint = endpoint

    def query_advisory(self, package_name: str, version: str) -> dict[str, Any]:
        if not package_name.strip() or not version.strip():
            raise ValueError("package name and version are required")
        payload = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}
        request = urllib.request.Request(self.endpoint, data=json.dumps(payload).encode(), method="POST", headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "sentinel-proof-remediation/0.2"})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                result = json.loads(response.read().decode())
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"OSV lookup failed; refusing to infer advisory data: {exc}") from exc
        if not isinstance(result, dict):
            raise RuntimeError("OSV returned an unexpected response")
        return result


class UnconfiguredOSVClient:
    def query_advisory(self, package_name: str, version: str) -> dict[str, Any]:
        raise RuntimeError("OSV client is not configured; refusing to infer advisory data")
