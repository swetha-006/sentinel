from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Protocol


class GitLabAdapter(Protocol):
    def create_issue_once(self, idempotency_key: str, title: str, description: str, labels: list[str]) -> str: ...
    def create_merge_request_once(self, idempotency_key: str, source_branch: str, target_branch: str) -> str: ...
    def issue_has_label(self, issue_id: str, label: str) -> bool: ...
    def post_receipt_note_once(self, issue_iid: str, idempotency_key: str, receipt_markdown: str) -> str: ...


class GitLabAPIError(RuntimeError):
    pass


class GitLabRESTClient:
    """Small GitLab REST adapter. Use a project-scoped token with minimum API permissions."""

    def __init__(self, project_id: str, token: str, base_url: str = "https://gitlab.com/api/v4") -> None:
        if not project_id.strip() or not token.strip():
            raise ValueError("project id and scoped token are required")
        self.project_id = urllib.parse.quote(project_id, safe="")
        self.token = token
        self.base_url = base_url.rstrip("/")

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        body = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(f"{self.base_url}/projects/{self.project_id}/{path.lstrip('/')}", data=body, method=method, headers={"PRIVATE-TOKEN": self.token, "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return json.loads(response.read().decode()) if response.status != 204 else None
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise GitLabAPIError(f"GitLab API {method} {path} failed: {exc}") from exc

    def create_issue_once(self, idempotency_key: str, title: str, description: str, labels: list[str]) -> str:
        marker = f"sentinel-key:{idempotency_key}"
        query = urllib.parse.urlencode({"state": "all", "search": idempotency_key, "in": "description", "per_page": 100})
        existing = self._request("GET", f"issues?{query}")
        for issue in existing if isinstance(existing, list) else []:
            if marker in str(issue.get("description", "")):
                return str(issue["web_url"])
        result = self._request("POST", "issues", {"title": title, "description": f"{description}\n\n{marker}", "labels": ",".join(labels)})
        return str(result["web_url"])

    def create_merge_request_once(self, idempotency_key: str, source_branch: str, target_branch: str) -> str:
        marker = f"sentinel-key:{idempotency_key}"
        existing = self._request("GET", "merge_requests?state=all&source_branch={}".format(urllib.parse.quote(source_branch, safe="")))
        for mr in existing if isinstance(existing, list) else []:
            if marker in str(mr.get("description", "")):
                return str(mr["web_url"])
        result = self._request("POST", "merge_requests", {"source_branch": source_branch, "target_branch": target_branch, "title": f"Sentinel remediation: {source_branch}", "description": marker, "remove_source_branch": True})
        return str(result["web_url"])

    def issue_has_label(self, issue_id: str, label: str) -> bool:
        result = self._request("GET", f"issues/{urllib.parse.quote(issue_id, safe='')}")
        labels = result.get("labels", []) if isinstance(result, dict) else []
        return label in labels

    def post_receipt_note_once(self, issue_iid: str, idempotency_key: str, receipt_markdown: str) -> str:
        marker = f"sentinel-receipt:{idempotency_key}"
        issue = urllib.parse.quote(issue_iid, safe="")
        existing = self._request("GET", f"issues/{issue}/notes?per_page=100")
        for note in existing if isinstance(existing, list) else []:
            if marker in str(note.get("body", "")):
                return str(note.get("web_url", f"issue-note:{note.get('id', '')}"))
        result = self._request("POST", f"issues/{issue}/notes", {"body": f"{receipt_markdown}\n\n<!-- {marker} -->"})
        return str(result.get("web_url", f"issue-note:{result.get('id', '')}"))


class UnconfiguredGitLabClient:
    """Fail-closed client used when GitLab credentials are absent."""
    def __getattr__(self, name: str) -> Any:
        raise RuntimeError(f"GitLab adapter operation {name!r} is not configured")
