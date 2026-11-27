"""Minimal GitHub REST client that keeps every response as audit evidence.

Each call is recorded with its URL, HTTP status, UTC timestamp and the SHA-256
hash of the response body, so an auditor can see exactly what was checked, when,
and that the stored evidence was not changed afterwards.
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

API = "https://api.github.com"


@dataclass
class Evidence:
    id: str
    url: str
    status: int
    retrieved_at: str
    sha256: str
    body: Any


@dataclass
class Response:
    status: int
    json: Any
    evidence_id: str


# A transport takes a URL and returns (status, body bytes). Tests replace it with fixtures.
Transport = Callable[[str], tuple[int, bytes]]


def http_transport(token: str | None = None) -> Transport:
    def fetch(url: str) -> tuple[int, bytes]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "compliance-autopilot"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    return fetch


@dataclass
class GitHub:
    transport: Transport = field(default_factory=lambda: http_transport(os.environ.get("GITHUB_TOKEN")))
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    evidence: list[Evidence] = field(default_factory=list)

    def get(self, path: str) -> Response:
        url = f"{API}{path}"
        status, raw = self.transport(url)
        try:
            body = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            body = raw.decode("utf-8", "replace")
        ev = Evidence(
            id=f"E-{len(self.evidence) + 1:03d}",
            url=url,
            status=status,
            retrieved_at=self.clock().strftime("%Y-%m-%dT%H:%M:%SZ"),
            sha256=hashlib.sha256(raw).hexdigest(),
            body=body,
        )
        self.evidence.append(ev)
        return Response(status, body, ev.id)
