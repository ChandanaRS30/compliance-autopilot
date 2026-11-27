"""Audit-readiness report: one view for control owners and auditors, one for engineers."""
from __future__ import annotations

from datetime import datetime, timezone

from .checks import CHECKS, ERROR, FAIL, PASS
from .github import GitHub
from .scan import Control, RepoResult, control_status

ICON = {PASS: "PASS", FAIL: "FAIL", ERROR: "NOT VERIFIED"}


def to_markdown(controls: list[Control], results: list[RepoResult], gh: GitHub, generated: datetime | None = None) -> str:
    when = (generated or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")
    statuses = {(r.repo, c.id): control_status(c, r) for r in results for c in controls}
    total = len(statuses)
    passed = sum(s == PASS for s in statuses.values())
    unverified = sum(s == ERROR for s in statuses.values())

    L = [f"# Audit readiness report", "", f"Generated {when} for {len(results)} repositories and {len(controls)} controls.", ""]
    L += [
        f"**{passed} of {total} control checks pass ({passed / total:.0%})**, "
        f"{total - passed - unverified} fail, {unverified} could not be verified. "
        "A control passes only if every technical check behind it passes; unverified never counts as compliant.",
        "",
    ]

    L += ["## Control status", "", "| Control | " + " | ".join(r.repo for r in results) + " |", "|---|" + "---|" * len(results)]
    for c in controls:
        L.append(f"| {c.id} {c.title} | " + " | ".join(ICON[statuses[(r.repo, c.id)]] for r in results) + " |")

    L += ["", "## Controls and framework mapping (for control owners and auditors)", ""]
    for c in controls:
        L += [
            f"### {c.id} {c.title}",
            "",
            f"**Requirement:** {c.requirement}",
            "",
            f"- ISO/IEC 27001:2022 Annex A: {'; '.join(c.iso27001) or 'n/a'}",
            f"- SOC 2 (TSC): {'; '.join(c.soc2) or 'n/a'}",
            f"- BSI C5:2020 (domain): {'; '.join(c.c5) or 'n/a'}",
            f"- Mapping status: {c.mapping_status} (to be confirmed by the control owner)",
            "",
            "| Repository | Check | Result | Detail | Evidence |",
            "|---|---|---|---|---|",
        ]
        for r in results:
            for name in c.checks:
                res = r.checks[name]
                L.append(f"| {r.repo} | {CHECKS[name].description} | {ICON[res.status]} | {res.detail} | {', '.join(res.evidence)} |")
        L.append("")

    L += ["## Remediation tasks (for engineering)", ""]
    tasks = [(r, c, r.checks[n]) for r in results for c in controls for n in c.checks if r.checks[n].status != PASS]
    seen = set()
    if not tasks:
        L.append("No open tasks.")
    for r, c, res in tasks:
        key = (r.repo, res.check)
        if key in seen:
            continue
        seen.add(key)
        L.append(f"- [ ] **{r.repo}**, {CHECKS[res.check].description.lower()} ({c.id}): {CHECKS[res.check].engineering_task}")

    L += ["", "## Evidence index", "", "Raw responses are stored as `<id>.json`; `manifest.json` lists their SHA-256 hashes and `manifest.sha256` seals the manifest.", "", "| Evidence | Retrieved (UTC) | HTTP | Source | SHA-256 |", "|---|---|---|---|---|"]
    for ev in gh.evidence:
        L.append(f"| {ev.id} | {ev.retrieved_at} | {ev.status} | `{ev.url.replace('https://api.github.com', '')}` | `{ev.sha256[:16]}…` |")
    return "\n".join(L) + "\n"
