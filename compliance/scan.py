"""Run the control catalogue against repositories and write the evidence package."""
from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path

from .checks import CHECKS, ERROR, FAIL, PASS, Result, default_branch
from .github import GitHub

CATALOGUE = Path(__file__).resolve().parent.parent / "controls.toml"


@dataclass
class Control:
    id: str
    title: str
    requirement: str
    checks: list[str]
    iso27001: list[str]
    soc2: list[str]
    c5: list[str]
    mapping_status: str


def load_controls(path: Path = CATALOGUE) -> list[Control]:
    data = tomllib.loads(path.read_text())
    controls = [Control(**c) for c in data["control"]]
    ids = [c.id for c in controls]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate control ids in catalogue")
    for c in controls:
        unknown = set(c.checks) - set(CHECKS)
        if unknown:
            raise ValueError(f"{c.id} refers to unknown checks: {sorted(unknown)}")
        if not (c.iso27001 or c.soc2 or c.c5):
            raise ValueError(f"{c.id} is not mapped to any framework")
    return controls


@dataclass
class RepoResult:
    repo: str
    branch: str | None
    checks: dict[str, Result]


def control_status(control: Control, rr: RepoResult) -> str:
    """A control passes only if every check passes. Any ERROR makes it ERROR (not verified)."""
    states = [rr.checks[c].status for c in control.checks]
    if ERROR in states:
        return ERROR
    return PASS if all(s == PASS for s in states) else FAIL


def scan(repos: list[str], gh: GitHub | None = None) -> tuple[list[RepoResult], GitHub]:
    gh = gh or GitHub()
    needed = sorted({c for ctl in load_controls() for c in ctl.checks})
    results = []
    for repo in repos:
        branch, ev = default_branch(gh, repo)
        if branch is None:
            results.append(RepoResult(repo, None, {n: Result(n, ERROR, "Repository not reachable.", [ev]) for n in needed}))
            continue
        results.append(RepoResult(repo, branch, {n: CHECKS[n].run(gh, repo, branch) for n in needed}))
    return results, gh


def write_evidence(gh: GitHub, out: Path) -> Path:
    """Store each API response and a manifest of hashes. Returns the manifest path."""
    out.mkdir(parents=True, exist_ok=True)
    manifest = []
    for ev in gh.evidence:
        name = f"{ev.id}.json"
        (out / name).write_text(json.dumps(ev.body, indent=2, sort_keys=True))
        entry = asdict(ev)
        entry.pop("body")
        entry["file"] = name
        manifest.append(entry)
    text = json.dumps(manifest, indent=2)
    path = out / "manifest.json"
    path.write_text(text)
    (out / "manifest.sha256").write_text(hashlib.sha256(text.encode()).hexdigest() + "  manifest.json\n")
    return path
