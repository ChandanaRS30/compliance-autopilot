"""Automated technical checks. Each one returns PASS, FAIL or ERROR with its evidence.

ERROR means the check could not be completed (for example, an unexpected API
error). It is never counted as a pass: unverified is not compliant.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

from .github import GitHub

PASS, FAIL, ERROR = "PASS", "FAIL", "ERROR"


@dataclass
class Result:
    check: str
    status: str
    detail: str
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Check:
    name: str
    description: str
    engineering_task: str  # what an engineer does to fix a FAIL, in their language
    run: Callable[[GitHub, str, str], Result]


def _unexpected(check: str, status: int, ev: str) -> Result:
    return Result(check, ERROR, f"Could not verify: GitHub API returned HTTP {status}.", [ev])


def default_branch(gh: GitHub, repo: str) -> tuple[str | None, str]:
    r = gh.get(f"/repos/{repo}")
    if r.status != 200 or not isinstance(r.json, dict):
        return None, r.evidence_id
    return r.json.get("default_branch"), r.evidence_id


def _file_exists(gh: GitHub, repo: str, paths: list[str]) -> tuple[str | None, list[str], int | None]:
    """First existing path, the evidence ids, and an unexpected HTTP status if one occurred."""
    evs = []
    for p in paths:
        r = gh.get(f"/repos/{repo}/contents/{p}")
        evs.append(r.evidence_id)
        if r.status == 200:
            return p, evs, None
        if r.status != 404:
            return None, evs, r.status
    return None, evs, None


# ---------------------------------------------------------------- checks

def branch_protected(gh: GitHub, repo: str, branch: str) -> Result:
    r = gh.get(f"/repos/{repo}/branches/{branch}")
    if r.status != 200:
        return _unexpected("branch_protected", r.status, r.evidence_id)
    if r.json.get("protected") is True:
        return Result("branch_protected", PASS, f"Branch '{branch}' is protected.", [r.evidence_id])
    return Result("branch_protected", FAIL, f"Branch '{branch}' is not protected; direct pushes are possible.", [r.evidence_id])


def ci_passing(gh: GitHub, repo: str, branch: str, max_age_days: int = 30, now: datetime | None = None) -> Result:
    r = gh.get(f"/repos/{repo}/actions/runs?branch={branch}&per_page=1")
    if r.status != 200:
        return _unexpected("ci_passing", r.status, r.evidence_id)
    runs = r.json.get("workflow_runs", [])
    if not runs:
        return Result("ci_passing", FAIL, "No CI runs found on the default branch.", [r.evidence_id])
    run = runs[0]
    created = datetime.strptime(run["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    age = (now or gh.clock()) - created
    if run.get("conclusion") != "success":
        return Result("ci_passing", FAIL, f"Latest CI run '{run.get('name')}' concluded '{run.get('conclusion')}'.", [r.evidence_id])
    if age > timedelta(days=max_age_days):
        return Result("ci_passing", FAIL, f"Latest CI run passed but is {age.days} days old (limit {max_age_days}).", [r.evidence_id])
    return Result("ci_passing", PASS, f"Latest CI run '{run.get('name')}' passed {age.days} days ago.", [r.evidence_id])


def dependabot_enabled(gh: GitHub, repo: str, branch: str) -> Result:
    found, evs, bad = _file_exists(gh, repo, [".github/dependabot.yml", ".github/dependabot.yaml"])
    if bad:
        return Result("dependabot_enabled", ERROR, f"Could not verify: GitHub API returned HTTP {bad}.", evs)
    if found:
        return Result("dependabot_enabled", PASS, f"Dependency monitoring configured in {found}.", evs)
    return Result("dependabot_enabled", FAIL, "No Dependabot configuration found.", evs)


def security_policy(gh: GitHub, repo: str, branch: str) -> Result:
    found, evs, bad = _file_exists(gh, repo, ["SECURITY.md", ".github/SECURITY.md"])
    if bad:
        return Result("security_policy", ERROR, f"Could not verify: GitHub API returned HTTP {bad}.", evs)
    if found:
        return Result("security_policy", PASS, f"Vulnerability reporting policy found in {found}.", evs)
    return Result("security_policy", FAIL, "No SECURITY.md describing how to report vulnerabilities.", evs)


MANIFEST = re.compile(r"^(requirements.*\.txt|pyproject\.toml|package\.json|Cargo\.toml|Pipfile|go\.mod)$")
LOCKFILES = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock", "poetry.lock", "Pipfile.lock", "uv.lock"}


def _tree(gh: GitHub, repo: str, branch: str):
    r = gh.get(f"/repos/{repo}/git/trees/{branch}?recursive=1")
    if r.status != 200:
        return None, r
    return [t["path"] for t in r.json.get("tree", []) if t.get("type") == "blob"], r


def lockfile_present(gh: GitHub, repo: str, branch: str) -> Result:
    paths, r = _tree(gh, repo, branch)
    if paths is None:
        return _unexpected("lockfile_present", r.status, r.evidence_id)
    locks = sorted(p for p in paths if p.split("/")[-1] in LOCKFILES)
    if locks:
        return Result("lockfile_present", PASS, f"Lockfile(s): {', '.join(locks)}.", [r.evidence_id])
    manifests = sorted(p for p in paths if MANIFEST.search(p.split("/")[-1]))
    if not manifests:
        return Result("lockfile_present", PASS, "No third-party dependency manifest; nothing to pin.", [r.evidence_id])
    return Result("lockfile_present", FAIL, f"{', '.join(manifests)} found but no lockfile; versions may change between builds.", [r.evidence_id])


SECRET_PATTERNS = [
    re.compile(p)
    for p in [
        r"(^|/)\.env(\.[\w-]+)?$",
        r"\.(pem|key|p12|pfx|jks|keystore)$",
        r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$",
        r"(^|/)credentials(\.json)?$",
        r"(^|/)\.npmrc$",
        r"(^|/)secrets?\.(json|ya?ml|toml)$",
    ]
]
ALLOWED = re.compile(r"(^|/)\.env\.(example|sample|template)$")


def no_secret_files(gh: GitHub, repo: str, branch: str) -> Result:
    paths, r = _tree(gh, repo, branch)
    if paths is None:
        return _unexpected("no_secret_files", r.status, r.evidence_id)
    hits = sorted(p for p in paths if any(rx.search(p) for rx in SECRET_PATTERNS) and not ALLOWED.search(p))
    if hits:
        return Result("no_secret_files", FAIL, f"Possible secret files committed: {', '.join(hits)}.", [r.evidence_id])
    return Result("no_secret_files", PASS, f"No credential or key files among {len(paths)} files.", [r.evidence_id])


CHECKS: dict[str, Check] = {
    c.name: c
    for c in [
        Check("branch_protected", "Default branch is protected", "Enable a branch protection rule (or ruleset) on the default branch: require a pull request and a passing status check before merging.", branch_protected),
        Check("ci_passing", "Latest CI run on the default branch passed recently", "Add a CI workflow that runs the tests on every push and pull request, and fix it until the latest run on the default branch is green.", ci_passing),
        Check("dependabot_enabled", "Dependency vulnerability monitoring is configured", "Add .github/dependabot.yml for each package ecosystem in the repo (e.g. pip, npm, cargo) with a weekly schedule.", dependabot_enabled),
        Check("security_policy", "Vulnerability reporting policy exists", "Add SECURITY.md stating supported versions and how to report a vulnerability privately.", security_policy),
        Check("lockfile_present", "Dependency versions are pinned", "Commit a lockfile (package-lock.json, Cargo.lock, poetry.lock or uv.lock) or pin exact versions with hashes.", lockfile_present),
        Check("no_secret_files", "No credential or key files in the repository", "Remove the file, rotate the exposed credential, purge it from history, and add the pattern to .gitignore.", no_secret_files),
    ]
}
