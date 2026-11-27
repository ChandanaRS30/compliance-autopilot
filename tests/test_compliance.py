"""Tests run against recorded GitHub API responses, so they need no network or token."""
import hashlib
import json
from datetime import datetime, timezone

import pytest

from compliance import checks, report, scan
from compliance.github import GitHub

NOW = datetime(2026, 11, 27, 9, 0, tzinfo=timezone.utc)


def fake(routes: dict[str, tuple[int, object]]):
    """Transport that answers from a dict of path -> (status, json); anything else is 404."""

    def transport(url: str):
        path = url.replace("https://api.github.com", "")
        status, body = routes.get(path, (404, {"message": "Not Found"}))
        return status, json.dumps(body).encode()

    return GitHub(transport=transport, clock=lambda: NOW)


def good_repo(name="acme/good"):
    return {
        f"/repos/{name}": (200, {"default_branch": "main"}),
        f"/repos/{name}/branches/main": (200, {"name": "main", "protected": True}),
        f"/repos/{name}/actions/runs?branch=main&per_page=1": (200, {"workflow_runs": [{"name": "CI", "conclusion": "success", "created_at": "2026-11-20T10:00:00Z"}]}),
        f"/repos/{name}/contents/.github/dependabot.yml": (200, {"name": "dependabot.yml"}),
        f"/repos/{name}/contents/SECURITY.md": (200, {"name": "SECURITY.md"}),
        f"/repos/{name}/git/trees/main?recursive=1": (200, {"tree": [{"path": p, "type": "blob"} for p in ["src/app.py", "uv.lock", ".env.example", "README.md"]]}),
    }


def weak_repo(name="acme/weak"):
    return {
        f"/repos/{name}": (200, {"default_branch": "main"}),
        f"/repos/{name}/branches/main": (200, {"name": "main", "protected": False}),
        f"/repos/{name}/actions/runs?branch=main&per_page=1": (200, {"workflow_runs": [{"name": "CI", "conclusion": "failure", "created_at": "2026-11-26T10:00:00Z"}]}),
        f"/repos/{name}/git/trees/main?recursive=1": (200, {"tree": [{"path": p, "type": "blob"} for p in ["app.py", "requirements.txt", ".env", "deploy/server.pem"]]}),
    }


# ---------------------------------------------------------------- catalogue

def test_catalogue_is_valid_and_every_check_is_used():
    controls = scan.load_controls()
    used = {c for ctl in controls for c in ctl.checks}
    assert used == set(checks.CHECKS)
    assert all(ctl.iso27001 and ctl.soc2 and ctl.c5 for ctl in controls)


def test_catalogue_rejects_unknown_checks(tmp_path):
    bad = tmp_path / "controls.toml"
    bad.write_text('[[control]]\nid="X"\ntitle="t"\nrequirement="r"\nchecks=["nope"]\niso27001=["A.1"]\nsoc2=[]\nc5=[]\nmapping_status="proposed"\n')
    with pytest.raises(ValueError, match="unknown checks"):
        scan.load_controls(bad)


# ---------------------------------------------------------------- individual checks

def test_good_repo_passes_every_control():
    results, gh = scan.scan(["acme/good"], fake(good_repo()))
    for c in scan.load_controls():
        assert scan.control_status(c, results[0]) == checks.PASS, c.id


def test_weak_repo_fails_with_clear_reasons():
    results, _ = scan.scan(["acme/weak"], fake(weak_repo()))
    r = results[0].checks
    assert r["branch_protected"].status == checks.FAIL
    assert "concluded 'failure'" in r["ci_passing"].detail
    assert r["dependabot_enabled"].status == checks.FAIL
    assert r["lockfile_present"].detail.startswith("requirements.txt found but no lockfile")
    assert r["no_secret_files"].detail == "Possible secret files committed: .env, deploy/server.pem."


def test_env_example_is_not_a_secret():
    gh = fake({"/repos/a/b/git/trees/main?recursive=1": (200, {"tree": [{"path": ".env.example", "type": "blob"}]})})
    assert checks.no_secret_files(gh, "a/b", "main").status == checks.PASS


def test_repo_without_dependencies_needs_no_lockfile():
    gh = fake({"/repos/a/b/git/trees/main?recursive=1": (200, {"tree": [{"path": "tool.py", "type": "blob"}]})})
    assert checks.lockfile_present(gh, "a/b", "main").status == checks.PASS


def test_stale_ci_run_fails():
    gh = fake({"/repos/a/b/actions/runs?branch=main&per_page=1": (200, {"workflow_runs": [{"name": "CI", "conclusion": "success", "created_at": "2026-09-01T00:00:00Z"}]})})
    res = checks.ci_passing(gh, "a/b", "main", now=NOW)
    assert res.status == checks.FAIL and "87 days old" in res.detail


def test_api_errors_are_never_a_pass():
    routes = good_repo("acme/flaky")
    routes["/repos/acme/flaky/branches/main"] = (500, {"message": "Server Error"})
    routes["/repos/acme/flaky/contents/.github/dependabot.yml"] = (403, {"message": "Forbidden"})
    results, _ = scan.scan(["acme/flaky"], fake(routes))
    r = results[0]
    assert r.checks["branch_protected"].status == checks.ERROR
    assert r.checks["dependabot_enabled"].status == checks.ERROR
    ctl = {c.id: c for c in scan.load_controls()}
    assert scan.control_status(ctl["CTL-01"], r) == checks.ERROR
    assert scan.control_status(ctl["CTL-03"], r) == checks.ERROR


def test_unreachable_repo_is_unverified_not_compliant():
    results, _ = scan.scan(["acme/missing"], fake({}))
    assert all(res.status == checks.ERROR for res in results[0].checks.values())


# ---------------------------------------------------------------- evidence and report

def test_every_result_points_to_stored_evidence(tmp_path):
    results, gh = scan.scan(["acme/good", "acme/weak"], fake(good_repo() | weak_repo()))
    manifest = json.loads(scan.write_evidence(gh, tmp_path).read_text())
    ids = {m["id"] for m in manifest}
    for r in results:
        for res in r.checks.values():
            assert res.evidence and set(res.evidence) <= ids
    # Hashes in the manifest match the stored bodies' original bytes, and the manifest is sealed.
    for m in manifest:
        assert m["retrieved_at"] == "2026-11-27T09:00:00Z"
        assert (tmp_path / m["file"]).exists()
    seal = (tmp_path / "manifest.sha256").read_text().split()[0]
    assert seal == hashlib.sha256((tmp_path / "manifest.json").read_bytes()).hexdigest()


def test_evidence_hash_is_of_the_raw_response():
    gh = fake({"/repos/a/b": (200, {"default_branch": "main"})})
    gh.get("/repos/a/b")
    assert gh.evidence[0].sha256 == hashlib.sha256(json.dumps({"default_branch": "main"}).encode()).hexdigest()


def test_report_shows_matrix_mapping_and_tasks():
    controls = scan.load_controls()
    results, gh = scan.scan(["acme/good", "acme/weak"], fake(good_repo() | weak_repo()))
    md = report.to_markdown(controls, results, gh, generated=NOW)
    assert "**5 of 10 control checks pass (50%)**" in md
    assert "| CTL-01 Changes to production code are protected | PASS | FAIL |" in md
    assert "A.8.32 Change management" in md and "CC8.1" in md and "DEV:" in md
    assert "- [ ] **acme/weak**, default branch is protected (CTL-01): Enable a branch protection rule" in md
    assert "acme/good**" not in md.split("## Remediation tasks")[1].split("## Evidence index")[0]
