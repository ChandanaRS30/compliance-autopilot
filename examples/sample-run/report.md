# Audit readiness report (sample run on recorded test data)

Generated 2026-11-27 09:00 UTC for 2 repositories and 5 controls.

**5 of 10 control checks pass (50%)**, 5 fail, 0 could not be verified. A control passes only if every technical check behind it passes; unverified never counts as compliant.

## Control status

| Control | acme/good | acme/weak |
|---|---|---|
| CTL-01 Changes to production code are protected | PASS | FAIL |
| CTL-02 Changes are tested before release | PASS | FAIL |
| CTL-03 Vulnerable dependencies are detected | PASS | FAIL |
| CTL-04 Dependencies are pinned and reproducible | PASS | FAIL |
| CTL-05 Secrets are not stored in source code | PASS | FAIL |

## Controls and framework mapping (for control owners and auditors)

### CTL-01 Changes to production code are protected

**Requirement:** Changes to the default branch cannot be made directly; they pass through a controlled change process.

- ISO/IEC 27001:2022 Annex A: A.8.32 Change management; A.8.4 Access to source code
- SOC 2 (TSC): CC8.1
- BSI C5:2020 (domain): DEV: Procurement, development and modification of information systems
- Mapping status: proposed (to be confirmed by the control owner)

| Repository | Check | Result | Detail | Evidence |
|---|---|---|---|---|
| acme/good | Default branch is protected | PASS | Branch 'main' is protected. | E-002 |
| acme/weak | Default branch is protected | FAIL | Branch 'main' is not protected; direct pushes are possible. | E-009 |

### CTL-02 Changes are tested before release

**Requirement:** Automated tests run on changes, and the most recent run on the default branch passed within the review period.

- ISO/IEC 27001:2022 Annex A: A.8.29 Security testing in development and acceptance; A.8.25 Secure development life cycle
- SOC 2 (TSC): CC8.1
- BSI C5:2020 (domain): DEV: Procurement, development and modification of information systems
- Mapping status: proposed (to be confirmed by the control owner)

| Repository | Check | Result | Detail | Evidence |
|---|---|---|---|---|
| acme/good | Latest CI run on the default branch passed recently | PASS | Latest CI run 'CI' passed 6 days ago. | E-003 |
| acme/weak | Latest CI run on the default branch passed recently | FAIL | Latest CI run 'CI' concluded 'failure'. | E-010 |

### CTL-03 Vulnerable dependencies are detected

**Requirement:** Third-party dependencies are monitored for known vulnerabilities and a process for reporting vulnerabilities exists.

- ISO/IEC 27001:2022 Annex A: A.8.8 Management of technical vulnerabilities
- SOC 2 (TSC): CC7.1
- BSI C5:2020 (domain): OPS: Operations
- Mapping status: proposed (to be confirmed by the control owner)

| Repository | Check | Result | Detail | Evidence |
|---|---|---|---|---|
| acme/good | Dependency vulnerability monitoring is configured | PASS | Dependency monitoring configured in .github/dependabot.yml. | E-004 |
| acme/good | Vulnerability reporting policy exists | PASS | Vulnerability reporting policy found in SECURITY.md. | E-007 |
| acme/weak | Dependency vulnerability monitoring is configured | FAIL | No Dependabot configuration found. | E-011, E-012 |
| acme/weak | Vulnerability reporting policy exists | FAIL | No SECURITY.md describing how to report vulnerabilities. | E-015, E-016 |

### CTL-04 Dependencies are pinned and reproducible

**Requirement:** The exact versions of third-party components are recorded so that builds are reproducible and changes are traceable.

- ISO/IEC 27001:2022 Annex A: A.8.9 Configuration management; A.5.21 Managing information security in the ICT supply chain
- SOC 2 (TSC): CC8.1
- BSI C5:2020 (domain): DEV: Procurement, development and modification of information systems
- Mapping status: proposed (to be confirmed by the control owner)

| Repository | Check | Result | Detail | Evidence |
|---|---|---|---|---|
| acme/good | Dependency versions are pinned | PASS | Lockfile(s): uv.lock. | E-005 |
| acme/weak | Dependency versions are pinned | FAIL | requirements.txt found but no lockfile; versions may change between builds. | E-013 |

### CTL-05 Secrets are not stored in source code

**Requirement:** Authentication information such as keys, certificates and credential files is not stored in the code repository.

- ISO/IEC 27001:2022 Annex A: A.5.17 Authentication information; A.8.12 Data leakage prevention
- SOC 2 (TSC): CC6.1
- BSI C5:2020 (domain): IDM: Identity and access management
- Mapping status: proposed (to be confirmed by the control owner)

| Repository | Check | Result | Detail | Evidence |
|---|---|---|---|---|
| acme/good | No credential or key files in the repository | PASS | No credential or key files among 4 files. | E-006 |
| acme/weak | No credential or key files in the repository | FAIL | Possible secret files committed: .env, deploy/server.pem. | E-014 |

## Remediation tasks (for engineering)

- [ ] **acme/weak**, default branch is protected (CTL-01): Enable a branch protection rule (or ruleset) on the default branch: require a pull request and a passing status check before merging.
- [ ] **acme/weak**, latest ci run on the default branch passed recently (CTL-02): Add a CI workflow that runs the tests on every push and pull request, and fix it until the latest run on the default branch is green.
- [ ] **acme/weak**, dependency vulnerability monitoring is configured (CTL-03): Add .github/dependabot.yml for each package ecosystem in the repo (e.g. pip, npm, cargo) with a weekly schedule.
- [ ] **acme/weak**, vulnerability reporting policy exists (CTL-03): Add SECURITY.md stating supported versions and how to report a vulnerability privately.
- [ ] **acme/weak**, dependency versions are pinned (CTL-04): Commit a lockfile (package-lock.json, Cargo.lock, poetry.lock or uv.lock) or pin exact versions with hashes.
- [ ] **acme/weak**, no credential or key files in the repository (CTL-05): Remove the file, rotate the exposed credential, purge it from history, and add the pattern to .gitignore.

## Evidence index

Raw responses are stored as `<id>.json`; `manifest.json` lists their SHA-256 hashes and `manifest.sha256` seals the manifest.

| Evidence | Retrieved (UTC) | HTTP | Source | SHA-256 |
|---|---|---|---|---|
| E-001 | 2026-11-27T09:00:00Z | 200 | `/repos/acme/good` | `c74b61e17e810a7d…` |
| E-002 | 2026-11-27T09:00:00Z | 200 | `/repos/acme/good/branches/main` | `e8b59aaad5e87a27…` |
| E-003 | 2026-11-27T09:00:00Z | 200 | `/repos/acme/good/actions/runs?branch=main&per_page=1` | `02ae94a9ba87835e…` |
| E-004 | 2026-11-27T09:00:00Z | 200 | `/repos/acme/good/contents/.github/dependabot.yml` | `4976910ff3e72d4f…` |
| E-005 | 2026-11-27T09:00:00Z | 200 | `/repos/acme/good/git/trees/main?recursive=1` | `bedd46026a43d905…` |
| E-006 | 2026-11-27T09:00:00Z | 200 | `/repos/acme/good/git/trees/main?recursive=1` | `bedd46026a43d905…` |
| E-007 | 2026-11-27T09:00:00Z | 200 | `/repos/acme/good/contents/SECURITY.md` | `cd4563d28b21c9fa…` |
| E-008 | 2026-11-27T09:00:00Z | 200 | `/repos/acme/weak` | `c74b61e17e810a7d…` |
| E-009 | 2026-11-27T09:00:00Z | 200 | `/repos/acme/weak/branches/main` | `50cdc669ad0faddc…` |
| E-010 | 2026-11-27T09:00:00Z | 200 | `/repos/acme/weak/actions/runs?branch=main&per_page=1` | `73aeef71533e89b3…` |
| E-011 | 2026-11-27T09:00:00Z | 404 | `/repos/acme/weak/contents/.github/dependabot.yml` | `b82014934f66beeb…` |
| E-012 | 2026-11-27T09:00:00Z | 404 | `/repos/acme/weak/contents/.github/dependabot.yaml` | `b82014934f66beeb…` |
| E-013 | 2026-11-27T09:00:00Z | 200 | `/repos/acme/weak/git/trees/main?recursive=1` | `61be401f1393cf89…` |
| E-014 | 2026-11-27T09:00:00Z | 200 | `/repos/acme/weak/git/trees/main?recursive=1` | `61be401f1393cf89…` |
| E-015 | 2026-11-27T09:00:00Z | 404 | `/repos/acme/weak/contents/SECURITY.md` | `b82014934f66beeb…` |
| E-016 | 2026-11-27T09:00:00Z | 404 | `/repos/acme/weak/contents/.github/SECURITY.md` | `b82014934f66beeb…` |
