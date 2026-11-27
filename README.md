# compliance-autopilot

Automated audit-evidence collection for repository security controls. A small control catalogue maps audit requirements (ISO/IEC 27001:2022, SOC 2, BSI C5) to technical checks. A Python scanner runs those checks through the GitHub REST API and writes an **audit-readiness report**, plus a **tamper-evident evidence package** an auditor can verify.

```bash
python -m compliance controls                                    # list the control catalogue
python -m compliance scan --repo owner/name --repo owner/other   # evidence/<timestamp>/report.md
```

No third-party dependencies: Python 3.11+ standard library only. A `GITHUB_TOKEN` is optional for public repositories.

## The problem it solves

Before an ISO 27001 or SOC 2 audit, compliance teams spend days collecting the same proof again and again: screenshots of branch protection settings, CI histories, dependency-scanning configs. Engineers get asked in audit language ("show evidence of A.8.32 change management") and answer in engineering language ("main is protected"). This tool automates the collection and does the translation in both directions.

| For | What they get |
|---|---|
| Auditors and control owners | Each control with its requirement, its framework references, a PASS/FAIL result per repository, and links to the evidence behind it |
| Engineers | A remediation checklist in plain engineering terms ("enable a branch protection rule requiring a pull request…") |
| Both | Every API response stored with its URL, UTC timestamp and SHA-256 hash, and a sealed manifest, so the evidence can be checked later |

## Controls

| Control | Automated checks | ISO/IEC 27001:2022 Annex A | SOC 2 | BSI C5:2020 (domain) |
|---|---|---|---|---|
| CTL-01 Changes to production code are protected | Default branch protected | A.8.32, A.8.4 | CC8.1 | DEV |
| CTL-02 Changes are tested before release | Latest CI run on default branch passed within 30 days | A.8.29, A.8.25 | CC8.1 | DEV |
| CTL-03 Vulnerable dependencies are detected | Dependabot configured; SECURITY.md exists | A.8.8 | CC7.1 | OPS |
| CTL-04 Dependencies are pinned and reproducible | Lockfile present when there are dependencies | A.8.9, A.5.21 | CC8.1 | DEV |
| CTL-05 Secrets are not stored in source code | No key, certificate or credential files in the tree | A.5.17, A.8.12 | CC6.1 | IDM |

The mapping is marked **proposed**: in a real information security management system (ISMS), the control owner confirms it. C5 is mapped at domain level; confirm exact criterion IDs against the BSI catalogue. Controls live in [`controls.toml`](controls.toml), so a compliance colleague can edit requirements and mappings without touching code.

## Design decisions

- **Unverified is never compliant.** If an API call fails (rate limit, permissions, outage), the check is `NOT VERIFIED`, not `PASS`. A control passes only if every check behind it passes.
- **Evidence first.** Each check result references the evidence IDs (`E-001`…) it was decided on. Raw responses are stored unchanged, and their hashes are taken from the original bytes.
- **Two languages, one source.** Each control carries an auditor-facing `requirement`, and each check carries an engineer-facing `engineering_task`. The report shows each audience its own view.
- **Continuous, not once a year.** [`.github/workflows/evidence.yml`](.github/workflows/evidence.yml) runs the scan every Monday against my own repositories, puts the report in the run summary, and keeps the evidence package as a 90-day artifact.

## Example

[`examples/sample-run/report.md`](examples/sample-run/report.md) is a run on recorded test data: one well-configured repository and one with typical gaps (unprotected branch, failing CI, a committed `.env` file and a private key). Real runs on my repositories appear under the repository's **Actions → Collect audit evidence**.

## Tests

```bash
pip install pytest && python -m pytest -q    # 12 tests, no network needed
```

Tests run against recorded API responses. They cover every check passing and failing, API errors that must never count as a pass, stale CI runs, `.env.example` not being flagged as a secret, evidence hashes and the sealed manifest, catalogue validation, and the report contents.

## Next steps

- More evidence sources: cloud configuration (for example, encryption at rest and MFA enforcement) and identity-provider exports
- ISO/IEC 42001 (AI management system) controls for AI features, such as human oversight of model output
- Export to a GRC tool instead of Markdown
