"""python -m compliance scan --repo owner/name [--repo ...] [--out evidence/]"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import report, scan
from .checks import PASS


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m compliance", description="Collect audit evidence for repository security controls.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="check repositories against the control catalogue")
    s.add_argument("--repo", action="append", required=True, help="owner/name; repeat for several repositories")
    s.add_argument("--out", type=Path, default=None, help="evidence folder (default: evidence/<UTC timestamp>)")
    s.add_argument("--fail-on-gap", action="store_true", help="exit 1 if any control does not pass")
    sub.add_parser("controls", help="list the control catalogue")
    args = ap.parse_args(argv)

    controls = scan.load_controls()
    if args.cmd == "controls":
        for c in controls:
            print(f"{c.id} {c.title}\n  ISO 27001: {'; '.join(c.iso27001)}\n  SOC 2: {'; '.join(c.soc2)}\n  C5: {'; '.join(c.c5)}")
        return 0

    out = args.out or Path("evidence") / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results, gh = scan.scan(args.repo)
    scan.write_evidence(gh, out)
    (out / "report.md").write_text(report.to_markdown(controls, results, gh))
    gaps = [(r.repo, c.id) for r in results for c in controls if scan.control_status(c, r) != PASS]
    print(f"wrote {out}/report.md and {len(gh.evidence)} evidence files; {len(gaps)} control gaps")
    return 1 if (args.fail_on_gap and gaps) else 0


if __name__ == "__main__":
    sys.exit(main())
