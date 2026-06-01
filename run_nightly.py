#!/usr/bin/env python3
"""
QA Harness — Nightly QA, cleanup, and security review service.

Runs all checks across all registered projects, generates a JSON report,
saves summary to OpenBrain, and alerts via iMessage file if critical issues found.

Usage:
    python3 run_nightly.py                    # Run all checks on all projects
    python3 run_nightly.py --project genome   # Run on one project only
    python3 run_nightly.py --check security_scan  # Run one check only
    python3 run_nightly.py --dry-run          # Print what would run, no output
    python3 run_nightly.py --verbose          # Print findings to stdout
"""

import argparse
import json
import os
import signal
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Hard limit per check: 5 minutes. Prevents any single slow check from blocking the run.
_CHECK_TIMEOUT_SEC = 300


class _CheckTimeout(Exception):
    pass


def _timeout_handler(signum, frame):
    raise _CheckTimeout()

# Add parent dir to path so checks/ is importable
sys.path.insert(0, str(Path(__file__).parent))

from checks import ALL_CHECKS
from checks.duplicate_code import finalize as finalize_duplicates
from checks.architecture_review import finalize as finalize_architecture


def load_config() -> Dict[str, Any]:
    """Load config.json from same directory as this script."""
    config_path = Path(__file__).parent / "config.json"
    with open(config_path) as f:
        return json.loads(f.read())


def run_all_checks(
    config: Dict[str, Any],
    project_filter: Optional[str] = None,
    check_filter: Optional[str] = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Run all (or filtered) checks across all (or filtered) projects."""

    projects = config["projects"]
    if project_filter:
        projects = [p for p in projects if p["name"] == project_filter]
        if not projects:
            print(f"ERROR: Project '{project_filter}' not found in config.json")
            sys.exit(1)

    checks_to_run = ALL_CHECKS
    if check_filter:
        checks_to_run = [(n, f) for n, f in ALL_CHECKS if n == check_filter]
        if not checks_to_run:
            print(f"ERROR: Check '{check_filter}' not found. Available: "
                  + ", ".join(n for n, _ in ALL_CHECKS))
            sys.exit(1)

    all_findings: List[Dict[str, Any]] = []
    project_summaries: Dict[str, Dict[str, Any]] = {}
    global_config = dict(config)  # Mutable copy for cross-project state

    start_time = time.time()

    for project in projects:
        project_name = project["name"]
        project_path = str(Path(project["path"]).expanduser())

        if not os.path.isdir(project_path):
            if verbose:
                print(f"  SKIP {project_name}: directory not found at {project_path}")
            continue

        if verbose:
            print(f"\n{'='*60}")
            print(f"  Scanning: {project_name}")
            print(f"  Path: {project_path}")
            print(f"{'='*60}")

        project_findings = []
        project_timings = {}

        for check_name, check_fn in checks_to_run:
            check_start = time.time()
            try:
                signal.signal(signal.SIGALRM, _timeout_handler)
                signal.alarm(_CHECK_TIMEOUT_SEC)
                findings = check_fn(project, global_config)
                signal.alarm(0)
                project_findings.extend(findings)
                elapsed = time.time() - check_start
                project_timings[check_name] = round(elapsed, 2)

                if verbose and findings:
                    print(f"\n  [{check_name}] {len(findings)} findings ({elapsed:.1f}s)")
                    for f in findings[:5]:
                        sev = f["severity"].upper()
                        print(f"    {sev}: {f['file']}:{f.get('line', '?')} -- {f['message'][:100]}")
                    if len(findings) > 5:
                        print(f"    ... and {len(findings) - 5} more")
                elif verbose:
                    print(f"  [{check_name}] clean ({elapsed:.1f}s)")

            except _CheckTimeout:
                signal.alarm(0)
                elapsed = time.time() - check_start
                project_timings[check_name] = round(elapsed, 2)
                project_findings.append({
                    "severity": "warning", "check": check_name,
                    "file": project_name, "line": None,
                    "message": f"Check timed out after {_CHECK_TIMEOUT_SEC}s — skipped",
                    "snippet": None,
                })
                if verbose:
                    print(f"  [{check_name}] TIMEOUT after {_CHECK_TIMEOUT_SEC}s")
            except Exception as e:
                signal.alarm(0)
                elapsed = time.time() - check_start
                project_timings[check_name] = round(elapsed, 2)
                error_finding = {
                    "severity": "warning",
                    "check": check_name,
                    "file": project_name,
                    "line": None,
                    "message": f"Check failed with error: {type(e).__name__}: {e}",
                    "snippet": None,
                }
                project_findings.append(error_finding)
                if verbose:
                    print(f"  [{check_name}] ERROR: {e}")

        all_findings.extend(project_findings)

        # Summarize
        severity_counts = {"critical": 0, "warning": 0, "info": 0}
        for f in project_findings:
            severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

        project_summaries[project_name] = {
            "total_findings": len(project_findings),
            "severities": severity_counts,
            "timings": project_timings,
        }

    # Run finalize passes for cross-project checks
    if not check_filter or check_filter == "duplicate_code":
        try:
            cross_findings = finalize_duplicates(global_config)
            all_findings.extend(cross_findings)
            if verbose and cross_findings:
                print(f"\n  [duplicate_code:finalize] {len(cross_findings)} cross-project findings")
        except Exception as e:
            if verbose:
                print(f"  [duplicate_code:finalize] ERROR: {e}")

    if not check_filter or check_filter == "architecture_review":
        try:
            cross_findings = finalize_architecture(global_config)
            all_findings.extend(cross_findings)
            if verbose and cross_findings:
                print(f"\n  [architecture_review:finalize] {len(cross_findings)} cross-project findings")
        except Exception as e:
            if verbose:
                print(f"  [architecture_review:finalize] ERROR: {e}")

    total_time = round(time.time() - start_time, 2)

    # Build report
    severity_totals = {"critical": 0, "warning": 0, "info": 0}
    for f in all_findings:
        severity_totals[f["severity"]] = severity_totals.get(f["severity"], 0) + 1

    report = {
        "timestamp": datetime.now().isoformat(),
        "duration_seconds": total_time,
        "projects_scanned": len(project_summaries),
        "total_findings": len(all_findings),
        "severity_totals": severity_totals,
        "project_summaries": project_summaries,
        "findings": all_findings,
    }

    return report


def save_report(report: Dict[str, Any], config: Dict[str, Any]) -> str:
    """Save JSON report to disk."""
    report_dir = config.get("report_dir", "/tmp")
    date_str = datetime.now().strftime("%Y-%m-%d")
    report_path = os.path.join(report_dir, f"qa-report-{date_str}.json")

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    return report_path


def save_to_openbrain(report: Dict[str, Any], config: Dict[str, Any]) -> bool:
    """Save summary to OpenBrain."""
    url = config.get("openbrain_url", "http://localhost:3210")
    token = config.get("openbrain_token", "openbrain-dev-token")

    severity = report["severity_totals"]
    summary_lines = [
        f"QA Harness Nightly Report — {report['timestamp'][:10]}",
        f"Projects: {report['projects_scanned']} | "
        f"Findings: {report['total_findings']} "
        f"(critical={severity['critical']}, warning={severity['warning']}, info={severity['info']})",
        f"Duration: {report['duration_seconds']}s",
    ]

    # Add per-project highlights
    for proj_name, proj_summary in report.get("project_summaries", {}).items():
        sev = proj_summary["severities"]
        if sev.get("critical", 0) > 0 or sev.get("warning", 0) > 0:
            summary_lines.append(
                f"  {proj_name}: {sev.get('critical',0)} critical, "
                f"{sev.get('warning',0)} warning, {sev.get('info',0)} info"
            )

    # Top critical findings
    criticals = [f for f in report["findings"] if f["severity"] == "critical"]
    if criticals:
        summary_lines.append("Critical issues:")
        for c in criticals[:5]:
            summary_lines.append(f"  - [{c['check']}] {c['file']}: {c['message'][:120]}")

    content = "\n".join(summary_lines)
    payload = json.dumps({
        "content": content,
        "source": "qa-harness",
        "tags": ["qa", "nightly", "security", "code-quality"],
    }).encode()

    try:
        req = urllib.request.Request(
            f"{url}/api/add",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError) as e:
        print(f"  OpenBrain save failed: {e}", file=sys.stderr)
        return False


def write_alert(report: Dict[str, Any], config: Dict[str, Any]) -> Optional[str]:
    """
    Write iMessage alert file if critical issues found.
    A separate launchd/cron job can pick this up and send via osascript.
    """
    criticals = [f for f in report["findings"] if f["severity"] == "critical"]
    if not criticals:
        return None

    alert_path = config.get("alert_file", "/tmp/qa-alert.txt")

    lines = [
        f"QA ALERT: {len(criticals)} critical issues found ({report['timestamp'][:10]})",
        "",
    ]
    for c in criticals[:10]:
        lines.append(f"- [{c['check']}] {c['file']}: {c['message'][:100]}")

    if len(criticals) > 10:
        lines.append(f"... and {len(criticals) - 10} more")

    lines.append(f"\nFull report: /tmp/qa-report-{report['timestamp'][:10]}.json")

    with open(alert_path, "w") as f:
        f.write("\n".join(lines))

    return alert_path


def print_summary(report: Dict[str, Any]) -> None:
    """Print a human-readable summary to stdout."""
    sev = report["severity_totals"]
    print(f"\n{'='*60}")
    print(f"  QA Harness Report — {report['timestamp'][:10]}")
    print(f"{'='*60}")
    print(f"  Projects scanned: {report['projects_scanned']}")
    print(f"  Total findings:   {report['total_findings']}")
    print(f"  Critical:         {sev['critical']}")
    print(f"  Warnings:         {sev['warning']}")
    print(f"  Info:             {sev['info']}")
    print(f"  Duration:         {report['duration_seconds']}s")
    print()

    # Per-project breakdown
    for proj_name, proj_summary in report.get("project_summaries", {}).items():
        s = proj_summary["severities"]
        total = proj_summary["total_findings"]
        if total == 0:
            status = "CLEAN"
        elif s.get("critical", 0) > 0:
            status = "CRITICAL"
        elif s.get("warning", 0) > 0:
            status = "WARNINGS"
        else:
            status = "INFO"
        print(f"  {status:10s} {proj_name}: {total} findings "
              f"(C={s.get('critical',0)} W={s.get('warning',0)} I={s.get('info',0)})")

    # Top critical findings
    criticals = [f for f in report["findings"] if f["severity"] == "critical"]
    if criticals:
        print(f"\n  CRITICAL ISSUES ({len(criticals)}):")
        for c in criticals[:10]:
            loc = f"{c['file']}:{c.get('line', '?')}"
            print(f"    [{c['check']}] {loc}")
            print(f"      {c['message'][:120]}")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="QA Harness — Nightly code quality & security review"
    )
    parser.add_argument(
        "--project", "-p",
        help="Run checks on a single project only",
    )
    parser.add_argument(
        "--check", "-c",
        help="Run a single check only (e.g., security_scan)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would run without executing",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed findings to stdout",
    )
    parser.add_argument(
        "--no-openbrain",
        action="store_true",
        help="Skip saving to OpenBrain",
    )
    parser.add_argument(
        "--no-alert",
        action="store_true",
        help="Skip writing alert file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON to stdout (for piping)",
    )

    args = parser.parse_args()
    config = load_config()

    if args.dry_run:
        projects = config["projects"]
        if args.project:
            projects = [p for p in projects if p["name"] == args.project]
        checks = ALL_CHECKS
        if args.check:
            checks = [(n, f) for n, f in ALL_CHECKS if n == args.check]

        print("DRY RUN — would execute:")
        for p in projects:
            print(f"  Project: {p['name']} ({p['path']})")
            for cn, _ in checks:
                print(f"    Check: {cn}")
        return

    # Run checks
    report = run_all_checks(
        config,
        project_filter=args.project,
        check_filter=args.check,
        verbose=args.verbose,
    )

    # Save report
    report_path = save_report(report, config)

    # Output
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_summary(report)
        print(f"  Report saved: {report_path}")

    # OpenBrain
    if not args.no_openbrain:
        if save_to_openbrain(report, config):
            if not args.json:
                print("  Summary saved to OpenBrain")
        else:
            if not args.json:
                print("  OpenBrain save failed (service may be down)")

    # Alert
    if not args.no_alert:
        alert_path = write_alert(report, config)
        if alert_path and not args.json:
            print(f"  ALERT written: {alert_path}")

    # Exit code: 1 if critical findings, 0 otherwise
    if report["severity_totals"]["critical"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
