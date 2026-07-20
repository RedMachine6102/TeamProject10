"""Fail a release when security scan reports contain blocking findings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as report_file:
        return json.load(report_file)


def pip_audit_findings(report: object) -> list[dict]:
    if not isinstance(report, dict) or not isinstance(report.get("dependencies"), list):
        raise ValueError("pip-audit report has an unexpected format")
    dependencies = report["dependencies"]
    return [
        vulnerability
        for dependency in dependencies
        if isinstance(dependency, dict)
        for vulnerability in dependency.get("vulns", [])
    ]


def trivy_findings(report: object) -> tuple[list[dict], list[dict]]:
    if not isinstance(report, dict) or not isinstance(report.get("Results"), list):
        raise ValueError("Trivy report has an unexpected format")
    vulnerabilities: list[dict] = []
    secrets: list[dict] = []
    for result in report["Results"]:
        if not isinstance(result, dict):
            raise ValueError("Trivy result has an unexpected format")
        vulnerabilities.extend(result.get("Vulnerabilities") or [])
        secrets.extend(result.get("Secrets") or [])
    return vulnerabilities, secrets


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pip-audit", required=True, type=Path)
    parser.add_argument("--trivy", required=True, type=Path)
    args = parser.parse_args()

    audit = pip_audit_findings(load_json(args.pip_audit))
    vulnerabilities, secrets = trivy_findings(load_json(args.trivy))
    print(f"pip-audit vulnerabilities: {len(audit)}")
    print(f"Trivy high/critical vulnerabilities: {len(vulnerabilities)}")
    print(f"Trivy secrets: {len(secrets)}")
    return 1 if audit or vulnerabilities or secrets else 0


if __name__ == "__main__":
    raise SystemExit(main())
