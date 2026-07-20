import json
import re
import tomllib
from pathlib import Path

import pytest

from scripts.generate_sbom import generate
from scripts.verify_security_reports import pip_audit_findings, trivy_findings


ROOT = Path(__file__).resolve().parents[1]


def locked_versions() -> dict[str, str]:
    values = {}
    for line in (ROOT / "requirements.lock").read_text().splitlines():
        if line and not line.startswith("#"):
            name, version = line.split("==", 1)
            values[name.lower().replace("_", "-")] = version
    return values


def locked_test_versions() -> dict[str, str]:
    values = {}
    for line in (ROOT / "requirements-test.lock").read_text().splitlines():
        if line and not line.startswith("#"):
            name, version = line.split("==", 1)
            values[name.lower().replace("_", "-")] = version
    return values


def test_direct_runtime_dependencies_match_linux_lock():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    locked = locked_versions()
    for requirement in project["project"]["dependencies"]:
        match = re.fullmatch(r"([A-Za-z0-9_-]+)(?:\[[^]]+\])?==([A-Za-z0-9_.-]+)", requirement)
        assert match, f"runtime dependency is not exactly pinned: {requirement}"
        assert locked[match.group(1).lower().replace("_", "-")] == match.group(2)


def test_direct_test_dependencies_match_test_lock():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    locked = locked_test_versions()
    for requirement in project["project"]["optional-dependencies"]["dev"]:
        name, version = requirement.split("==", 1)
        assert locked[name.lower().replace("_", "-")] == version


def test_generated_spdx_inventory_contains_no_environment_secrets(tmp_path):
    output = tmp_path / "sbom.spdx.json"
    generate(output)
    document = json.loads(output.read_text())
    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["packages"]
    text = output.read_text()
    assert "OPENAI_API_KEY" not in text
    assert "VAULTMIND_ROOT_KEY" not in text
    assert all("versionInfo" in package for package in document["packages"])


def test_security_report_parser_accepts_clean_reports():
    audit = {"dependencies": [{"name": "safe", "vulns": []}]}
    trivy = {"Results": [{"Vulnerabilities": [], "Secrets": []}]}

    assert pip_audit_findings(audit) == []
    assert trivy_findings(trivy) == ([], [])


def test_security_report_parser_rejects_incomplete_reports():
    with pytest.raises(ValueError):
        pip_audit_findings({})
    with pytest.raises(ValueError):
        trivy_findings({})
