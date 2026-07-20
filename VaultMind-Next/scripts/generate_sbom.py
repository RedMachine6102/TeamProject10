from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from importlib.metadata import distributions
from pathlib import Path


def spdx_id(name: str) -> str:
    return "SPDXRef-Package-" + re.sub(r"[^A-Za-z0-9.-]", "-", name)


def generate(output: Path) -> None:
    packages = []
    for distribution in sorted(
        distributions(), key=lambda value: value.metadata["Name"].lower()
    ):
        name = distribution.metadata["Name"]
        packages.append({
            "SPDXID": spdx_id(name), "name": name,
            "versionInfo": distribution.version,
            "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        })
    document = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT", "name": "vaultmind-next-runtime",
        "documentNamespace": "https://vaultmind.internal/sbom/runtime",
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat(),
            "creators": ["Tool: VaultMind SBOM generator"],
        },
        "packages": packages,
    }
    output.write_text(json.dumps(document, indent=2), encoding="utf-8")


if __name__ == "__main__":
    generate(Path(sys.argv[1] if len(sys.argv) > 1 else "sbom.spdx.json"))
