# Software supply chain

The production image starts from an immutable Python Alpine base-image digest and
installs every Linux runtime package from `requirements.lock` with an exact
version. The project build tool is pinned and build isolation is disabled, so a
rebuild cannot silently resolve a newer setuptools release.

CI installs test-only packages from `requirements-test.lock` without dependency
resolution. Runtime and test locks remain separate so test tools never enter the
production image.

Direct dependencies in `pyproject.toml` must match the lock. Tests enforce that
rule. Updating dependencies is an intentional workflow:

1. build and test the candidate versions in an isolated branch;
2. update direct pins and the complete Linux lock together;
3. run the full unit/integration suite and controlled rotation drill;
4. review upstream security notices and licenses;
5. build the container and compare its installed inventory with the lock;
6. deploy through the existing hashed release process.

Every image contains `/app/sbom.spdx.json`, an SPDX 2.3 package inventory
generated after installation. It contains package names and versions only—no
environment values, API keys, tokens, vault data, or build-host paths.

Build-only packaging tools are removed after the application is installed and
before its runtime inventory is created. The pinned Alpine base replaced Debian
after container scanning found
unfixed high/critical Debian package advisories while the equivalent Alpine base
reported none.

Exact versions improve reproducibility but do not prove packages are safe.
The pinned release scanners and blocking gate are documented in
`VULNERABILITY_SCANNING.md`. Commercial release still requires artifact signing,
provenance attestations, license policy, and a reviewed update cadence.
