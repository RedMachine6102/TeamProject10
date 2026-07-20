# Signed releases

Release images are built by the repository workflow from a tagged commit,
scanned before release tags are added, and addressed by digest. The workflow:

1. installs test and runtime dependencies from exact lock files;
2. runs the complete test suite;
3. builds and pushes a temporary candidate image;
4. blocks on high/critical vulnerabilities or embedded secrets;
5. copies the scanned digest to the release tag;
6. signs the digest with a short-lived GitHub OIDC identity;
7. publishes build-provenance and SPDX 2.3 SBOM attestations;
8. verifies the resulting signature and attestations.

Consumers must verify the digest rather than trusting a mutable tag:

```text
cosign verify ghcr.io/OWNER/vaultmind-next@sha256:DIGEST \
  --certificate-identity "https://github.com/OWNER/TeamProject10/.github/workflows/vaultmind-release.yml@refs/tags/vaultmind-vVERSION" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

GitHub provenance can be checked with:

```text
gh attestation verify oci://ghcr.io/OWNER/vaultmind-next@sha256:DIGEST \
  --repo OWNER/TeamProject10
```

Only tags shaped like `vaultmind-v1.2.3` are production releases. Manual
workflow runs publish a clearly named test tag and must not be deployed as a
production version.
