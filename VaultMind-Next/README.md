# VaultMind Next

VaultMind Next is the production-track successor to the class prototype. It is
being built as a zero-knowledge vault and controlled password-rotation platform.

## What works now

- Opaque client-encrypted vault record API
- Authenticated API surface with constant-time token comparison
- Persistent 30, 60, and 90-day rotation policies
- Item-scoped automatic grants bound to a specific trusted agent
- Deduplicated rotation queue with enforced transitions and short-lived leases
- Ed25519-signed agent actions with timestamp and replay protection
- Tamper-evident chained audit events and verification API
- Trusted-agent provider interface that keeps credentials away from AI
- AES-256-GCM protection for server-held integration secrets
- Google and Microsoft OAuth authorization-code flows with PKCE
- One-time OAuth state, encrypted token storage, connection listing, and revocation
- Isolated Google/Microsoft metadata monitor with sanitized event classification
- Optional stateless AI planner with strict, non-authoritative recommendations
- Owner passkey registration and passwordless sign-in
- Opaque 30-minute HTTP-only sessions with strict origin enforcement
- Passkey-authorized sign-out-everywhere and audited device revocation
- In-process authentication throttling and one-use WebAuthn challenges
- Tokenless, Ed25519-signed trusted-agent job APIs
- Atomic verified-rotation commit for vault ciphertext, job state, and schedule
- Windows DPAPI protection for the agent device key
- Global and provider-level automation kill switches
- Isolated demo provider for safe end-to-end rotation testing
- Dedicated unattended scheduler for automatic 30/60/90-day job creation
- Passkey-authorized, hashed, single-use trusted-agent enrollment codes
- Automatic shutdown of deployment-token API access after owner setup
- Responsive security dashboard
- Browser-side AES-GCM encryption with a random vault data key
- Zero-knowledge passphrase changes that only rewrap the vault data key
- Five-minute inactivity lock and immediate lock when the browser is backgrounded
- Authenticated encrypted backups with automatic retention and restore drills
- Database readiness, scheduler heartbeat, and backup freshness health checks
- Exact Linux runtime lock and embedded SPDX 2.3 package inventory
- Live Vault, Rotations, Connections, and Security workspaces
- Device and automation-grant revocation APIs
- Hardened single-container development deployment
- Core and API integration tests

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
$env:VAULTMIND_API_KEY="development-token-change-before-deploying"
.\.venv\Scripts\python.exe -m uvicorn vaultmind_next.api:app --reload --port 8080
```

Open the origin configured by `VAULTMIND_PUBLIC_URL`. The deployed internal
environment uses `https://vaultmind.internal`. On first use, create the owner
passkey with the development bootstrap token. Later browser sessions use only the passkey; the
bootstrap token is not retained by the page and stops authorizing vault APIs as
soon as the owner exists.

To enable an email provider, set its client ID and client secret from
`.env.example`, set `VAULTMIND_PUBLIC_URL` to the application origin, and
register this callback with the provider:

```text
https://your-vault-host/api/v1/email/oauth/callback?provider=google
https://your-vault-host/api/v1/email/oauth/callback?provider=microsoft
```

Production callback URLs must use HTTPS. OAuth access and refresh tokens are
encrypted with `VAULTMIND_ROOT_KEY`; they are never returned by the API.

The production Compose stack terminates TLS in a pinned, non-root Caddy image.
Its internal CA is suitable only for explicitly trusted private devices; a
public deployment must use a publicly trusted certificate and owned hostname.

Run tests:

```powershell
.\.venv\Scripts\python.exe -m pytest
```

## Security architecture

Read [Architecture](docs/ARCHITECTURE.md) and
[Threat model](docs/THREAT_MODEL.md) before adding integrations. The
[product-readiness checklist](docs/PRODUCT_READINESS.md) separates working
foundations from private-beta and commercial launch gates. The central rule is
that planners and models have no credential authority. Password changes run
through deterministic provider adapters on a trusted device or disposable,
isolated worker.

The [trusted-agent guide](docs/TRUSTED_AGENT.md) documents enrollment, kill
switches, the local execution boundary, and the safe demo workflow.
The [backup and restore guide](docs/BACKUP_RESTORE.md) documents independent key
handling, automated retention, verification, and incident-safe recovery.
The [email monitoring guide](docs/EMAIL_MONITORING.md) documents exact provider
metadata limits, token refresh, sanitization, and the untrusted-signal boundary.
The [AI planner guide](docs/AI_PLANNER.md) documents the exact data boundary and
why model output cannot authorize or execute credential operations.
The [supply-chain guide](docs/SUPPLY_CHAIN.md) documents reproducible dependency
updates and the embedded SPDX package inventory.

## Roadmap

1. Multi-user accounts, additional passkey enrollment, and recovery controls.
2. Signed Windows agent packaging and TPM-backed non-exportable device keys.
3. Argon2id key wrapping, vault-key rotation, encrypted sync, and recovery.
4. Provider adapter SDK with a fully tested demonstration integration.
5. Metadata-only security-message polling and connection health checks.
6. Append-only signed audit events and anomaly detection.
7. Multi-tenant PostgreSQL deployment, billing, admin, and support systems.
8. Independent security review, packaging, signed updates, and launch gates.

The [Proxmox blueprint](infra/proxmox/README.md) lists the external details
needed before infrastructure can be safely provisioned.
