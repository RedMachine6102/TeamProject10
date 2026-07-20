# Trusted rotation agent

The Windows agent is the only component allowed to decrypt a vault item and
submit a password rotation. AI planners never receive a vault key, credential,
OAuth token, provider session, or device signing key.

## Security boundaries

- Every agent request is signed with its registered Ed25519 device key.
- The device private key is encrypted by Windows DPAPI for the current user.
- Routine polling, claiming, package retrieval, failure reporting, and commit
  requests do not use the deployment bearer token.
- The API releases an encrypted item and its passphrase-wrapped vault data key
  only after the agent owns an unexpired job lease.
- The agent unwraps the data key locally, changes the provider password, and
  verifies the new login before it re-encrypts the vault record.
- Before contacting the provider, the agent writes a DPAPI-protected prepared
  recovery record containing the pending encrypted vault update and the
  credentials needed to reconcile an interruption. It marks the record changed
  only after verifying the new provider login. The server accepts an identical
  signed commit more than once, and the agent removes the record only after a
  confirmed response.
- The API commits the new encrypted record, successful job state, audit events,
  and next rotation date in one SQLite transaction.
- A foreground agent retries temporary API outages with bounded backoff. If it
  crashes after claiming but before preparing a provider change, only that same
  signed agent can reclaim its expired lease. A different device cannot repeat
  the job.
- A global `PAUSED` file and a provider allowlist stop execution before any job
  is claimed.
- A separate hardened scheduler automatically turns due 30/60/90-day policies
  into deduplicated jobs; the dashboard scan button is not required.

DPAPI protects the key at rest but cannot defeat malware already executing as
the same Windows user while the agent is unlocked. A commercial build still
needs a signed executable, TPM-backed non-exportable device keys, integrity
checks, and automatic lock/revocation on endpoint compromise.

## Enrollment

Install the project into the Windows virtual environment, then enroll once:

1. Sign in to VaultMind with the owner passkey.
2. Open **Security** and choose **Enroll agent**.
3. Copy the displayed ten-minute, one-time code into the agent's hidden prompt.

```powershell
vaultmind-agent enroll `
  --server http://localhost:8080 `
  --name "VaultMind Windows Agent" `
  --adapter demo=http://localhost:8090
```

The enrollment code and vault passphrase are read through hidden prompts and are
not accepted as command-line arguments. The deployment bootstrap token never
reaches the agent. Configuration and the DPAPI-wrapped device key are stored
under `%LOCALAPPDATA%\VaultMind\Agent`.

Provider adapters must listen on loopback. The agent rejects remote adapter
URLs so plaintext credentials cannot be routed through a third-party bridge.
Each adapter owns its password-generation rule and must verify the new login
before the encrypted vault update can be committed.

When adding a credential in the web vault, enter the exact provider ID used by
the agent's `--adapter` entry, choose **Trusted agent**, select an active
enrolled device, and choose how long its item-scoped authorization remains
valid. Automatic policies without a current active-device grant remain manual
and cannot be claimed as unattended work.

The Rotations view can pause or resume each policy and revoke each item grant.
Pausing a policy or revoking its grant immediately cancels waiting work. A job
already changing a provider is allowed only to finish or reconcile, avoiding a
half-changed credential. Grant expiry and active-device status are checked
again when work is listed and claimed, so an earlier approval cannot outlive its
authorization.

Manual policies appear on the overview as proposed jobs. The owner can approve,
retry, or cancel waiting jobs from that view; these controls require the same
authenticated owner session as other vault administration.

Run at most one job:

```powershell
vaultmind-agent run-once
```

Or keep the agent visible in the foreground so approved due jobs run
automatically:

```powershell
vaultmind-agent run --poll-seconds 60
```

The foreground process asks for the vault passphrase once and retains it in
process memory until stopped. It does not write the passphrase to disk. Stop the
process when the device is unattended; a signed Windows service with a
TPM-backed vault key remains a production requirement.

Use `vaultmind-agent pause`, `resume`, and `status` for the global kill switch.
The status command reports `recovery pending` when an interrupted provider
change must be committed before another job can start.

## Email verification challenges

An allowlisted provider adapter can request a short-lived email code before
committing a password change. When local email access is configured, the agent
retrieves the code directly from Google or Microsoft and submits it directly to
the adapter. The backend never receives the OAuth token, message body, or code.

Connect the local mailbox with the system-browser
`vaultmind-agent email-connect` flow, inspect the non-secret settings with
`email-status`, and remove them with `email-disconnect`. See
[EMAIL_CHALLENGES.md](EMAIL_CHALLENGES.md) for scope, sender allowlists, and
setup details.

## Isolated demo provider

The `demo` Compose profile proves the change-and-verify protocol without
touching a real account. It is not a production service.

```powershell
$env:VAULTMIND_DEMO_USERNAME="owner@example.com"
$env:VAULTMIND_DEMO_PASSWORD="a-long-demo-password"
docker compose --profile demo up demo-provider
```

The demo service stores only a scrypt password hash in memory, binds to
localhost, and is excluded from the normal deployment profile.
