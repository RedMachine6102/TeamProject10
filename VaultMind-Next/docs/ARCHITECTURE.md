# VaultMind Next architecture

## Trust boundaries

```text
User client / trusted agent
  - decrypts vault records
  - generates replacement passwords
  - performs provider-specific changes
  - re-encrypts the updated record
              |
              | opaque ciphertext + signed job results
              v
VaultMind API
  - stores encrypted records
  - schedules 30/60/90-day rotations
  - records approvals and audit events
  - never receives a vault decryption key
              |
              | provider job metadata only
              v
Planner service
  - classifies provider workflows
  - proposes actions and recovery steps
  - has no provider token or password authority
```

An AI model must never receive passwords, recovery codes, session cookies,
OAuth refresh tokens, or vault keys. It may create a typed plan. A deterministic
executor validates that plan against a versioned provider adapter and an exact
allowlist before any action is possible.

## Rotation lifecycle

1. The API marks a policy due after 30, 60, or 90 days.
2. A `proposed` job is created once; duplicate open jobs are rejected.
3. Manual mode requires a user approval. Automatic mode requires a previously
   granted per-provider scope on a trusted agent.
4. The trusted agent claims the job and decrypts the credential locally.
5. A provider adapter performs the password change through a supported API or
   a tightly defined browser workflow.
6. The agent verifies the new credential by signing in through the provider's
   supported verification path.
7. Only after verification does the agent replace the encrypted vault record
   and report success. Failure preserves the prior credential and emits a
   machine-readable error.

The working agent protocol now implements this sequence. Routine agent calls
use Ed25519 device signatures rather than the deployment bearer token. Package
retrieval requires a current lease, and the final commit binds the signature to
the SHA-256 digest of the replacement envelope. The API updates the envelope,
job, audit chain, and next due date in one transaction.

Every claim and result is signed by the agent's registered Ed25519 device key,
includes a short-lived timestamp and one-time nonce, and is recorded in the
hash-chained audit log. Automatic mode is only active while an item-specific
grant for that exact agent remains valid.

Arbitrary browser agents are not acceptable for password changes. Every site
needs a maintained adapter with selectors/API contracts, rate limits, MFA and
CAPTCHA fallback behavior, tests, and a kill switch.

## Email connection

Email is a recovery and notification channel, not a source of broad authority.
The production flow should:

- use OAuth with the smallest provider scope available;
- recommend a dedicated security alias rather than unrestricted inbox access;
- encrypt refresh tokens using a KMS/HSM-backed root key;
- filter only provider security and password-change messages;
- require explicit confirmation before following reset links;
- never expose message bodies or tokens to the planner model;
- revoke the connection automatically after suspicious activity.

Google, Microsoft, and generic IMAP adapters must be separate implementations.
IMAP password authentication should not be supported when OAuth is available.

The API now implements Google and Microsoft authorization-code flows with PKCE.
The server creates a ten-minute, one-time state value and stores the PKCE
verifier encrypted. After the provider callback, access and refresh tokens are
encrypted with the deployment root key and never included in connection-list
responses. Revocation immediately removes the stored token ciphertext. Message
polling is not implemented yet.

## Product services

- `api`: zero-knowledge record storage, policies, jobs, audit API.
- `proxy`: pinned non-root HTTPS ingress and automatic internal certificates.
- `scheduler`: scans due policies on a bounded interval and creates deduplicated jobs.
- `backup`: makes consistent, independently encrypted snapshots without network access.
- `email-monitor`: refreshes sealed OAuth tokens and stores sanitized metadata signals.
- `planner`: optional stateless AI classification with no credential authority.
- `trusted-agent`: local desktop service holding device-bound keys.
- `worker`: optional isolated short-lived VM for supported remote adapters.
- `planner`: unprivileged structured-plan generation.
- `notifications`: scoped email/push delivery.
- `admin`: billing, tenant policy, incident response, and support tooling.

The current repository implements the API/domain foundation and dashboard.

The runtime image is based on an immutable Python Alpine image digest, installs an
exact Linux dependency lock without build isolation, and emits an SPDX 2.3
package inventory at `/app/sbom.spdx.json` after the application is installed.

The email monitor is the only worker with both network access and permission to
decrypt provider OAuth tokens. It never receives vault keys. It polls a bounded
25-message metadata window, classifies locally, hashes provider message IDs,
removes sender local parts, and stores no subject or body. Sanitized events are
untrusted planner inputs and cannot grant rotation authority.

The scheduler runs as a separate non-root container against the shared database
volume. It scans immediately at startup and every 15 to 3,600 seconds
thereafter. Existing open jobs prevent duplicates, so restarts and overlapping
scans do not create multiple rotations for one item. Each successful scan
updates a container-local heartbeat; Docker marks the worker unhealthy if that
heartbeat becomes stale.

The backup worker mounts the live database read-only and has no network. It uses
SQLite's online backup API, authenticates each encrypted snapshot with an
independent AES-256-GCM key, verifies the restored digest and database integrity,
then applies bounded retention to a separate volume. A separate opt-in restore
profile is the only container granted write access to the data volume.
Backup health checks require a recent encrypted file, while API readiness runs
SQLite's bounded `quick_check`. The HTTPS proxy depends on that readiness
endpoint, so a process that is alive but cannot read a valid database fails
closed at ingress.

## Browser authentication

The first owner proves deployment authority with the server bootstrap token and
registers a WebAuthn passkey. Subsequent browser access uses user-verifying,
discoverable passkeys. WebAuthn challenges are single-use and expire after five
minutes. Successful authentication creates a random 30-minute session token;
only its SHA-256 hash is stored. The browser cookie is HTTP-only,
SameSite-Strict, and Secure when the configured origin uses HTTPS. Stateful
requests made with the cookie must present that exact origin.

The browser drops its vault CryptoKey reference, overwrites the retained key
bytes, clears decrypted DOM content, and resets passphrase fields after five
minutes without keyboard or pointer activity. It locks immediately when the
page is backgrounded or unloaded. The owner can invalidate every server session
and revoke a trusted device; device revocation also deletes that device's
automation grants.

The deployment token remains available only for initial owner setup. Once the
owner exists, it no longer authorizes vault APIs. The owner
creates a ten-minute, one-use agent enrollment code from a passkey session. The
server stores only its SHA-256 hash, and the agent redeems it while registering
its public key. Multi-user enrollment, passkey recovery, distributed throttling,
and centralized session revocation remain pre-beta work.

The browser creates a random 256-bit AES-GCM vault data key. It derives a key
encryption key locally with Web Crypto PBKDF2-HMAC-SHA256 and 600,000 iterations,
then stores only the AES-GCM-wrapped data key on the API. Vault records use the
random data key, so a passphrase change only replaces the wrapped-key envelope.
The wrapping operation authenticates the fixed `vaultmind-vault-key-v1` context
to prevent ciphertext reuse in another protocol.

The trusted agent receives the wrapped key only with a leased job package and
unwraps it locally from the operator-entered passphrase. Legacy vaults that used
a directly derived record key are migrated by the browser only after that key
successfully decrypts an existing record. PBKDF2 remains an interoperable
baseline; an audited Argon2id browser implementation and recovery keys are
still release gates. Keys and passphrases remain in client memory only.
