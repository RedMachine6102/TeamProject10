# Threat model

## Security promise

VaultMind can reduce the damage from server compromise, stolen databases,
network interception, malicious model output, and some forms of local malware.
It cannot honestly guarantee secrecy when an attacker fully controls an
unlocked endpoint and can read its memory, screen, keyboard, or browser session.

The design goal is containment, rapid detection, and revocation—not an
unprovable claim of being “bulletproof.”

## Protected assets

- vault decryption keys and plaintext credentials;
- passkeys, recovery codes, and MFA seeds;
- provider OAuth refresh tokens and authenticated browser sessions;
- rotation approvals and signed audit history;
- billing, tenant, and device identity data.

## Required controls

### Client and device

- Device-bound keys backed by TPM, Secure Enclave, or platform keystore.
- Argon2id recovery-key derivation with calibrated memory cost.
- Memory locking and short plaintext lifetimes where the OS permits it.
- Automatic lock on sleep, session switch, remote desktop, or integrity loss.
- Signed updates, reproducible builds, and rollback protection.
- Clipboard avoidance by default; secure autofill through an extension channel.

### Server

- TLS 1.3, HSTS, strict origin policy, and certificate automation.
- WebAuthn/passkeys with phishing-resistant MFA for user and admin access.
- Envelope encryption using a KMS/HSM for server-held integration secrets.
- Row-level tenant isolation, least-privilege service identities, and egress rules.
- Append-only signed audit events exported to a separate security account.
- Device-signed worker requests with bounded clock skew and replay rejection.
- Rate limits, replay protection, idempotency keys, and short-lived tokens.
- Encrypted backups with restore drills and separate deletion credentials.

The current backup worker provides authenticated encryption, bounded local
retention, and an integrity-checked restore path. Off-host replication with
separate deletion credentials remains required so a VM or Docker administrator
cannot destroy both the live database and every recovery copy.

The private deployment terminates HTTPS at a pinned, non-root reverse proxy,
sets HSTS, and uses an internal CA trusted only on enrolled clients. This blocks
passive LAN interception after CA enrollment, but it is not a substitute for a
publicly trusted certificate on an Internet-facing service.

### Automation

- No credentials or tokens in model prompts, logs, traces, or crash reports.
- Provider-specific allowlisted operations and schemas.
- Human approval for new providers, recovery paths, MFA changes, and anomalies.
- One job per isolated worker; destroy worker state after completion.
- Verify new credentials before committing the vault update.
- Global, tenant, provider, and device kill switches.

Email subjects and senders are attacker-controlled. The monitor strips raw
metadata after local classification, stores only a sender domain and fixed
category, and treats every event as advisory. An email event cannot approve or
execute a rotation, change MFA, enroll a device, or trigger recovery.

The optional model sees only the monitor's fixed category, provider, and sender
domain. Structured output is validated into a recommendation with no authority
field. Prompt injection can therefore affect advisory classification but cannot
decrypt a vault record, approve a job, sign an agent request, or commit a new
password.

## Compromised endpoint response

If endpoint integrity is uncertain, the application must lock immediately,
revoke device sessions, pause rotations, and require recovery from a different
trusted device. Server-side encrypted records alone cannot prevent an active
attacker from stealing plaintext while the user has unlocked the vault.

The development Windows agent wraps its device key with DPAPI and only decrypts
vault records inside the rotation process. DPAPI does not stop malware already
running as the same user. TPM-backed non-exportable keys, signed binaries,
integrity monitoring, and revocation-on-compromise remain launch requirements.

Before changing a provider password, the agent keeps one bounded
DPAPI-protected prepared recovery record and blocks new jobs. After a restart it
verifies whether the old or new provider login works before failing or
committing the job. Identical signed commits are idempotent, including after the
original lease timeout, so a lost response does not repeat the provider change.
The record is deleted only after confirmation. It temporarily contains the old
and new credentials, so same-user malware can still read them while the agent
is running; DPAPI protects only the at-rest file.

Optional mailbox refresh tokens are also protected with DPAPI and used only by
the local agent. Exact sender-domain and timestamp checks reduce accidental or
malicious code selection, but email accounts, message bodies, local process
memory, and the system clock remain attack surfaces. A same-user process can
read a token or challenge code while the agent is running. The backend cannot
use mailbox access to authorize a rotation because it never receives that
access.

Mailbox authorization uses the system browser rather than an embedded view.
The local listener binds only to loopback, accepts one bounded authorization
response, validates a random state value, and uses a one-time PKCE verifier.
This reduces interception and request-forgery risk but does not protect a
mailbox already controlled by an attacker or a fully compromised local user.

Vault records use a random data key. The server stores that key only as an
AES-GCM envelope protected by a passphrase-derived wrapping key, so database or
backup disclosure does not reveal it. Passphrase changes replace the envelope
without decrypting records on the server.

An active same-user process can still read credentials while the vault is
unlocked or intercept input before encryption. Memory clearing is best-effort
in browser JavaScript and Python. Endpoint detection, a dedicated agent account,
TPM-backed identity, rapid revocation, and short unlock windows remain required
defense-in-depth controls.

The browser reduces that exposure by locking after five minutes of inactivity
and immediately on background or unload. Locking clears decrypted DOM content,
revealed passwords, edit forms, passphrase fields, and retained key bytes before
dropping the CryptoKey reference. Passwords are never placed in HTML data
attributes or copied automatically. The owner can revoke all browser sessions
and remove a device's automation authority, but these controls do not defeat
malware already reading the active process.

## Launch gates

No commercial release should occur before independent penetration testing,
external cryptographic review, dependency/SBOM scanning, privacy and legal
review, incident-response exercises, and a documented vulnerability-disclosure
program.
