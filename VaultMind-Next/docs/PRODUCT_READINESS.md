# Product readiness

VaultMind Next is an engineering preview, not yet a commercial password
manager. This checklist keeps the remaining work tied to evidence instead of
marketing claims.

## Current evidence

| Capability | Status | Evidence |
| --- | --- | --- |
| Client-encrypted vault records | Working foundation | Random data key, wrapped-key API, migration and agent rotation tests |
| Vault passphrase change | Working foundation | Rewraps the data key without replacing record ciphertext |
| 30/60/90-day scheduling | Working foundation | Policy, queue, lease, and transition tests |
| Trusted-agent authorization | Working foundation | Device signatures, nonce replay rejection, scoped grants |
| Email account linking | Working foundation | OAuth code + PKCE integration test, encrypted token storage, revocation |
| Email verification challenges | Security design | Local-agent-only boundary documented; provider review and adapter implementation remain required |
| Email security monitoring | Working foundation | Bounded metadata requests, token refresh, sanitization and deduplication tests |
| AI planning boundary | Working foundation | Sanitized-only input, strict schema, stateless request, no approval/execution fields |
| Deployed backend | Working foundation | Hardened VM 101 services with persistent data and HTTPS ingress |
| Verified automated rotation | Working foundation | Signed agent protocol and full demo change/verify/atomic-commit test |
| Unattended scheduling | Working | Dedicated hardened service created a real due job without an API scan call |
| Automatic real-site password changes | Not implemented | No reviewed production provider adapter yet |
| Malware-resistant endpoint storage | Partial | Windows DPAPI at rest; signed packaging and TPM-bound keys remain |
| Owner account security | Working foundation | User-verifying passkey, one-use challenges, hashed 30-minute sessions, origin checks |
| Endpoint lock and revocation | Working foundation | Background/inactivity lock, DOM clearing, all-session and device revocation tests |
| Agent enrollment | Working foundation | Passkey-authorized ten-minute code, hash-only storage, one-use redemption |
| Encrypted recovery | Working foundation | Consistent AES-GCM backups, retention, tamper tests, restore integrity drill |
| Service health | Working foundation | DB quick-check readiness, scheduler heartbeat, backup freshness, proxy fail-closed dependency |
| Reproducible runtime | Working foundation | Immutable base digest, exact dependency lock, lock tests, embedded SPDX inventory |

## Required before a private beta

1. Replace the private `vaultmind.internal` CA with an owned hostname and
   publicly trusted automated certificate before any Internet-facing beta.
2. Expand the single-owner passkey foundation into multi-user enrollment,
   additional passkeys, session inventory, distributed rate
   limits, device enrollment, and account recovery. Keep the deployment token
   limited to bootstrap and agent operations.
3. Build and sign a trusted desktop agent whose device key is protected by the
   operating-system keystore. Lock and revoke it when endpoint integrity is
   uncertain.
4. Upgrade the browser PBKDF2 wrapping baseline to audited Argon2id and add
   recovery keys plus vault-key rotation.
5. Publish a small provider adapter SDK and prove the full change/verify/commit
   sequence against a controlled demonstration provider. Add global, provider,
   account, and device kill switches before enabling unattended jobs.
6. Register Google and Microsoft OAuth applications, configure production
   callback URLs, and validate the implemented refresh/metadata monitor against
   controlled provider mailboxes and provider revocation.
7. Replicate encrypted backups off-host with separate deletion credentials, then
   export health metrics and add alert delivery, dependency/container scanning, artifact signing, and
   documented incident response.

## Required before sale

- PostgreSQL with tenant isolation and tested authorization boundaries.
- Billing, organization administration, retention controls, deletion, export,
  privacy workflows, and support tooling.
- Signed and reproducible client releases with rollback protection.
- Independent penetration test and cryptographic review.
- Legal/privacy review, threat-model review, disaster-recovery exercise, and a
  vulnerability disclosure process.

No design can keep secrets from malware that fully controls an unlocked device
and can read its memory, keyboard, or screen. VaultMind's defensible promise is
to minimize exposed plaintext, bind authority to trusted devices, detect
compromise, and make revocation fast.
