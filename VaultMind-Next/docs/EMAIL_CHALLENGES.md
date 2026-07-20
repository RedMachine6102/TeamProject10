# Email verification challenges

Mailbox-body access is not part of the backend service. The deployed email
monitor intentionally keeps metadata-only permissions and cannot read or return
verification codes.

Some providers require a short-lived email code during a password change. That
capability belongs only in the trusted local rotation agent:

- it is opt-in per provider and disabled by default;
- OAuth tokens are stored under the operating-system account protection and
  never uploaded to the backend;
- mailbox-body access starts only after the agent claims an authorized rotation
  job and ends when that job finishes;
- the agent considers only messages newer than the claim, no older than five
  minutes, and from an exact provider-domain allowlist;
- at most one bounded text message is examined and attachments are never read;
- the code remains in process memory, is submitted directly to the provider,
  and is never stored, logged, backed up, or sent to an AI planner;
- a code cannot authorize a rotation, enroll a device, change MFA settings, or
  recover an account;
- repeated or ambiguous codes fail closed and pause that provider.

This feature is for email-delivered, single-use password-change challenges only.
It must not collect authenticator-app seeds, recovery codes, passkeys, SMS
codes, or security-key assertions.

Google mailbox-body access requires the restricted `gmail.readonly` scope.
Microsoft requires delegated `Mail.Read`; `Mail.ReadBasic` cannot return message
bodies. A commercial deployment must complete each provider's consent,
verification, and security-review requirements before enabling local challenge
retrieval.
