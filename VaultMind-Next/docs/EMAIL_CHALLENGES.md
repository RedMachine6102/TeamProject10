# Email verification challenges

Mailbox-body access is not part of the backend service. The deployed email
monitor intentionally keeps metadata-only permissions and cannot read or return
verification codes.

Some providers require a short-lived email code during a password change. That
capability is implemented only in the trusted local rotation agent:

- it is opt-in per provider and disabled by default;
- OAuth tokens are stored under the operating-system account protection and
  never uploaded to the backend;
- mailbox-body access starts only after the agent claims an authorized rotation
  job and ends when that job finishes;
- the agent considers only messages newer than the claim, no older than five
  minutes, and from an exact provider-domain allowlist;
- at most ten recent messages are examined, text is capped at 32 KiB per
  message, provider responses are capped at 1 MB, and attachments are never
  fetched;
- the code remains in process memory, is submitted directly to the provider,
  and is never stored, logged, backed up, or sent to an AI planner;
- a code cannot authorize a rotation, enroll a device, change MFA settings, or
  recover an account;
- repeated or ambiguous codes fail the current rotation without changing the
  stored vault credential.

This feature is for email-delivered, single-use password-change challenges only.
It must not collect authenticator-app seeds, recovery codes, passkeys, SMS
codes, or security-key assertions.

Google mailbox-body access requires the restricted `gmail.readonly` scope.
Microsoft requires delegated `Mail.Read`; `Mail.ReadBasic` cannot return message
bodies. A commercial deployment must complete each provider's consent,
verification, and security-review requirements before enabling local challenge
retrieval.

## Local setup

Create a Google or Microsoft OAuth application with a loopback/native-client
configuration and the narrow mailbox scope described above. Obtain a refresh
token through that provider's authorization flow, then configure the agent:

```powershell
vaultmind-agent email-configure `
  --mail-provider google `
  --client-id "your-oauth-client-id" `
  --sender-domain demo=accounts.example
```

The client secret and refresh token use hidden prompts and are never accepted as
command-line arguments. The encrypted file is stored beside the agent
configuration under `%LOCALAPPDATA%\VaultMind\Agent`. Use:

```powershell
vaultmind-agent email-status
vaultmind-agent email-disconnect
```

The status command displays only the mail provider and sender-domain allowlist.
It does not display OAuth credentials. The initial provider authorization and
consent flow is intentionally separate in this engineering build; a production
installer must provide a reviewed native OAuth flow rather than asking users to
handle refresh tokens.
