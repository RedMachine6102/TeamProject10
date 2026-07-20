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

Create a Google **Desktop app** OAuth client or a Microsoft
**Mobile and desktop application** registration with its system-browser
loopback redirect enabled. Then connect the agent:

```powershell
vaultmind-agent email-connect `
  --mail-provider google `
  --client-id "your-oauth-client-id"
```

The agent opens the system browser and uses an authorization-code flow with a
random state value, PKCE S256, a random loopback port, and a three-minute
timeout. It requests only the mailbox-read and offline scopes required for
local challenge retrieval. The authorization code and tokens are never printed.
An optional client secret uses a hidden prompt and is never accepted as a
command-line argument.

After the provider returns a refresh token, the agent protects it with Windows
DPAPI and stores the encrypted file beside the agent configuration under
`%LOCALAPPDATA%\VaultMind\Agent`. If the provider rotates that token during a
refresh, the replacement is atomically protected before mailbox processing
continues. A new connection starts with no allowed senders, so code retrieval
fails closed until an exact provider sender is configured:

```powershell
vaultmind-agent email-allowlist `
  --sender-domain demo=accounts.example
```

Use:

```powershell
vaultmind-agent email-status
vaultmind-agent email-disconnect
```

The status command displays only the mail provider and sender-domain allowlist.
It does not display OAuth credentials. `email-configure` remains available as a
hidden-prompt recovery option for controlled development, but the native
`email-connect` flow is the normal path.
