# Metadata-only email monitoring

The email monitor turns bounded mailbox metadata into low-trust security signals.
It never requests, stores, or sends message bodies to an AI planner.

## Provider boundaries

Google polling uses the `gmail.metadata` scope. That scope does not permit a
search query on `users.messages.list`, so the monitor lists at most 25 recent
message IDs and calls `users.messages.get` with `format=METADATA` and only the
`Subject` and `From` headers. See the official
[list](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list)
and [get](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get)
documentation.

Microsoft polling uses delegated `Mail.ReadBasic` and requests only `id`,
`subject`, `sender`, and `receivedDateTime` from the inbox. It does not request
`body`, `bodyPreview`, attachments, recipients, or MIME content. See the
[Microsoft mail API overview](https://learn.microsoft.com/en-us/graph/api/resources/mail-api-overview?view=graph-rest-1.0)
and [permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference).

Access tokens are refreshed inside the isolated monitor from root-key-encrypted
refresh tokens. Rotated Microsoft refresh tokens replace older values as
required by the provider. Tokens are never returned by the API or included in
logs. See the official [Google refresh flow](https://developers.google.com/identity/protocols/oauth2/web-server)
and [Microsoft authorization-code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow).

## Stored event shape

The monitor immediately classifies metadata and persists only:

- a SHA-256 hash of provider name plus provider message ID;
- provider and fixed event category;
- sender domain without the mailbox/local part;
- provider occurrence time and local detection time.

Raw subject, sender address, provider message ID, message body, and tokens are
discarded. Repeated polls are deduplicated by the hashed event ID.

Email is attacker-controlled input. A classified event may inform a dashboard
or propose a plan, but it must never authorize a password rotation, MFA change,
recovery action, or device enrollment. Those actions still require the existing
policy, signed agent authority, and provider verification boundaries.
