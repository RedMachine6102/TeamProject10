# Encrypted backup and restore

VaultMind takes a consistent SQLite snapshot, checks it, and encrypts it with
AES-256-GCM before it reaches backup storage. The authenticated header records
the creation time, plaintext size, and SHA-256 digest. Verification decrypts to
a temporary directory, validates the authentication tag and digest, and runs
SQLite `PRAGMA integrity_check` plus a VaultMind schema check.

## Key handling

`VAULTMIND_BACKUP_KEY` must be an independently generated, base64-encoded
32-byte key. It must not equal `VAULTMIND_ROOT_KEY`, the deployment token, or a
vault passphrase. Store a recovery copy in the organization password manager or
HSM-backed secret store before enabling backups. Losing this key makes every
backup unrecoverable.

The Docker backup worker receives the backup key and a read-only database
volume. It does not receive the API root key, OAuth credentials, deployment
token, or network access. It writes only to the dedicated backup volume.

## Automatic backups

The default service creates and verifies a backup immediately at startup, then
every 24 hours. It retains the newest 14 files. Configure these bounded values
in `.env`:

```text
VAULTMIND_BACKUP_HOURS=24
VAULTMIND_BACKUP_RETAIN=14
```

Docker marks the worker unhealthy if the newest encrypted backup is older than
the configured interval plus one hour. This detects a hung worker even when its
container process has not exited.

Check recent activity without exposing the key:

```sh
docker compose logs --tail 20 backup
docker compose run --rm --no-deps backup vaultmind-backup drill --directory /app/backups
```

The local Docker volume is the first recovery layer, not an off-site backup.
Production operations must replicate encrypted `.vmbak` files to storage with
separate deletion credentials and test recovery from that copy.

## Restore procedure

Never overwrite a running database. During an approved recovery window:

1. Preserve the damaged database and current encrypted backups for forensics.
2. Stop writers with `docker compose stop api scheduler backup`.
3. Run a restore drill against the newest backup.
4. Restore through the isolated profile:

```sh
docker compose --profile restore run --rm --no-deps restore \
  vaultmind-backup restore-latest \
  --directory /app/backups \
  --database /restore-data/vaultmind-next.db \
  --force
```

5. Start only the API, verify health, audit-chain integrity, owner/passkey state,
   and record counts, then start the scheduler and backup worker.
6. Record the drill or incident in the operations log.

The restore command decrypts into a temporary file, verifies cryptographic and
SQLite integrity, sets restrictive permissions, and atomically replaces the
target. It never writes a partially decrypted database to the final path.
