# Single VPS Field Encryption

This document defines the self-host encryption path for a Verdant deployment
where the backend, Postgres, Redis/PgBouncer, Garage, Caddy, and optional
LiveKit all run on one VPS.

The goal is app-level protection for sensitive database fields. It does not
replace host hardening, Postgres permissions, filesystem permissions, encrypted
backups, or full-disk encryption. It reduces blast radius if a database dump,
backup, or read-only SQL credential leaks without the backend environment
secrets.

## Threat Model

Protected against:

- Offline database dumps without `/etc/verdant/backend.env`.
- Accidental plaintext exposure in SQL exports, backups, or operator reports.
- Read-only database role compromise for encrypted fields.
- Cross-column ciphertext replay, when associated data is enforced.

Not protected against:

- A compromised running backend process.
- A compromised root user on the VPS.
- A stolen `/etc/verdant/backend.env` or operator secret backup.
- Malicious code deployed into the backend binary.
- Plaintext that must be sent to users, email providers, clients, or logs.

For stronger at-rest protection on a single VPS, use app-level field encryption
plus encrypted backups and, where available, encrypted disks or LUKS.

## Keys

Self-host deployments use:

- `APP_FIELD_ENCRYPTION_KEY`: 32 random bytes encoded as 64 lowercase or
  uppercase hex characters. Required for `standalone`, `linked`, and
  `federated` instances.
- `TOTP_ENCRYPTION_KEY`: current legacy key used by the existing TOTP secret
  path. This remains separate until TOTP is migrated to the shared field
  encryption format.

The root field key must not be stored in Postgres. It lives in
`/etc/verdant/backend.env` for system installs or the rootless backend env file
for rootless installs. The operator may keep a local copy in Windows Credential
Manager so it can rewrite the remote env without regenerating secrets.

Do not regenerate `APP_FIELD_ENCRYPTION_KEY` for an existing database unless a
planned rotation or recovery migration is being performed. Losing it means
encrypted fields cannot be decrypted.

## Primitive

The backend uses envelope-style derived keys from `APP_FIELD_ENCRYPTION_KEY`:

- An AEAD key for encryption.
- A blind-index key for searchable equality indexes.

Field encryption uses AES-256-GCM with a random 96-bit nonce per write.
Associated data includes:

- Schema format label.
- Key version.
- Table name.
- Column name.
- Row identifier.

The associated data prevents ciphertext from one table, column, row, or key
version being accepted in another context.

Blind indexes use keyed HMAC-SHA256 over normalized values and field identity.
They support equality lookup without deterministic encryption. Blind indexes
are not reversible, but they still leak equality patterns within the same
field. Do not create blind indexes unless the product needs lookup by that
value.

## Storage Shape

Encrypted fields should store:

- `*_ciphertext bytea`
- `*_nonce bytea`
- `*_key_version smallint`
- Optional `*_blind_index text` for equality lookup

Do not store raw image bytes or large media bytes in Postgres for encryption.
Media belongs in Garage/object storage. Database encryption covers metadata and
small sensitive fields.

## Sensitive Field Inventory

Passwords and bearer credentials should not be encrypted. They should stay
one-way only:

- `users.password_hash`: Argon2id password hash.
- `sessions.token_hash`, `sessions.revoke_token_hash`, and
  `sessions.verify_token_hash`: token hashes for bearer, revocation, and
  high-risk verification flows.
- `password_resets.token_hash` and `email_verifications.token_hash`: one-time
  token hashes.
- `bot_tokens.token_hash`: bot token hash.
- `users.backup_code_hashes`: HMAC/hash list.
- `federation_instances.verification_token_hash`,
  `account_link_intents.state_hash`, `account_links.proof_jti_hash`,
  `account_link_issued_grants.proof_jti_hash`, and
  `federation_client_memberships.invite_code_hash`: hash-only metadata.

Encrypted or encryption-ready in this slice:

- `users.email`: additive encrypted columns and a blind index are present.
  Login, duplicate checks, password-reset lookup, email-change uniqueness, and
  user reads use the blind index/decryption path when `APP_FIELD_ENCRYPTION_KEY`
  is configured. Plaintext compatibility is still written until the verified
  plaintext-removal release. A bounded startup worker backfills legacy rows when
  the key is configured.
- `email_verifications.email`: additive encrypted columns are present.
  Repository inserts write encrypted metadata when `APP_FIELD_ENCRYPTION_KEY`
  is configured, token-hash reads decrypt at the service boundary, and legacy
  rows are handled by the same bounded startup backfill worker. The current
  registration and resend email-verification hot path stores verification
  tokens in Redis, so this is primarily protection for the durable Postgres
  side-table if it is used by older or future flows.
- `users.totp_secret`: already encrypted by the legacy TOTP helper. It should
  be migrated to the shared field format later so AAD, versioning, and rotation
  are consistent.

Next strong candidates:

- `sessions.ip`, `sessions.user_agent`, `sessions.city`, `sessions.region`,
  `sessions.country`, `login_entries.ip`, `login_entries.user_agent`,
  `login_entries.city`, and `login_entries.country`: encrypt, reduce retention,
  or both. They are useful for security/session UX but sensitive in dumps.
- `audit_entries.metadata` and `audit_entries.ip`: encrypt selected metadata
  values or split sensitive metadata into encrypted typed columns.
- `invite_codes.code` and `server_invites.code`: migrate to hash-only storage.
  Show invite codes once at creation, then store only hashes plus safe display
  metadata.
- `reports.reason`, `moderation_actions.reason`, and `bug_reports.title`,
  `bug_reports.description`, `bug_reports.os`, `bug_reports.fingerprint`, and
  `bug_reports.close_note`: encrypt or reduce detail because these can contain
  private user content or device data.
- `relationships.notes`, `dm_channels.name`, and any future private profile
  notes: encrypt if they remain user-authored private metadata.

Deferred product decisions:

- `messages.content` and DM message content. Encrypting message bodies changes
  search, moderation, retention, previews, bot access, federation, and abuse
  workflows, so it needs its own design and migration.
- `attachments.filename` and `attachments.url`: raw attachment bytes remain in
  Garage/object storage behind authenticated media APIs. Attachment metadata may
  be encrypted later, but public media keys and private attachment keys must
  remain separated before that work starts.
- `announcements.content`: can be server-public data, but may include private
  drafts or bot-provided content depending on product behavior. Treat as a
  later moderation/product decision.
- `account_links.issuer_username` and `issuer_display_name`: identity metadata,
  not credentials. Encrypting it is optional and would reduce support/debug
  visibility.
- Federation route and remote-id tables: runtime mapping metadata, not secret
  material. Keep keys/proofs hashed where applicable and avoid storing runtime
  payload bodies in official/self-host crossing tables.

## Migration Plan

Use additive migrations first.

1. Add encrypted columns next to plaintext columns.
2. Backfill encrypted values in small batches.
3. Add blind-index columns and unique indexes where needed.
4. Read through encrypted columns first, falling back to plaintext during the
   backfill window.
5. Write both encrypted and plaintext columns during the transition.
6. Verify counts and lookup behavior.
7. Stop writing plaintext.
8. Drop or null plaintext columns only after a release with verified rollback
   notes.

The backend must fail closed if a self-host instance starts without
`APP_FIELD_ENCRYPTION_KEY` once encrypted columns are required.

Current implementation slice:

- `users.email` has additive encrypted columns and a blind index.
- Registration writes plaintext compatibility columns plus encrypted email
  material when `APP_FIELD_ENCRYPTION_KEY` is configured.
- Login, registration duplicate checks, password-reset lookup, and email-change
  uniqueness checks use the blind index when available and fall back to the
  legacy plaintext lookup for rows not yet backfilled.
- User reads in auth and account settings decrypt `users.email` when encrypted
  material is present, otherwise they use the plaintext compatibility column.
- `backfill_encrypted_email_batch` claims bounded row batches with
  `FOR UPDATE SKIP LOCKED` and writes only encrypted metadata, not plaintext
  email values.
- `email_verifications.email` has encrypted insert/read helpers plus
  `backfill_encrypted_email_verifications_batch`; lookup remains by token hash,
  so no blind index is needed for this table.
- `field_encryption_backfill` starts after migrations when
  `APP_FIELD_ENCRYPTION_KEY` is configured. It processes bounded batches,
  sleeps briefly between non-empty batches, and logs counts only.
- Plaintext compatibility columns are still written in this slice. Removing or
  nulling plaintext requires a separate verified backfill and rollback plan.

Not implemented yet:

- A hostctl/operator status view or command to inspect field-encryption backfill
  progress on demand.
- A migration that stops writing `users.email` plaintext, replaces
  `users_email_lower_uniq`, and then nulls or drops the plaintext column.
- A migration that stops writing `email_verifications.email` plaintext and then
  nulls or drops the plaintext column.
- Runtime key rotation beyond the versioned storage shape and design.

## Rotation Plan

The first implementation uses key version `1`. Rotation needs:

- Current key version in config.
- Decryption support for old versions.
- Writes using the newest key version.
- A background or operator-triggered re-encryption job.
- Progress and failure reporting without logging plaintext, ciphertext, nonce,
  keys, or full blind indexes.

During rotation, old keys must remain available until every row using them is
re-encrypted and verified.

## Operator Requirements

The operator should:

- Generate `APP_FIELD_ENCRYPTION_KEY` only when empty and only after explicit
  user action.
- Store the local environment profile in Windows Credential Manager.
- Preserve existing secrets when filling defaults from services.
- Back up remote backend env files before overwriting.
- Warn before replacing any existing encryption key.
- Show that losing the key makes encrypted fields unrecoverable.
- Never print generated secrets in hostctl output unless the operator explicitly
  requested secret material for local env autofill.

## Tests

Backend unit tests:

- Valid 32-byte hex keys are accepted.
- Missing self-host field keys fail config startup.
- Short, non-hex, all-zero, repeated, and placeholder keys are rejected.
- Encrypt/decrypt round trips require the same associated data.
- Reusing the same plaintext produces different ciphertexts.
- Wrong row/table/column/key fails decryption.
- Blind indexes are stable for the same normalized value and key, but differ
  across keys and fields.

Backend integration tests:

- Encrypted fields are not stored as plaintext.
- Login and uniqueness work through blind indexes after email migration.
- Restarting with the same key decrypts existing rows.
- Restarting with a different key fails closed for encrypted fields.
- A live scratch-Postgres harness exists at
  `server-rs/tests/field_encryption_storage.rs`. It runs only when
  `VERDANT_FIELD_CRYPTO_TEST_DATABASE_URL` points to a scratch database whose
  name contains `verdant_field_crypto_test`. Non-local databases are refused
  unless `VERDANT_ALLOW_NONLOCAL_FIELD_CRYPTO_TEST_DB=1` is explicitly set.

Operator/hostctl tests:

- `APP_FIELD_ENCRYPTION_KEY` is allowed for self-host env writes.
- Invalid field keys are rejected before remote write.
- Existing local secrets survive service autofill and default generation.
- Remote env writes create a backup before replacement.
