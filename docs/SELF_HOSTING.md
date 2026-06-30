# Self-Hosting Verdant

This guide covers the Docker Compose template in `deploy/selfhost/`. It is intended for a practical single-host deployment of the Rust server with Postgres, Redis, MinIO/S3-compatible storage, and optional LiveKit voice.

## Minimum Specs

For a small private instance:

- 2 vCPU
- 4 GB RAM
- 40 GB SSD
- Docker Engine with the Docker Compose plugin
- A DNS name and TLS-terminating reverse proxy for production

For instances with active voice or frequent uploads, start with 4 vCPU, 8 GB RAM, and separate object storage backups. LiveKit media quality depends heavily on network path, public UDP reachability, and host CPU headroom.

## Included Services

The self-host compose stack includes:

- `app`: the Rust Verdant server built from `server-rs/Dockerfile`.
- `postgres`: Postgres 17 Alpine with a persistent volume.
- `redis`: Redis 7 Alpine with append-only persistence for rate limits, presence, pub/sub, voice placement, and short-lived verification state.
- `minio`: local S3-compatible object storage for uploads.
- `livekit`: optional voice service enabled with the `voice` compose profile.

The app is bound to `127.0.0.1:3001` by default. Put a reverse proxy in front
of it for TLS and public traffic. If the proxy forwards a real client IP header,
configure `TRUSTED_PROXY_CIDRS` with only the proxy's IP/CIDR and make the proxy
overwrite `do-connecting-ip` before requests reach the app. Do not trust
forwarded IP headers from arbitrary public clients.

## Not Included

The self-host template does not include official Verdant subscription services, Stripe billing, external content scanning providers, Cloudflare Worker deployments, or function delegate infrastructure. Self-host defaults set:

- `INSTANCE_MODE=standalone`
- `BILLING_MODE=disabled`
- `CONTENT_SCAN_PROVIDER=none`
- `UPLOAD_POLICY=media_validation_only`

With `CONTENT_SCAN_PROVIDER=none`, uploads are not automatically checked by an external moderation scanner. `media_validation_only` means the server enforces file type and size validation before storage; the operator remains responsible for moderation policy, abuse response, backups, and retention.

## Client Network Selection

The desktop client can connect to the official Verdant network or to saved custom networks. Custom networks are local client profiles containing a display name and API origin; they do not link accounts, merge data, or grant federation trust by themselves.

When a user adds a custom network, the client validates the API origin, fetches `/api/instance`, and stores the selected origin under a local profile name. Accounts, sessions, keyring entries, cache, REST transport, and WebSocket transport remain scoped to the selected backend origin.

Use an HTTPS API origin for any network that is reachable outside local development. Local HTTP is only intended for `localhost`, `127.0.0.1`, and `::1` testing.

## Instance Metadata Visibility

Self-host servers publish public operator metadata at `/api/instance`. The
client uses it for network selection, Settings > About, capability gates, and
upload consent copy. This metadata is self-reported unless a future official
registry verifies it.

Check the active values after deployment:

```bash
curl -fsS https://your-api-origin.example/api/instance | jq '{
  name,
  mode,
  serverVersion,
  minClientVersion,
  uploadPolicy,
  contentScanning,
  security,
  capabilities: {
    imageUploads: .capabilities.imageUploads,
    fileSharing: .capabilities.fileSharing,
    messageAttachments: .capabilities.messageAttachments,
    maxUploadBytes: .capabilities.maxUploadBytes
  }
}'
```

Expected standalone/no-scanner shape:

```json
{
  "mode": "standalone",
  "uploadPolicy": "media_validation_only",
  "contentScanning": {
    "provider": "none",
    "enabled": false
  }
}
```

`serverVersion`, `minClientVersion`, and scanner provider/status are public
status fields. Scanner API keys, mock hash lists, bucket names, object keys, and
other secrets are never exposed through this endpoint.

`security.certificatePins` is advisory public metadata for operators and
diagnostics. It can be populated from the process environment with
`INSTANCE_CERT_SHA256_PINS` as comma-separated certificate SHA-256 fingerprints
in 64-character hex form, with `VERDANT_CERT_SHA256_PINS` and
`VERDANT_OFFICIAL_CERT_SHA256_PINS` accepted as aliases. Clients must not use
this self-reported endpoint to bootstrap first-contact trust; enforceable
pinning still has to be configured in the client build/run environment before
the first request to the backend.

## Federation And Discovery Status

The custom network selector is not federation. It is a local convenience for manually connecting the client to known API origins.

The intended federation flow starts with metadata and discovery only:

1. A self-host operator publishes `/api/instance` metadata for name, mode, public URL, API URL, capabilities, and upload policy.
2. The operator later registers the instance with the official registry using domain verification and an instance signing key.
3. The official network can list an approved community or invite in search/discovery.
4. A user who chooses that community connects directly to the self-host API origin. The self-host server still owns local account creation, membership, messages, uploads, roles, and moderation.

Payment is intentionally not part of the current implementation. A paid registration flow can be added later, but payment alone must not grant trust. Linked/federated trust requires registry approval, revocation support, and signed or otherwise verified instance metadata. See [Federation Boundaries](../FEDERATION_BOUNDARIES.md) and [Open Source And Federation Goals](OPEN_SOURCE_FEDERATION_GOALS.md).

Account linking is optional identity metadata. A linked or federated self-host
can create local link intents and verify official RS256 identity proofs when
`FEDERATION_LINK_VERIFY_KEY_PEM` is configured. Set
`ACCOUNT_LINK_OFFICIAL_API_ORIGIN` only when linked or federated self-hosts
should poll proof-grant revocation status. This does not merge accounts or
grant local permissions; it only stores local identity metadata that can become
`linked`, `stale`, or `revoked`.

## Upload Capability

Image upload controls are shown only when the connected backend advertises upload support and the authenticated user is entitled to use it. Self-host instances normally enable image uploads with:

```env
UPLOAD_POLICY=media_validation_only
INSTANCE_CAP_IMAGE_UPLOADS=true
INSTANCE_CAP_FILE_SHARING=true
INSTANCE_CAP_MESSAGE_ATTACHMENTS=true
CDN_BASE_URL=https://your-domain.example
```

`INSTANCE_CAP_IMAGE_UPLOADS` controls profile, avatar, banner, server icon, and emoji-style image upload surfaces. `INSTANCE_CAP_FILE_SHARING` enables the attachment upload endpoint. `INSTANCE_CAP_MESSAGE_ATTACHMENTS` tells compatible clients that uploaded files can be claimed by text-channel and DM messages; it defaults to true only when file sharing is enabled on a backend version that supports message attachment claims. The compose template includes MinIO and sets those values for local testing. For production, keep `UPLOAD_POLICY=media_validation_only` only if you accept operator-managed moderation with file type and size validation but no external scanner. Set `UPLOAD_POLICY=disabled`, `INSTANCE_CAP_IMAGE_UPLOADS=false`, `INSTANCE_CAP_FILE_SHARING=false`, or `INSTANCE_CAP_MESSAGE_ATTACHMENTS=false` to hide the matching client upload controls and make the matching backend path reject images or attachment claims.

Message attachments are uploaded first, then claimed when the message is created. The server only links pending attachments uploaded by the same user in the same channel, so an attachment ID from another channel, another account, or an already-sent message is rejected. Attachment URLs returned to clients use `/api/media/attachments/{id}` and require the viewer to be authenticated and able to view the channel or DM. Do not expose raw `attachments/*` object paths through Caddy, a bucket website, or a public CDN rule; object/CDN public media paths should be limited to profile, server, bot, emoji, and sticker assets. The protected URL shape requires a compatible client that fetches attachment blobs through authenticated REST/native transport; deploy the compatible client before or alongside the `server-rs` cutover.

The desktop client does not keep broad `img-src https:` in the static Tauri CSP. Message attachments are fetched through authenticated REST/native transport and rendered as app-owned `blob:` URLs. Public profile, server, bot, emoji, sticker, Klipy image, YouTube thumbnail, and announcement images are fetched by the Rust native public media proxy, validated against the active backend API/public/CDN origins from `/api/instance` plus pinned official media hosts, and then rendered as app-owned `blob:` URLs. Self-host operators should set `CDN_BASE_URL` to the public origin that serves profile/server/bot/emoji/sticker keys; raw `attachments/*` keys must remain private and must not be served by public CDN rules.

The desktop client also keeps `media-src` narrow. Current direct video playback
is limited to app/blob/local development and pinned Klipy clip hosts; self-host
message attachments, official attachments, and future operator-hosted
audio/video must not be exposed by adding broad remote media origins. If a
self-host wants video or audio attachments later, treat that as a new native
media delivery and CSP/security-review project, not a bucket-policy-only
configuration change.

### MinIO Bucket Behavior

The bundled self-host template uses a single MinIO bucket for both public media
and protected message attachments. The bucket root is not public. Instead, the
bootstrap applies an anonymous `GetObject` policy only to public media prefixes.

This means a browser may read objects such as `avatars/...`, `server-icons/...`,
`emojis/...`, or `stickers/...` directly from the configured public media origin, but it must
not be able to read `attachments/...` object keys. Message attachments are
stored in the same bucket, but clients receive authenticated
`/api/media/attachments/{id}` URLs. The backend checks channel or DM visibility
before streaming those attachment objects.

The bundled MinIO template allows anonymous `GetObject` only for these public
prefixes:

- `avatars/*`
- `banners/*`
- `member-list-banners/*`
- `server-icons/*`
- `server-banners/*`
- `bot-avatars/*`
- `bot-banners/*`
- `bot-uploads/*`
- `emojis/*`
- `stickers/*`

Do not grant anonymous bucket-wide download. Do not grant anonymous access to
`attachments/*`, including encoded variants such as `%61ttachments/*` or
`attach%6dents/*`. If you use Caddy, Nginx, a bucket website, or a CDN in front
of object storage, its route/matcher policy must enforce the same prefix
boundary. Split public/private buckets are preferred when your provider cannot
express this boundary safely.

After deployment, run the self-host media deployment check from the repository
root with Node.js 20 or newer. This command validates `/health`,
`/api/instance`, the expected non-official instance mode, the public media
origin advertised by `cdnUrl`, raw attachment denial, unauthenticated attachment
API denial, and at least one public media sample:

```bash
bun run check:selfhost-media-deployment -- \
  --api-base-url https://your-domain.example \
  --expect-mode standalone \
  --attachment-key attachments/<channel-id>/<attachment-id>.webp \
  --attachment-id <attachment-id> \
  --sample-url avatars/<user-id>/<file-id>.webp
```

If your public media origin is separate from the API origin and not accurately
published as `/api/instance.cdnUrl`, pass it explicitly:

```bash
node deploy/check-selfhost-media-deployment.mjs \
  --api-base-url https://api.your-domain.example \
  --media-base-url https://media.your-domain.example \
  --expect-mode standalone \
  --attachment-key attachments/<channel-id>/<attachment-id>.webp \
  --attachment-id <attachment-id> \
  --sample-url avatars/<user-id>/<file-id>.webp
```

The script must report HTTP 4xx for raw `attachments/*` object paths, encoded
attachment-path variants, and unauthenticated `/api/media/attachments/{id}`.
A HTTP 2xx or 3xx for any
forbidden path means the deployment is publicly exposing protected message
attachments. The script retries forbidden paths with a full GET after a denied
range request, so a proxy that blocks ranges but serves full objects still fails.
`node deploy/check-media-exposure.mjs` remains available for narrow provider or
CDN debugging, but release acceptance should use the self-host deployment check
or `bun run release:acceptance`.

## Database Role Split

Do not run all database traffic through the table-owner role.

- `DATABASE_URL` uses the owner/migration login, `db_owner` in the template.
- `MIGRATION_DATABASE_URL` also uses the owner/migration login and is used for startup migrations.
- `DATABASE_APP_URL` uses the separate runtime login, `app_runtime_login` in the template.
- `app_runtime_login` is granted the NOLOGIN `app_runtime` role by `deploy/selfhost/postgres/init/001-create-app-role.sh`. Override both with `POSTGRES_APP_LOGIN` and `POSTGRES_APP_ROLE` if needed.
- The runtime role is also attached to the migration-managed RLS base role so it inherits the grants applied by existing migrations.
- `DATABASE_APP_URL` must not equal `DATABASE_URL`.

The split matters because request paths that use row-level-security helpers need a constrained runtime role. Table-owner connections can bypass policies.

## Email Stance

The compose template defaults to `EMAIL_PROVIDER=disabled`. That is suitable for private or invite-only testing, but production public registration should use a real email provider and verified sender domain before enabling public signup or requiring email verification. Without email delivery, users cannot reliably complete verification or password recovery flows.

## Configure

From the repository root:

```bash
cp deploy/selfhost/.env.example deploy/selfhost/.env
```

Edit `deploy/selfhost/.env`:

- Replace all local/example passwords and secrets.
- Generate a random `JWT_SECRET` with at least 32 characters.
- Keep `POSTGRES_PASSWORD` and `POSTGRES_APP_PASSWORD` different.
- Keep `DATABASE_URL`/`MIGRATION_DATABASE_URL` on the owner role.
- Keep `DATABASE_APP_URL` on `POSTGRES_APP_LOGIN`.
- Set `INSTANCE_PUBLIC_URL`, `INSTANCE_API_URL`, `INSTANCE_WS_URL`, `INSTANCE_DOCS_URL`, and `CORS_ORIGIN` to your real HTTPS origins. For the desktop client, include the Tauri origins you support, usually `http://tauri.localhost`, `https://tauri.localhost`, and `tauri://localhost`.
- Keep `S3_ENDPOINT=http://minio:9000` for the bundled MinIO service, or point `S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY`, and `S3_SECRET_KEY` at another S3-compatible provider.
- Keep `STORAGE_PATH_STYLE=true` for MinIO.
- Set `CDN_BASE_URL` to the public URL that serves profile, server, bot, emoji, and sticker media. Message attachment object keys must stay off public CDN/proxy matchers and should only be served by the authenticated `/api/media/attachments/{id}` route.
- Run `bun run check:selfhost-media-deployment -- --api-base-url <api-origin> --expect-mode <standalone|linked|federated> --attachment-key <private-key> --attachment-id <id> --sample-url <public-media>` after every reverse-proxy, bucket-policy, CDN, or `/api/instance.cdnUrl` change. For split media/API deployments where metadata is not authoritative yet, add `--media-base-url <media-origin>`.

## Release Acceptance

Before publishing a self-host build or opening a public test instance, run the
tracked release acceptance harness from the repository root with real canaries:

```bash
bun run release:acceptance -- \
  --profile selfhost \
  --full \
  --live \
  --base-url https://your-domain.example \
  --selfhost-expect-mode standalone \
  --attachment-key attachments/<channel-id>/<attachment-id>.webp \
  --attachment-id <attachment-id> \
  --sample-url avatars/<user-id>/<file-id>.webp
```

The harness checks client/Tauri version agreement, server-rs migration checksum
drift, native transport, deploy guardrail tests, self-host compose config when
`deploy/selfhost/.env` exists, self-host `/health` plus `/api/instance` mode,
and strict media exposure. `--selfhost-expect-mode` must match your instance
mode (`standalone`, `linked`, or `federated`) so this gate cannot pass against
an official-mode backend by mistake. Manual gates for custom network selection,
login/register, upload surfaces, protected attachments, public media proxy
rendering, and scanner/capability copy are printed in the command output and
documented in `docs/RELEASE_ACCEPTANCE.md`.

For a whole-system release pass that compares the official and self-host paths
together, use the e2e gate from the repository root:

```bash
bun run release:acceptance -- \
  --e2e \
  --profile both \
  --media-base-url https://<official-public-media-origin> \
  --api-base-url https://<official-api-origin> \
  --selfhost-base-url https://your-domain.example \
  --selfhost-expect-mode standalone \
  --attachment-key attachments/<channel-id>/<attachment-id>.webp \
  --attachment-id <attachment-id> \
  --sample-url avatars/<user-id>/<file-id>.webp \
  --selfhost-attachment-key attachments/<channel-id>/<attachment-id>.webp \
  --selfhost-attachment-id <selfhost-attachment-id> \
  --selfhost-sample-url avatars/<user-id>/<file-id>.webp
```

The e2e gate also checks the self-host `/health` and `/api/instance` endpoints
and runs a separate self-host strict media exposure check. For split self-host
media/API origins, replace `--selfhost-base-url` with
`--selfhost-media-base-url` plus `--selfhost-api-base-url`. It prints manual
gates for backend switching, account linking/revocation, protected
DM/text-channel attachments, public media proxy rendering, and ZDT reconnect
behavior.

## Start And Stop

Validate the base stack:

```bash
docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/.env config
```

Validate the optional voice profile:

```bash
docker compose --profile voice -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/.env config
```

Start the base stack:

```bash
docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/.env up -d
```

Start with LiveKit voice:

```bash
docker compose --profile voice -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/.env up -d
```

Check health and logs:

```bash
docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/.env ps
docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/.env logs -f app
curl http://127.0.0.1:3001/health
```

Stop containers without deleting data:

```bash
docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/.env down
```

Stop and delete local data volumes:

```bash
docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/.env down -v
```

## LiveKit Voice

Voice is optional. To enable it:

1. Set `INSTANCE_CAP_VOICE_CHAT=true`.
2. Set `LIVEKIT_URL` to the public WebSocket URL clients can reach, for example `wss://voice.example.com`.
3. Set `LIVEKIT_API_URL` to the private URL reachable by the app container, usually `http://livekit:7880` in this compose stack.
4. Replace `LIVEKIT_API_KEY` and `LIVEKIT_API_SECRET`. The secret must be non-placeholder random text at least 32 characters long.
5. Start compose with `--profile voice`.

LiveKit needs TCP signaling and media fallback plus UDP media reachability. The
template exposes `7880/tcp` on localhost for signaling, `7881/tcp` for ICE/TCP,
and `7882/udp` for ICE/UDP mux. In production, place signaling behind TLS and
open the media ports required by your network design.

Desktop clients do not connect renderer JavaScript directly to arbitrary
self-host LiveKit signaling origins. When `capabilities.voiceChat=true`, the
client asks Rust native transport to call this self-host backend's
`/api/channels/{id}/voice/join`; Rust validates the returned `LIVEKIT_URL` and
exposes a localhost-only signaling proxy to the renderer. Keep `LIVEKIT_URL`
as a base WebSocket URL without credentials, query strings, or fragments. Use
`wss://...` on a publicly routable host for real deployments; private,
reserved, or localhost LiveKit hosts are accepted only when the API backend
itself is local development. `ws://localhost` is only for local testing.
Video/camera UI is still a separate client feature even though LiveKit room
tokens can carry video grants.

## Backups

Back up at least these volumes or migrate them to managed services:

- `postgres-data`
- `redis-data`
- `minio-data`

Test restores before relying on backups. Postgres and object storage backups must be coordinated closely enough that database rows do not point at missing objects after restore.
