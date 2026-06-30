# Verdant Self-Host Compose

This directory contains a practical single-host Docker Compose stack for the Rust server, Postgres, Redis, MinIO, and optional LiveKit voice.

Read the full guide first: [docs/SELF_HOSTING.md](../../docs/SELF_HOSTING.md).

## Quick Start

From the repository root:

```bash
cp deploy/selfhost/.env.example deploy/selfhost/.env
```

Edit `deploy/selfhost/.env` before starting the stack:

- Replace `JWT_SECRET`, `POSTGRES_PASSWORD`, `POSTGRES_APP_PASSWORD`, `MINIO_ROOT_PASSWORD`, and `S3_SECRET_KEY`.
- Keep `DATABASE_URL`/`MIGRATION_DATABASE_URL` on the owner role and `DATABASE_APP_URL` on the `POSTGRES_APP_LOGIN` runtime role; they must not be equal.
- Set `INSTANCE_PUBLIC_URL`, `INSTANCE_API_URL`, `INSTANCE_WS_URL`, and `CORS_ORIGIN` to the real HTTPS origins for production. Include the desktop client origins you support, usually `http://tauri.localhost`, `https://tauri.localhost`, and `tauri://localhost`.
- Set `CDN_BASE_URL` to the origin that serves only public media prefixes. Do not serve raw `attachments/*` object keys from this origin.
- For voice, set `INSTANCE_CAP_VOICE_CHAT=true`, `LIVEKIT_URL`, `LIVEKIT_API_URL`, `LIVEKIT_API_KEY`, and a random `LIVEKIT_API_SECRET` at least 32 characters long, then expose the LiveKit TCP/UDP ports through your firewall. `LIVEKIT_URL` should be a base WebSocket URL; desktop clients connect through a Rust-owned localhost signaling proxy rather than broad renderer CSP.

Validate the rendered compose file:

```bash
docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/.env config
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

Stop the stack:

```bash
docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/.env down
```

Delete local data volumes only when you intend to reset the instance:

```bash
docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/.env down -v
```

## Deployment Check

After configuring a reverse proxy and starting the stack, verify the public
operator metadata before testing clients:

```bash
curl -fsS https://api.example.com/api/instance | jq '{name, mode, serverVersion, minClientVersion, uploadPolicy, contentScanning, capabilities}'
```

The test droplet should report `mode=standalone`,
`uploadPolicy=media_validation_only`, and
`contentScanning.provider=none` / `contentScanning.enabled=false` unless you
intentionally configured a scanner. Clients must describe that as file type/size
validation with no automatic scanner reported.

Official instances still force email verification when public registration is
enabled. Standalone self-host test instances may disable verification explicitly
with `REQUIRE_EMAIL_VERIFICATION=false` and `EMAIL_PROVIDER=disabled`.

Self-host stacks do not need to publish `updates/latest.json`. When the updater
manifest is absent, non-official instances return `UPDATE_NOT_CONFIGURED`
instead of treating it as a server fault.

## Media Exposure Check

This check uses the Node scripts in `deploy/`; run it with Node.js 20 or newer
from your workstation, CI runner, or the deployment host.

After deployment, run the live self-host media deployment check with a real
private attachment canary, its matching attachment API id, and at least one
public avatar/server/emoji/sticker sample:

```bash
bun run check:selfhost-media-deployment -- \
  --api-base-url https://api.example.com \
  --expect-mode standalone \
  --attachment-key attachments/<channel-id>/<attachment-id>.webp \
  --attachment-id <attachment-id> \
  --sample-url avatars/<user-id>/<file-id>.webp
```

The checker validates `/health`, `/api/instance`, the expected non-official
mode, and the media origin advertised by `cdnUrl`. It then verifies public media
still reads while raw `attachments/*`, encoded attachment paths, Cloudflare
image-transform attachment paths, and unauthenticated
`/api/media/attachments/{id}` are denied.

If your API and media/CDN use different public origins and `/api/instance.cdnUrl`
is not authoritative yet, add `--media-base-url`:

```bash
node deploy/check-selfhost-media-deployment.mjs \
  --api-base-url https://api.example.com \
  --media-base-url https://media.example.com \
  --expect-mode standalone \
  --attachment-key attachments/<channel-id>/<attachment-id>.webp \
  --attachment-id <attachment-id> \
  --sample-url avatars/<user-id>/<file-id>.webp
```

The live canary check must pass before enabling public self-host access with
`INSTANCE_CAP_FILE_SHARING=true` and `INSTANCE_CAP_MESSAGE_ATTACHMENTS=true`. A
failure on `attachments/*`, `%61ttachments/*`, or `attach%6dents/*` means the
bucket, reverse proxy, or CDN is exposing protected message attachments. The
lower-level `node deploy/check-media-exposure.mjs` remains available for narrow
provider debugging.
