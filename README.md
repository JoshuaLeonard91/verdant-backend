# Verdant Backend

Verdant Backend is the Rust server for running a Verdant self-host instance.
It provides the API, WebSocket runtime, authentication, roles, channels,
messages, media metadata, custom emoji and sticker catalogs, and the
self-hosting deployment template.

This repository is a public source split from the private Verdant development
workspace. It is intended for self-host operators, contributors, and release
review. Private infrastructure tooling, production runbooks, local live-test
harnesses, and secrets are intentionally not part of this repository.

## What Is Included

- `server-rs/`: the Rust backend service.
- `proto/`: protocol definitions required by the backend build.
- `deploy/selfhost/`: a single-host Docker Compose template for Postgres,
  Redis, MinIO-compatible storage, and optional LiveKit voice.
- `docs/SELF_HOSTING.md`: self-host setup and operational guidance.
- `docs/OPEN_SOURCE_FEDERATION_GOALS.md`: public architecture goals for
  self-hosting and future federation.
- `FEDERATION_BOUNDARIES.md` and `SECURITY_HARDENING.md`: public security
  boundaries that should remain true for self-host and federation work.

## Local Backend Development

Install Rust stable and run the backend tests from the repository root:

```powershell
cargo test -j 2 --manifest-path server-rs/Cargo.toml --lib
```

Build the backend binary:

```powershell
cargo build --locked --release --manifest-path server-rs/Cargo.toml --bin verdant-server
```

## Self-Hosting

The self-host template is documented in
[`docs/SELF_HOSTING.md`](docs/SELF_HOSTING.md) and
[`deploy/selfhost/README.md`](deploy/selfhost/README.md).

At a high level, a production self-host needs:

- a DNS name and TLS reverse proxy
- Postgres
- Redis or Valkey
- S3-compatible object storage
- optional LiveKit voice
- scheduled backups for database, media, and configuration

The bundled Compose template is suitable for development and small single-host
deployments after configuration review.

## Releases

Public backend releases are built by GitHub Actions from immutable `v*.*.*`
tags. The release workflow builds and tests the backend, packages the Linux
x64 binary with migrations, writes checksums, and publishes release assets with
GitHub artifact attestation.

Do not move or overwrite release tags after publication.

## Security

Self-host instances own their local data plane. The official Verdant network
must not proxy, relay, persist, or inspect self-host runtime traffic.

Message attachments must stay behind authenticated API routes. Public media
storage may expose profile images, server media, bot images, emoji, and
stickers, but must not expose raw `attachments/*` object keys.

Report security issues through GitHub private vulnerability reporting when
available.
