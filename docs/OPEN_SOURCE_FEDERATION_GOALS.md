# Open Source And Federation Goals

This document explains the intended direction for the Verdant self-host distribution. It is a product and architecture goals document, not a promise that every item is implemented today.

The short version: Verdant should be open source enough for people to run their own independent servers, while the official Verdant network remains a managed service with its own identity, moderation, billing, and operational policies. A self-hosted server should work without the official network. If a server operator and user choose to connect to the official network later, that connection should be explicit, inspectable, revocable, and scoped.

## Why This Exists

People asking for open source usually want more than source code. They want the ability to:

- Run the app without depending on a single hosted provider.
- Inspect the client and server that handle their identity, messages, uploads, and voice sessions.
- Keep control of their data, backups, moderation rules, and uptime.
- Modify or extend the system for their own community.
- Trust that the official network cannot silently become the only place the software works.

The self-host distribution is meant to answer those needs without turning the official Verdant service into an unbounded support, abuse, or billing dependency for every third-party server.

## Guiding Principles

1. Self-hosted servers must be useful in standalone mode.
2. Official-network connection must be optional and explicit.
3. Local server accounts and official-network accounts must be separate identities until a user links them.
4. A linked account must use scoped tokens and clear user consent, not shared passwords or database access.
5. Self-host operators own their local policies, resource limits, backups, and moderation decisions.
6. The official network keeps control of official billing, official abuse response, official identity reputation, and official network access.
7. Federation should be protocol-driven, versioned, and additive. It should not depend on private tooling from the original repository.
8. Security controls must be enforced by the protocol and server authorization checks, not by client trust alone.

## Distribution Model

Verdant should support four high-level instance modes:

| Mode | Purpose |
| --- | --- |
| `official` | The managed Verdant network operated by the Verdant team. This is the only mode that may expose official Stripe billing routes. |
| `standalone` | A self-hosted instance with local accounts, local data, local moderation, and no dependency on the official network. This should be the default self-host mode. |
| `linked` | A self-hosted instance that allows users to link a local account to an official Verdant account for official-network identity, entitlement, or trust features. |
| `federated` | A self-hosted instance that participates in a future server-to-server federation protocol with the official network and possibly other approved peers. |

The current self-host bundle defaults to `INSTANCE_MODE=standalone`, `BILLING_MODE=disabled`, `CONTENT_SCAN_PROVIDER=none`, and local/operator-managed capabilities.

## Identity And Auth

Self-hosting requires a clean split between local identity and official-network identity.

A standalone server should have its own user table, sessions, roles, permissions, server membership, message history, uploads, and admin controls. Creating an account on a self-hosted server should not require signing up for the official Verdant network.

If official-network linking is added, the expected flow is:

1. A user signs into their local self-hosted account.
2. The user chooses to link an official Verdant account.
3. The official network performs an OAuth/OIDC-style consent flow.
4. The self-hosted server receives a scoped link token, not the user's official password.
5. The self-hosted server stores only the minimum official identity metadata needed for the linked feature.
6. The user can unlink later, and the official network can revoke the link.

The link should not merge databases. It should create an explicit mapping:

```text
self_host_instance_id + local_user_id <-> official_network_user_id
```

That mapping can support official identity display, trust signals, entitlement checks, or future federation routing, but local authorization must still be enforced by the local server.

The current foundation stores this mapping through authenticated
`/api/account-links` endpoints using short-lived state-bound intents and RS256
official identity proofs. The consent flow requires verified proof audiences
and backend-scoped native credentials. Official proof grants are revocable
through opaque proof-hash status polling.

## Standalone Servers

A standalone server must continue working when it never connects to the official network. At minimum, that means:

- Local registration or invite-only account creation.
- Local login, sessions, two-factor auth where supported, and password reset when email is configured.
- Local servers, channels, roles, permissions, messages, reactions, uploads, bots, and voice configuration.
- Local instance capability settings such as image uploads, animated avatars, video streaming, voice bitrate, and file sharing.
- Local storage using Postgres, Redis, S3-compatible object storage, and optional LiveKit.
- Local admin responsibility for backups, abuse handling, content policy, legal compliance, and uptime.

Standalone mode should not call official billing, official content scanning, Cloudflare Workers, private deployment tooling, or private operator services.

## Official Network Linking

Linking to the official network should be valuable but not required.

Potential linked-mode features include:

- Showing that a local account is linked to an official Verdant identity.
- Letting official-network users carry a stable identity or profile marker into linked self-hosted communities.
- Checking official entitlements where a self-host operator chooses to recognize them.
- Allowing official-network trust, abuse, or reputation signals to inform local policy.
- Enabling future cross-server discovery, invites, or routing through a federation API.

Linked mode must stay opt-in for both sides:

- The self-host operator chooses to enable official-network linking.
- The user chooses to link an official account.
- The official network chooses which instance capabilities and API scopes it will trust.

The official network should be able to deny, suspend, or revoke a linked instance without breaking that instance's standalone local operation.

## Federation API Direction

Federation should start as a narrow API surface and grow only when the trust model is clear.

Early federation building blocks should include:

- Instance discovery: public metadata for name, public URL, API URL, WebSocket URL, version, mode, and capabilities.
- Instance identity: a stable instance ID and public signing key.
- Domain verification: proof that an instance controls the domain it claims.
- Capability manifest: explicit flags for uploads, voice, video, file sharing, max upload size, max voice bitrate, content scanning stance, and registration policy.
- Version negotiation: protocol version and minimum compatible client/server versions.
- Link handshake: a scoped, revocable way to bind a local account to an official-network account.
- Audit trail: local logs for linking, unlinking, federation token issuance, and federation failures.

Current backend foundation:

- Runtime ingress currently supports `invite_preview` audit records,
  non-login-capable remote-principal projection through `principal_upsert`, and
  invite-scoped `membership_join` for remote principals that present a real
  local invite code and pass the owning backend's local invite, ban, cap, and
  membership checks. `membership_leave` now lets remote principals remove only
  themselves from local servers they already joined. Permissioned
  `membership_remove`, `membership_ban`, and `membership_unban` now let remote
  moderator projections apply local kick/ban semantics after the receiving
  backend checks local moderation permissions, hierarchy, owner/self targets,
  target existence, audit logging, and normal member ejection fanout.
  The server-owned backend model now keeps runtime persistence outside S2S.
  Member-role, role, category, channel, override, presence, typing, read-state,
  reaction, message, pin, DM, relationship, and emoji runtime events remain
  protocol inventory only and are rejected before inbound command conversion,
  inbound event storage, runtime application, outbound peer-route lookup, or
  outbound outbox insertion. Runtime writes go directly from the client to the
  backend that owns the server/community/DM. The outbound side retains durable
  bounded-envelope storage, signed S2S dispatch, retry/backoff, sanitized
  failure codes, and dead-letter status only for allowed metadata and
  membership handshakes when S2S signing is configured. Attachments, emoji
  upload/import, group-DM membership mutation, server administration, voice,
  and media events remain fail-closed until a separate reviewed design exists.

Federation should avoid broad database synchronization at first. Sharing full user, server, message, or upload state across instances creates hard moderation, privacy, deletion, legal, and abuse problems. The first useful protocol should prove identity, capabilities, and trust without copying more data than needed.

## Billing And Entitlements

Self-hosted servers must not expose official Stripe billing routes. The current direction is:

- `BILLING_MODE=official_stripe` is only valid for `INSTANCE_MODE=official`.
- Self-host modes use `BILLING_MODE=disabled`.
- Official subscriptions remain part of the official Verdant network.
- Self-host operators manage their own resource limits and local premium-like features.

This prevents a self-hosted server from bypassing or impersonating the official subscription system. It also avoids forcing self-host operators to use Verdant's payment stack.

If official entitlements become visible to linked self-hosted servers, they should be read-only, scoped, and optional. A self-host operator may choose to honor an official entitlement, but the operator still controls local costs and limits such as upload sizes, voice bitrate, video streaming, and storage quotas.

## Content Policy And Upload Safety

The self-host distribution should not claim automatic moderation when no scanner is configured. Today the self-host stance is:

- `CONTENT_SCAN_PROVIDER=none`
- `UPLOAD_POLICY=media_validation_only`

That means the server validates file type and size before storage, but it does not perform external abuse or illegal-content scanning. Operators are responsible for their own moderation, reporting, retention, and legal process.

Future federation should expose content policy as instance metadata. For example, an instance should be able to say whether uploads are disabled, locally moderated, externally scanned, or accepted under operator-managed policy. Other instances and clients can then make informed trust decisions.

## Client And Server Inspection

There has been discussion about requiring connected self-host servers or clients to pass binary hash inspection before using official-network features. The safer framing is build attestation and transparency, not blind trust in hashes.

Hash checks can help identify official builds, but they are not enough by themselves:

- Open source builds may vary by platform, compiler, dependency version, and build environment.
- A malicious server can lie about what binary it is running unless claims are signed and verified.
- A modified client can still speak the protocol unless the server enforces authorization and rate limits correctly.
- Hash inspection must never replace endpoint auth, membership checks, input validation, abuse controls, or scoped federation tokens.

A better long-term model is:

- Official releases are signed.
- Official clients publish build provenance when possible.
- Self-host servers expose version, commit, mode, capabilities, and federation compatibility metadata.
- Linked or federated mode may require an approved release channel, signed build, reproducible build proof, or operator registration.
- Standalone mode never requires official inspection.

This keeps official-network access defensible while preserving the right to run modified self-hosted software outside the official network.

## Security Boundaries

Federation creates new trust boundaries. The design must assume a self-hosted server can be honest, buggy, compromised, or intentionally hostile.

Required security properties:

- No official-network passwords are shared with self-hosted servers.
- Federation tokens are scoped, short-lived where possible, and revocable.
- Every federation endpoint validates authentication, authorization, input shape, rate limits, and replay risk.
- Local membership and permissions are checked by the local server for local resources.
- Official-network actions are checked by the official backend for official resources.
- Instance metadata is treated as untrusted until verified.
- User-visible errors avoid leaking account existence or sensitive federation state.
- Logs avoid secrets, tokens, private messages, and unnecessary PII.
- Cross-server features fail closed when verification or policy checks are unavailable.

The protocol should make the secure path the normal path. It should not depend on operators reading private runbooks or copying private infrastructure.

## What Is Intentionally Excluded

The self-host repository should not include everything from the private operational repository.

Excluded by design:

- Private deployment runbooks and infrastructure scripts.
- Official-network release signing automation.
- Private load-test harnesses and operator tools.
- Cloudflare Worker deployments.
- Official Stripe billing integration for self-host instances.
- External content scanner integrations that are not implemented or not safe to publish.
- Secrets, credentials, production configs, and private history.

Open source users can build their own tooling around the public client, server, protocol definitions, and deployment template.

## Admin And Operator Experience

Self-hosting should eventually include a small admin experience for common operator tasks. The first priority is safe configuration and visibility, not a large control panel.

Useful operator features include:

- Instance metadata and capability review.
- Registration mode and invite controls.
- Upload limits and storage usage.
- Voice enablement and LiveKit health.
- User moderation basics.
- Backup and restore guidance.
- Federation/linking status when those modes exist.
- Warnings when production settings are unsafe.

The admin surface must be protected by strong authentication and authorization. It should not expose secrets in the browser, logs, API responses, or exported diagnostics.

## Roadmap Shape

The safest path is staged:

1. Harden standalone self-hosting.
   - Keep the Docker Compose bundle reliable.
   - Keep `DATABASE_URL` and `DATABASE_APP_URL` role separation clear.
   - Keep Stripe, Cloudflare Workers, private tooling, and scanner claims out of self-host mode.
   - Verify upload, auth, WebSocket, voice, and backup paths.

2. Add official-network linking.
   - Add user consent, scoped tokens, revocation, instance metadata, and clear UI.
   - Keep standalone behavior intact when linking is disabled or unavailable.
   - Treat official entitlement data as optional metadata, not local authority.

3. Add narrow federation primitives.
   - Start with discovery, instance identity, domain verification, capability manifests, and version negotiation.
   - Avoid message or database federation until identity and trust are proven.

4. Expand federation carefully.
   - Add cross-server features only when moderation, privacy, deletion, abuse response, and protocol compatibility are designed.
   - Prefer additive protocol changes and minimum-client-version enforcement for breaks.

## Success Criteria

This direction is working when:

- A person can run Verdant privately without an official-network account.
- The official network can still operate as a managed service with paid features and abuse controls.
- A user can understand whether they are using a standalone, linked, federated, or official instance.
- Linking an account is explicit, reversible, and does not share passwords.
- Federation APIs are narrow, documented, versioned, and testable.
- Self-host operators can see their responsibilities clearly.
- Public source does not expose private secrets, private history, or private infrastructure assumptions.
