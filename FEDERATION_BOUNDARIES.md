# Verdant Federation Boundaries

This document is the working security and product boundary for official-network,
self-host, linked, and future federated Verdant deployments. Update it whenever
the boundary changes.

For client CSP, Rust IPC transport, and token ownership hardening, see
[Security Hardening Notes](SECURITY_HARDENING.md).

## Current Position

Unofficial/self-hosted servers must not send runtime events, messages, presence,
voice state, moderation actions, media delivery, uploads, REST reads/writes, or
database writes into the official Verdant backend. The official backend must not
proxy, relay, route, persist, inspect, or broadcast self-host runtime traffic.

The official network is not a shared broadcast bus for self-hosted servers.
Self-hosted servers own their own data plane:

- Accounts created on that server.
- Servers, channels, messages, uploads, roles, invites, and moderation state.
- Local storage, billing, rate limits, upload limits, and operator policy.
- Local fanout/broadcast infrastructure for their own members.

The official network may later provide visibility and trust metadata:

- Discovering public self-hosted communities.
- Linking to a self-hosted server invite.
- Showing that a local self-hosted account is linked to an official identity.
- Publishing verified instance metadata such as domain, display name, server
  version, and capability manifest.

Federation/linking starts as metadata and identity, not message federation.
The desktop client may open direct native transports to multiple joined
networks, but the official backend remains out of the self-host runtime path.

Verdant's product model is now the server/community-owned backend model:

- The backend that owns a server, channel, DM, role, member row, upload, or
  moderation state is the source of truth for that runtime data.
- A user sending a message in a server owned by Backend B sends to Backend B
  through the client joined-network transport. Backend B authorizes, persists,
  and fans out the message.
- Backend A, even if it is the user's home or linked identity backend, must not
  store Backend B-owned messages, uploads, roles, channels, moderation state,
  or runtime traffic.
- The sender waits for the owning backend's persistence acknowledgement, not
  for every trusted peer to receive optional S2S metadata.
- S2S exists for signed discovery/invite metadata, principal projection,
  membership handshakes, and revocation/permission notifications. It is not a
  runtime write path.

Current federation runtime foundation:

- `POST /api/federation/v1/events` accepts signed S2S event envelopes from
  locally trusted peers.
- Accepted event kinds are metadata and membership handshakes:
  `invite_preview`, `principal_upsert`, `membership_join`,
  `membership_leave`, `membership_remove`, `membership_ban`, and
  `membership_unban`.
- Cross-backend runtime persistence events such as messages, reactions, DMs,
  channel/category/role mutation, emoji mutation, read-state, presence, and
  typing are rejected before command conversion, inbound event storage, or
  runtime application.
- Custom emoji/sticker sharing is not an emoji mutation event stream. It is an
  explicit import/copy operation initiated against the receiving server; the
  receiving backend must fetch only trusted peer media, rerun validation and
  scanning, store an owned local public-media object or digest-deduped asset,
  and keep source provenance as audit/display metadata only.
- `principal_upsert` creates or updates a disabled local projection for the
  remote principal. It does not create login-capable local credentials,
  sessions, or account-link authority.
- `membership_join` requires an active remote-principal projection and a real
  local invite code for the target server. The owning backend applies the same
  invite expiry, use-cap, deleted-server, ban, member-cap, existing-membership,
  `MEMBER_JOIN`, bot-event, and welcome-message paths as local invite accept.
- `membership_leave` allows an active remote-principal projection to remove
  only itself from a local server it already joined.
- `membership_remove`, `membership_ban`, and `membership_unban` require an
  active remote moderator projection on the target local server and local
  moderation permission. Member ejection reuses hierarchy checks, local role
  cleanup, audit logging, bot events, and `MEMBER_REMOVE` / `SERVER_DELETE`
  fanout. These events do not grant server administration.
- Replay nonces and inbound event IDs are stored durably in local Postgres.
- Outbound S2S metadata and membership handshakes use a local durable outbox
  with bounded JSON event envelopes, payload hashes, row-locked claims, S2S
  Ed25519 signing, sanitized retry/dead-letter metadata, and no
  credential/session material. The dispatcher starts only when local S2S
  signing configuration is complete.
- Cross-backend runtime persistence events such as messages, reactions, DMs,
  channel/category/role mutation, emoji mutation, read-state, presence, and
  typing are not accepted under the server-owned backend model and are not
  inserted into the outbound outbox.
- Outbound producers are isolated under `server-rs/src/federation/producer.rs`.
  They check the server-owned runtime policy before peer-route lookup or
  outbox insertion, build typed envelopes only for allowed metadata or
  membership actions, select active `federation_peer_routes` for those allowed
  scopes, enqueue durable outbox rows, and refuse inbound rebroadcast attempts.
- `federation_peer_routes` is a local visibility subscription table. Active
  peer keys are required for delivery, but peer keys alone never authorize
  outbound event visibility. Federated membership joins grant server and
  existing text-channel routes for the source peer, and federated leaves revoke
  them.
- Outbound delivery resolves the destination peer through the active peer-key
  endpoint for that exact `destination_peer_id`. For `host:<domain>` peer IDs,
  the signed request may target only that host or a subdomain API origin; a
  lookalike route such as `verdant.chat.evil.com` must fail before delivery.

## Hard Trust Boundaries

These systems are official-internal only and must not be exposed to unofficial
servers:

- Redis pub/sub topics.
- NATS cross-region mesh.
- Postgres or database replication.
- LiveKit control-plane credentials.
- Cloud provider, DNS provider, payment provider, storage provider, or operator
  automation tokens.
- ZDT/orchestrator management actions.

`server-rs` enforces this for the current NATS bridge: cross-region NATS startup
is allowed only when `INSTANCE_MODE=official`. `standalone`, `linked`, and
`federated` modes must not join the official NATS mesh even if NATS environment
variables are present.

## Instance Modes

- `official`: First-party Verdant network. May use official billing, official
  cross-region NATS, official Redis, official storage, official orchestration,
  and official moderation/trust decisions.
- `standalone`: Self-hosted, fully local, no official-network dependency.
- `linked`: Self-hosted instance that can optionally link a local account to an
  official Verdant account for identity/trust display.
- `federated`: Future mode for approved server-to-server metadata exchange.
  This does not imply access to official runtime transport or official data.

`linked` and `federated` are still untrusted external modes from the official
network's perspective.

## Client Model

The client should support choosing a backend API/WS origin, for example:

- Official: `https://api.verdant.example`
- Self-hosted: `https://api.community.example`

Before login or registration, the client should fetch the backend's instance
metadata endpoint and show enough context for the user to understand where the
account will live:

- Instance name.
- Instance mode.
- Server version and minimum client version.
- Public URL/domain.
- Upload policy, scanner provider/status, and advertised capabilities.
- Whether the instance is official, standalone, linked, or federated.
- Whether official-account linking is available.

Accounts are scoped to their joined network. Creating an account on a
self-hosted server creates a local account on that self-hosted server, not an
official Verdant account. A user may use the same client binary for multiple
networks, but sessions, local caches, WebSocket state, media policy, and IDs must
remain separated by `networkId`.

Current single-transport implementation direction:

- The user selects an API origin, not an arbitrary WebSocket URL.
- API origins are normalized to origins only; paths, query strings, fragments,
  embedded credentials, and non-localhost plain HTTP are rejected.
- The WebSocket URL is derived from the selected API origin as `/ws`.
- The client reads `/api/instance` from the selected backend before using it.
- Browser fallback token storage is scoped by backend origin.
- Desktop keyring tokens record the backend origin and are ignored when the
  selected backend does not match.
- Switching backend origins logs out the current local session before applying
  the new backend.

This intentionally prevents a self-hosted server from injecting an arbitrary
official runtime transport URL into the client.

Long-term implementation direction:

- Joined networks are not user-facing backend toggles in settings.
- The client rail opens joined networks and eventually shows a merged live list.
- The local joined network registry stores display metadata and cached UI
  availability/auth labels only. It does not store tokens and does not prove a
  user is authenticated to that network.
- Rust native transport owns one direct API/WS transport per authenticated
  joined network.
- Native events, REST calls, media cache entries, and merged store entities are
  tagged by `networkId`.
- Raw backend IDs are never treated as globally unique.
- The official backend never acts as the transport relay for self-host runtime
  data.
- Network, community, and username display names are never identity or trust
  inputs. The client derives network identity from the actual normalized API
  origin it connected to, caches only non-secret instance identity facts, and
  disambiguates risky surfaces with backend origin or trust status when names
  collide or metadata looks spoofed.
- Inactive joined networks may release their WebSocket and poll a direct,
  authenticated, owning-backend `/api/sync/summary` endpoint for unread,
  mention, latest-activity, cursor, and reconnect metadata only. That poll is
  not S2S federation, not an official relay, and not a content replication feed.
  It must not return message bodies, attachment URLs, member lists, presence
  maps, relationship graphs, role data, profile media, or arbitrary runtime
  events.

## Account Linking Model

Official accounts and self-hosted accounts are separate until the user links
them.

The expected linking flow is OAuth/OIDC-style:

1. The user starts linking from a self-hosted server or from the official network.
2. The self-hosted instance sends the user to the official network with an
   instance identifier, callback URL, nonce/state, and requested scopes.
3. The official network authenticates the user and asks for consent.
4. The official network returns a short-lived authorization code to the registered
   self-host callback.
5. The self-host exchanges the code for a scoped proof token or link result.
6. The self-host stores the minimum mapping needed:
   `self_host_instance_id + local_user_id <-> official_user_id`.

Never share official passwords, official session cookies, broad bearer tokens, or
database credentials with a self-hosted instance. Link tokens must be scoped,
audience-bound to the specific instance, short-lived where possible, replay
protected, and revocable from the official network.

Unlinked self-host users remain valid local users. Official users are not
automatically members of a self-hosted server.

Current implementation foundation:

- `/api/account-links/intents` creates short-lived local link intents on
  `linked`/`federated` self-hosts with a configured official verify key.
- `/api/account-links/proofs` lets an authenticated official user mint an RS256
  identity proof only on `INSTANCE_MODE=official` with a configured signing key
  and a verified federation registry audience.
- `/api/account-links/complete` verifies the proof audience, state hash, expiry,
  issuer, and scopes before storing a local identity mapping.
- `/api/account-links/{linkId}` revokes only links owned by the current local
  user.
- Desktop native transport stores credentials in Rust-derived backend-scoped
  keyring entries so official and self-host sessions can coexist during consent.
- Stored link data is metadata only and must not be used as local authorization.

## Discovery and Invites

Official-network discovery may index public self-hosted communities, but the
official backend should treat all self-host metadata as untrusted until verified.

Minimum controls before public discovery:

- Stable instance ID.
- Public signing key.
- Domain verification.
- Capability manifest.
- Version/release channel.
- Abuse contact or operator identity where required.
- Revocation/suspension path.
- Rate limits and audit logs for discovery/link endpoints.

Current implementation foundation:

- `GET /api/federation/manifest` is public and self-reported.
- `GET /api/federation/discovery` lists only official-registry rows that are
  both verified and public.
- `/api/admin/federation/*` registry mutations are official-mode only and require
  the HMAC `FEDERATION_REGISTRY_ADMIN_SECRET`.
- Domain verification is manual in this foundation PR. The admin create endpoint
  returns DNS TXT and HTTP well-known challenges, stores only a token hash, and
  does not perform outbound verification requests yet.
- A verified discovery record still does not grant runtime access to official
  Redis, NATS, Postgres, LiveKit, storage, billing, or orchestration.

Official search can return a self-hosted invite or community profile, but joining
that server happens against the self-hosted server's API. The self-hosted server
owns admission, account creation, local policy, messages, and storage.

## Things Not To Build Yet

Do not implement these as first federation steps:

- Cross-server chat/message federation.
- Automatic syncing of self-hosted messages into the official database.
- Home-backend storage of another backend's server/community runtime data.
- Official Redis/NATS topics consumed by self-hosted servers.
- Shared global moderation actions that directly mutate self-hosted state.
- Official billing entitlements that automatically grant self-hosted resources.

These may be reconsidered later only with a new threat model and narrow protocol
design.

## Implementation Checklist

Before changing self-host, federation, linking, client backend selection, or
transport code:

- Confirm whether the change touches official-internal transport.
- Keep Redis/NATS/Postgres/LiveKit control planes private to official mode.
- Fail closed for `standalone`, `linked`, and `federated`.
- Keep official and self-host account/session/cache state separated by backend.
- Namespace merged client entities by `networkId + localId`; raw backend IDs are
  not globally unique.
- Reject designs that route self-host runtime traffic through the official
  backend.
- Treat self-host metadata as untrusted until signed and verified.
- Add tests for any new mode gate or trust boundary.
- Update this document if the boundary changes.
