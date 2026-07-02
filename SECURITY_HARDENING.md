# Security Hardening Notes

This document tracks security boundaries that are easy to lose during self-host,
federation, and client transport work.

## Native Client Transport

Tauri desktop builds always use the native Rust transport. The old renderer
`fetch`/`WebSocket` path is only for non-Tauri localhost browser development
and is not a desktop rollback path.

When native transport is enabled:

- Tauri redacts access/session tokens from the old `get_tokens` IPC command.
- Rust owns backend preview/apply, auth, JSON REST, multipart REST, and
  WebSocket socket lifecycle.
- Renderer auth state uses `nativeSession` and must not depend on raw bearer
  tokens.
- Rust attaches bearer auth internally only when stored credentials match the
  active backend origin.
- Native WebSocket sends encode current client events as protobuf in Rust;
  renderer-supplied `IDENTIFY` is rejected because Rust owns the auth handshake.
- Native WebSocket resume state is updated by both full `READY` and
  `READY_DELTA`, and planned drain text frames are treated as planned reconnects
  even when the server omits an explicit retry delay.
- Native WebSocket runtimes use per-network generation tokens. Reconnect,
  replacement, backend-switch, and disconnect paths must invalidate older loops
  so stale tasks cannot emit status/events or reconnect after a newer loop owns
  that `networkId`.
- Desktop and server WebSocket protocol handling should stay on
  Axum/Tungstenite semantics. Do not manually turn protocol `Ping` frames into
  Verdant app binary frames; Verdant protobuf `PING`/`PONG` is the application
  heartbeat and is separate from RFC WebSocket control frames.
- Rust rejects absolute REST URLs, paths outside `/api`, path traversal, encoded
  separator/dot traversal sequences, fragments, backslashes, and control
  characters.
- Native REST and multipart requests carry abort IDs so renderer abort signals
  cancel the Rust request path instead of only hiding the response.
- Native auth startup waits for the renderer-selected backend profile to be
  applied in Rust before reading backend-scoped keyring credentials.
- Legacy raw token writes through `set_tokens` are disabled when native
  transport is compiled in; native auth commands are the only token writers.
- Desktop account-link pending intent handoff state is stored at rest in the OS
  credential store through fixed Rust IPC commands. Renderer code cannot choose
  the keyring service/account name, and Rust validates the self-host origin,
  official issuer, host-scoped audience, short TTL, ASCII state token, and
  `identity.basic` scope before writing. Desktop clears renderer `localStorage`
  pending-flow values instead of restoring or migrating them. Non-Tauri
  localhost browser development may still use `localStorage` for this non-token
  pending state.
- Official account-link proof issuance must bind both the `host:<hostname>`
  audience and the actual self-host API origin to the same verified federation
  registry record. Do not sign proofs when an unverified API origin asks for a
  verified audience.
- The developer settings tab exposes token-safe native diagnostics for canary
  testing: backend origin, derived WS URL, credential match, credential presence
  booleans, auth stage, pending 2FA, and renderer WS status. It must never show
  access tokens, session tokens, pending 2FA tickets, passwords, or raw keyring
  payloads.

Release-level acceptance should verify native transport, media boundaries,
client publish, and server release behavior together before publication.

## Self-Host Field Encryption

Single-VPS self-host deployments must keep `APP_FIELD_ENCRYPTION_KEY` outside
Postgres. The key is required for non-official instance modes and is used for
app-level encryption of sensitive database fields as those fields are migrated.
Do not log it, regenerate it during repair, or write it into database rows.

Detailed key handling, field inventory, migration, rotation, and operator
requirements live in `docs/SINGLE_VPS_FIELD_ENCRYPTION.md`.

## Multi-Network Client Boundary

The long-term client model is a local native multiplexer, not an official
runtime relay.

Hard requirements:

- The official backend must not proxy, relay, route, persist, inspect, or
  broadcast runtime traffic for self-hosted networks.
- Self-host REST, WebSocket, uploads, media delivery, messages, presence,
  moderation, voice state, and database state stay on the self-host data plane.
- The desktop client may connect directly to multiple joined networks, but each
  connection must be keyed by `networkId` and owned by Rust native transport.
- Rust derives native network IDs from normalized API origins and must reject
  mismatched `networkId` / API origin pairs before storing backend profiles,
  routing REST/media requests, reading backend-scoped credentials, or refreshing
  tokens. Only the pinned official API origin may use `networkId: "official"`.
- A renderer-supplied `networkId` must not be enough to create arbitrary native
  egress. Network-scoped REST, multipart, bytes, and media requests must use a
  Rust-registered backend profile; unregistered network IDs fail closed.
- Native WebSocket runtimes are keyed by registered `networkId` values. A
  self-host WebSocket cannot be opened, sent to, or disconnected unless Rust
  already has the matching backend profile for that network.
- Each native WebSocket runtime also owns a generation token. A down, slow, or
  replaced self-host socket must not leave an old loop able to mark the network
  unavailable, replay events, or reconnect after a newer loop has taken over.
- Inactive joined-network runtime polling is direct to the owning backend only.
  A summary request must use that backend's registered profile and stored
  credentials, must fail closed without credentials, and must never use the
  active backend or official backend as a fallback. The summary response is a
  content-free badge/reconnect feed: unread counts, mention counts, latest
  activity timestamps, cursor, and reconnect hint only. Message bodies,
  attachment URLs, member lists, presence maps, relationship graphs, role data,
  profile media, and arbitrary runtime events must stay out of this endpoint.
- Renderer-visible events, REST targets, media cache entries, and merged store
  records must be tagged by `networkId`.
- Renderer stores are untrusted local UI/cache state. A malicious local
  renderer, injected script, or modified client can try to edit Zustand state or
  call renderer helpers with forged tags, so backend and Rust native transport
  code must never authorize from renderer store contents. Server membership,
  roles, message access, uploads, moderation, and account-link trust must be
  enforced on the owning backend, and Rust must continue to require registered
  backend profiles before network-scoped egress. Do not treat local store
  immutability as a security control; assume store tampering is possible and
  make server-side authorization the enforcement point.
- Legacy active-backend REST and WebSocket helpers must reject scoped
  `networkId/localId` entity IDs. Scoped IDs are cache/UI identifiers until the
  call path is explicitly network-aware and passes a Rust-validated `networkId`.
- Network-aware server/channel/admin writes must derive the owning route from a
  scoped entity ID and must de-scope child IDs only when they belong to that
  same route. Cross-network role, member, bot, feed, channel, message, or emoji
  IDs must fail before REST is attempted. The client route helper is a
  correctness guard only; authorization still belongs to Rust profile
  registration plus the owning backend's membership, role, moderation, upload,
  and message-visibility checks.
- Scoped self-host invite links must not be flattened into official
  `verdant.chat/invite/*` links or bare codes. The invite link/deep link must
  preserve the owning API origin, and preview/accept must route through the
  matching joined network's native REST profile so invite secrets are not sent
  to the official backend or any unrelated active backend.
- Scoped DM creation, DM display-color writes, and scoped message search must
  route only through the owning joined network's native REST profile. Search
  author filters must belong to that same network, and returned messages must be
  scoped before entering renderer state.
- Relationship writes are network-aware. Scoped joined-network user IDs must
  resolve to their owning registered Rust backend profile, be de-scoped only
  for that backend's `/api/users/me/relationships*` routes, and must never be
  sent to official or to an unrelated active backend. The merged Friends view
  can aggregate all networks or apply a saved per-network filter, but each
  relationship edge remains owned and authorized by its backend.
- Protected message attachment URLs must be bound to the message owner's
  network API origin. A self-host message must not be able to trigger an
  authenticated official `/api/media/attachments/*` fetch by embedding an
  official attachment URL.
- Network-tagged native WebSocket events must be dispatched through
  network-scoped store APIs. Unsupported `native-ws-network-event` payloads must
  not be applied to the legacy raw-ID active-backend stores because a self-host
  can collide with official IDs.
- The renderer applies network-tagged WebSocket events for scoped server,
  category, channel, `READY`, `READY_DELTA`, messages, unread markers,
  reactions, typing, roles, members, presence, DMs, voice states, emojis,
  announcement feeds, feed announcements, bot presence, and channel activity.
  New event classes must either add an explicit scoped store path or fail
  closed; never "temporarily" route them through raw active-backend stores.
- Network-tagged events are the native desktop source of truth. The renderer
  must route them dynamically by `networkId`: active-backend events enter the
  raw active-backend dispatcher, while non-active joined-network events enter
  scoped store APIs. The legacy `native-ws-event` listener is compatibility-only
  for older native binaries and must ignore already-tagged events.
- Legacy active-backend preference and ordering writes must continue to strip
  scoped `networkId/localId` values before sending
  `/api/users/me/preferences`, `/api/users/me/server-order`, or
  `/api/users/me/favorite-order`. Scoped preference writes are persisted only
  to the Rust-owned local per-network preference cache keyed by `networkId`;
  the cache stores raw local IDs under that network and re-scopes them into
  merged stores after network `READY`. The official backend must never receive
  another network's runtime identifiers or empty clears derived only from
  another network.
- Native WebSocket availability updates are local client UI state. A down
  network may show a red rail badge for its servers, but that state must not
  create trust, route through official, or affect other joined networks.
- Raw backend IDs must not be used as global keys in merged stores because a
  self-host can choose IDs that collide with official or other self-host IDs.
- A single unavailable self-host must fail locally and must not block official
  or other joined networks.
- Account linking remains identity metadata only and must not become a runtime
  transport, role, membership, upload, message, billing, or moderation grant.
- Joined network registry records are renderer-local metadata only. Cached
  `authStatus` values are for UI labels and must be reconciled against
  Rust-owned backend-scoped credentials before any future live transport opens.
  They must never be treated as authentication or authorization proof.
- Removing a migrated joined network must also clean legacy saved backend
  profile storage so a removed self-host origin cannot silently reappear on the
  next app load.

## CSP Cutover Rule

Desktop Tauri `connect-src` is narrowed now that native transport owns auth,
REST, multipart, and WebSocket traffic. It must keep Tauri IPC, localhost dev
allowances, and the exact official LiveKit signaling origins required for
official voice, but it must not include broad remote `https:` or `wss:` sinks.

Before publishing transport or CSP changes, verify:

- Official login, registration, 2FA, verification, refresh, and logout.
- Self-host backend selection and login.
- Avatar, banner, server icon, emoji, and sticker uploads.
- ZDT planned WebSocket drain/reconnect without message loss.

Use the developer diagnostics panel during acceptance to confirm the renderer
mode, Rust mode, backend origin, credential backend, credential match, auth
state, and WS state on both official and self-hosted backends.

`media-src` is narrowed to app/blob, local dev, and the exact Klipy media hosts
needed by the current direct `<video>` clip surfaces. It must not include broad
`https:`, `http:`, `data:`, or `*` sources. Message attachments are served by
authenticated `/api/media/attachments/{id}` requests and rendered as app-owned
`blob:` URLs; they must not depend on remote `media-src` origins. Desktop
`img-src` must not include broad remote `https:`; server-provided public images
must resolve through the native public media proxy and render as app-owned
`blob:` URLs. The proxy derives its allowed origins from Rust-owned backend
profile state plus `/api/instance` metadata for the active backend, pinned
official Verdant media origins, and explicit third-party image hosts. It must
reject raw `attachments/*`, SVG/active formats, credentials, unsafe paths, and
off-policy origins. Future self-host or official audio/video attachment media
requires a native media delivery path or a separate CSP/security review before
adding any remote media origin. The current official voice exception is limited
to exact `https://voice.verdant.chat` and `wss://voice.verdant.chat`
signaling. Joined-network voice must use the Rust-owned native voice join and
localhost LiveKit signaling proxy: Rust validates the registered owning backend
profile, obtains the room token from that backend, validates the returned
LiveKit signaling base URL, rejects remote localhost/private/reserved signaling
hosts outside local development, and never routes scoped LiveKit signaling or
media through the active backend or official backend as a shortcut. Scoped
voice rows must stay unavailable before click when metadata is missing, the
user is signed out, the network is unavailable, or the owning instance reports
`capabilities.voiceChat=false`.

## Media Exposure Boundary

Message attachments have a separate storage boundary: uploads create pending
attachment rows, and message creation may only claim pending rows with matching
`channel_id`, `uploader_id`, and `message_id IS NULL`. Attachment IDs from other
users, channels, or already-sent messages must be rejected. Raw `attachments/*`
object keys must not be exposed by public bucket website rules, Caddy media
matchers, or CDN routes; the API route must recheck channel/DM visibility and
hide deleted-message attachments.

This boundary applies to both official and self-host deployments:

- Public object/CDN/proxy rules may expose profile, server, bot, emoji, and sticker
  object prefixes. Embed or announcement images must stay on explicitly
  approved origins and must not expand the object-storage prefix allowlist.
- Custom emoji/sticker dedupe is exact canonical-byte dedupe only. Store
  SHA-256 hashes, metadata, and storage keys in Postgres; keep raw bytes in
  object storage, and only delete shared public objects after the final catalog
  reference is removed and the digest cleanup path rechecks references.
- Public object/CDN/proxy rules must not expose `attachments/*`, encoded
  attachment path variants, or unauthenticated `/api/media/attachments/*`.
- `INSTANCE_CAP_FILE_SHARING` controls text-channel and DM attachments;
  `INSTANCE_CAP_IMAGE_UPLOADS` is only for profile/server/bot/emoji/sticker image
  upload surfaces.
- Before enabling message attachments on an official or public self-host
  deployment, run `node deploy/check-media-exposure.mjs` with a real private
  canary `--attachment-key`, `--attachment-id`, and at least one public
  `--sample-url`. Use `--base-url <origin>` for unified deployments, or
  `--media-base-url <media-origin> --api-base-url <api-origin>` for split
  media/API deployments.
- For self-host deployments, prefer the higher-level
  `bun run check:selfhost-media-deployment` command with `--api-base-url`,
  `--expect-mode`, `--attachment-key`, `--attachment-id`, and `--sample-url`.
  It validates `/health` and `/api/instance`, rejects accidental official-mode
  targets, derives the public media origin from the self-host's `cdnUrl`
  metadata unless explicitly overridden, then runs the same strict
  raw-attachment probes.

Object storage providers can expose bucket objects directly through public
domains. Before enabling public media, verify that raw `attachments/*` canaries
are not public and that only approved public media prefixes are exposed.

## Official/Internal Boundaries

- Self-hosted servers must not join official Redis or NATS transport.
- Runtime events, messages, presence, voice state, moderation actions, and data
  writes stay local to the server that owns them.
- Verdant uses a server/community-owned backend model. If a server is owned by
  Backend B, Backend B is the source of truth for its messages, uploads, roles,
  channels, moderation, and fanout. Backend A may provide identity/linking
  metadata, but it must not persist Backend B-owned runtime data as a home
  backend relay.
- Cross-backend S2S runtime persistence is disabled. Federation routes client
  writes directly to the owning backend and uses S2S for metadata, identity,
  and membership handshakes, not for making one backend store another backend's
  runtime data.
- `official`, `linked`, `federated`, and `standalone` instance metadata is
  untrusted unless verified by a pinned official origin or future signed
  registry flow.
- Public `/api/instance` metadata may expose mode, version, upload policy,
  scanner provider/status, capabilities, and advisory certificate pin
  fingerprints for operator visibility. It must not expose scanner secrets, mock
  hash lists, bucket names, account IDs, object keys, credentials, or other
  deployment secrets. Backend-served certificate pin metadata is self-reported
  and must not be used as the first-contact trust root; enforceable pinning
  belongs in the client build or a separately trusted registry/channel. Upload
  copy must treat `CONTENT_SCAN_PROVIDER=none` as no automatic scanner reported.
- Official instances force email verification when public registration is
  enabled. Standalone self-hosts may explicitly disable email verification for
  local/community onboarding; that must not relax the official-network rule.

## Federation Discovery Registry

Federation discovery is metadata-only. Public `/api/federation/manifest`
responses are self-reported and must not be treated as official trust.
Federation identity in clients is keyed by the actual normalized API origin
that was contacted, plus the reported instance ID and public-key fingerprint;
display names, usernames, claimed domains, community names, and `mode` strings
are never trust or authorization inputs. Pinned official trust requires the
exact first-party origin, and future verified trust must come from the official
registry row for that same origin and fingerprint. Self-hosts that claim
official branding, official API origins, lookalike domains, IDN/punycode hosts,
or changed fingerprints must be displayed as warnings on risky client surfaces
such as add/join network, invite preview/accept, login network selection,
profile popovers, friends/DMs, and moderation/admin views.

Official public discovery reads only `verified + publicDiscovery` registry rows.
Admin registry mutations under `/api/admin/federation/*` are available only when
`INSTANCE_MODE=official`, `FEDERATION_REGISTRY_ADMIN_ENABLED=true`, and
`FEDERATION_REGISTRY_ADMIN_SECRET` is configured. They are not mounted by
default; keep the opt-in disabled unless a specific operator tool is using it.
They use scoped HMAC signatures, nonce-backed replay rejection, and the existing
admin rate limit.

Registry validation must reject IPs, localhost, wildcard domains, embedded URL
credentials, non-HTTPS registry origins, path/query-bearing API origins, and
`mode: "official"` for self-host registry rows. The registry stores verification
token hashes only; raw verification tokens are returned once as operator
challenges and must not appear in public discovery output. Federation admin HMAC
signatures are scoped to `timestamp.nonce.method.path.body`, unlike the legacy
update notification endpoint. Registry mutations use a stricter 60-second skew
window, so a captured mutation cannot be replayed against a different registry
instance path or reused with the same nonce. Redis nonce storage must fail
closed if unavailable. Public manifest key material must
reject private-key PEM markers because `/api/federation/manifest` is public.
Federation admin request bodies are capped at 64 KiB before HMAC verification
or JSON parsing, independent of upload-sized global body limits. Public
discovery must serialize only whitelisted scanner/capability fields and must
strip or reject arbitrary JSON keys such as scanner API keys, mock hash lists,
bucket names, object keys, and account IDs. Changing registry identity fields
such as domain, API/public origins, public key, or verification method must
force pending re-verification before the row can be publicly discoverable again.

## Account Linking

Account linking is identity metadata only. It must not grant local membership,
roles, message access, upload rights, moderation authority, billing privileges,
or any official runtime transport access.

The foundation endpoints live under authenticated `/api/account-links`.
Linked/federated self-host consumers can create short-lived local intents and
complete them with RS256 proofs only when `FEDERATION_LINK_VERIFY_KEY_PEM` is
configured. Official issuers can mint proofs only when `INSTANCE_MODE=official`
and `FEDERATION_LINK_SIGNING_KEY_PEM` is configured. Standalone instances and
non-official issuers fail closed.

Proofs must be audience-bound to the self-host `INSTANCE_ID`, state-bound to a
pending local intent, short-lived, scoped to whitelisted scopes, and replay
checked through the stored hashed JWT ID. The database stores only link metadata,
hashed state, and hashed proof IDs. It must never store official passwords,
official access/session tokens, cookies, or database credentials.

Official proof issuance must fail closed unless `audienceInstanceId` is a
`host:<hostname>` value backed by a verified, non-revoked federation registry
record. Desktop native transport stores credentials in Rust-derived
backend-scoped keyring entries so official and self-host sessions can coexist
without renderer-held tokens.
