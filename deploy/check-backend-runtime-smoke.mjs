#!/usr/bin/env node
import crypto from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";

import { normalizeApiBaseUrl, runLiveApiSmoke } from "./check-live-api-smoke.mjs";

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_BODY_BYTES = 64 * 1024;
const CLIENT_VERSION = "verdant-backend-runtime-smoke/1";
const STATUS_ORDER = { fail: 0, skip: 1, pass: 2 };

function usage() {
  return `Usage:
  node deploy/check-backend-runtime-smoke.mjs --api-base-url URL [options]

Checks a real Verdant backend through HTTP before manual client testing.
The default mode is read-only. Use --create-account to exercise authenticated
routes with a disposable account.

Options:
  --api-base-url URL      Backend API origin, e.g. https://api.example.com.
  --expect-mode MODE      Require official, standalone, linked, or federated.
  --create-account        Create a disposable account and test authenticated routes.
  --create-server         Also create a disposable server. Implies --create-account.
  --message-flow          Create a disposable server, send a message, and fetch it back.
  --websocket-flow        Also verify the sent message arrives over /ws. Implies --message-flow.
  --cleanup-server        Delete the disposable server after creation.
  --email EMAIL           Email for mutation mode. Defaults to a unique verdant.chat smoke address.
  --password PASSWORD     Password for mutation mode. Defaults to a generated value.
  --server-name NAME      Server name for --create-server.
  --timeout-ms N          Per-request timeout. Default: ${DEFAULT_TIMEOUT_MS}.
  --json                  Print sanitized JSON result.
  --quiet                 Print only pass/fail summary.
  -h, --help              Show this help.

Exit codes:
  0 pass
  1 one or more backend checks failed
  2 invalid usage`;
}

function requireValue(argv, index, arg) {
  const value = argv[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${arg} requires a value`);
  }
  return value;
}

export function parseBackendRuntimeSmokeArgs(argv) {
  const options = {
    apiBaseUrl: null,
    expectMode: null,
    timeoutMs: DEFAULT_TIMEOUT_MS,
    createAccount: false,
    createServer: false,
    messageFlow: false,
    websocketFlow: false,
    cleanupServer: false,
    email: null,
    password: null,
    serverName: null,
    json: false,
    quiet: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      const value = requireValue(argv, i, arg);
      i += 1;
      return value;
    };

    switch (arg) {
      case "-h":
      case "--help":
        options.help = true;
        break;
      case "--api-base-url":
        options.apiBaseUrl = next();
        break;
      case "--expect-mode":
        options.expectMode = next();
        if (!["official", "standalone", "linked", "federated"].includes(options.expectMode)) {
          throw new Error("--expect-mode must be official, standalone, linked, or federated");
        }
        break;
      case "--timeout-ms":
        options.timeoutMs = Number(next());
        if (!Number.isInteger(options.timeoutMs) || options.timeoutMs < 1000 || options.timeoutMs > 60000) {
          throw new Error("--timeout-ms must be an integer between 1000 and 60000");
        }
        break;
      case "--create-account":
        options.createAccount = true;
        break;
      case "--create-server":
        options.createAccount = true;
        options.createServer = true;
        break;
      case "--message-flow":
        options.createAccount = true;
        options.createServer = true;
        options.messageFlow = true;
        break;
      case "--websocket-flow":
        options.createAccount = true;
        options.createServer = true;
        options.messageFlow = true;
        options.websocketFlow = true;
        break;
      case "--cleanup-server":
        options.cleanupServer = true;
        break;
      case "--email":
        options.email = next();
        break;
      case "--password":
        options.password = next();
        break;
      case "--server-name":
        options.serverName = next();
        break;
      case "--json":
        options.json = true;
        break;
      case "--quiet":
        options.quiet = true;
        break;
      default:
        throw new Error(`unknown option: ${arg}`);
    }
  }

  if (!options.help && !options.apiBaseUrl) {
    throw new Error("--api-base-url is required");
  }
  return options;
}

function randomId(bytes = 6) {
  return crypto.randomBytes(bytes).toString("hex");
}

function defaultEmail() {
  return `verdant-smoke-${Date.now()}-${randomId()}@verdant.chat`;
}

function defaultPassword() {
  return `Verdant-smoke-${randomId(12)}!aA1`;
}

function defaultServerName() {
  return `Backend Smoke ${new Date().toISOString().replace(/[:.]/g, "-")}`;
}

function check(name, status, detail) {
  return { name, status, detail };
}

function worstStatus(checks) {
  return checks.reduce((current, item) => {
    if (STATUS_ORDER[item.status] < STATUS_ORDER[current]) {
      return item.status;
    }
    return current;
  }, "pass");
}

function pushFailure(checks, name, error) {
  const message = formatErrorMessage(error);
  checks.push(check(name, "fail", sanitizeDetail(message)));
}

function safeCauseValue(value) {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 && trimmed.length <= 160 ? trimmed : null;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }
  return null;
}

function formatErrorMessage(error) {
  const message = error instanceof Error ? error.message : String(error);
  const cause = error instanceof Error && error.cause && typeof error.cause === "object"
    ? error.cause
    : null;
  if (!cause) {
    return message;
  }

  const details = [];
  for (const key of ["code", "syscall", "hostname", "address", "port"]) {
    const value = safeCauseValue(cause[key]);
    if (value) {
      details.push(`${key}=${value}`);
    }
  }
  if (cause instanceof Error && cause.message && cause.message !== message) {
    const causeMessage = safeCauseValue(cause.message);
    if (causeMessage) {
      details.push(`cause=${causeMessage}`);
    }
  }
  return details.length > 0 ? `${message} (${details.join(", ")})` : message;
}

function sanitizeDetail(value) {
  return String(value)
    .replace(/\b(?:Bearer\s+)?[A-Za-z0-9._~+/=-]{24,}\b/g, "<redacted>")
    .replace(/"accessToken"\s*:\s*"[^"]+"/gi, '"accessToken":"<redacted>"')
    .replace(/"sessionToken"\s*:\s*"[^"]+"/gi, '"sessionToken":"<redacted>"')
    .replace(/"password"\s*:\s*"[^"]+"/gi, '"password":"<redacted>"');
}

async function withTimeout(timeoutMs, operation) {
  const controller = new AbortController();
  let timeoutId;
  const operationPromise = operation(controller.signal);
  const timeoutPromise = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      controller.abort();
      reject(new Error("request timed out"));
    }, timeoutMs);
  });
  try {
    return await Promise.race([operationPromise, timeoutPromise]);
  } finally {
    clearTimeout(timeoutId);
    operationPromise.catch(() => {});
  }
}

async function readTextLimited(response, label) {
  const lengthHeader = response.headers.get("content-length");
  if (lengthHeader) {
    const length = Number(lengthHeader);
    if (Number.isFinite(length) && length > MAX_BODY_BYTES) {
      await response.body?.cancel?.().catch(() => {});
      throw new Error(`${label} response too large`);
    }
  }

  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > MAX_BODY_BYTES) {
    throw new Error(`${label} response too large`);
  }
  return text;
}

function assertNotHtml(text, contentType, label) {
  if (/text\/html/i.test(contentType) || /^\s*<!doctype html/i.test(text) || /^\s*<html/i.test(text)) {
    throw new Error(`${label} returned HTML instead of API JSON`);
  }
}

async function readApiJson(response, label) {
  const contentType = response.headers.get("content-type") ?? "";
  const text = await readTextLimited(response, label);
  assertNotHtml(text, contentType, label);
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`${label} did not return valid JSON`);
  }
}

function authHeaders(token) {
  return token ? { authorization: `Bearer ${token}` } : {};
}

async function apiFetch(fetchImpl, apiBaseUrl, path, options = {}) {
  const url = `${apiBaseUrl}${path}`;
  const method = options.method ?? "GET";
  const headers = new Headers({
    accept: "application/json",
    "user-agent": CLIENT_VERSION,
    "x-client-version": CLIENT_VERSION,
    ...authHeaders(options.token),
    ...(options.headers ?? {}),
  });
  let body;
  if (options.body !== undefined) {
    headers.set("content-type", "application/json");
    body = JSON.stringify(options.body);
  }

  const response = await withTimeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, (signal) =>
    fetchImpl(url, {
      method,
      headers,
      body,
      redirect: "manual",
      signal,
    }),
  );
  return {
    status: response.status,
    ok: response.ok,
    json: await readApiJson(response, `${method} ${path}`),
  };
}

function apiErrorSuffix(json) {
  if (!json || typeof json !== "object" || Array.isArray(json)) {
    return "";
  }
  const fields = [];
  for (const key of ["code", "message", "error"]) {
    if (typeof json[key] === "string" && json[key].trim()) {
      fields.push(`${key}=${json[key]}`);
    }
  }
  return fields.length > 0 ? ` (${fields.join(", ")})` : "";
}

function assertStatus(actual, allowed, label, json = null) {
  if (!allowed.includes(actual)) {
    throw new Error(`${label} returned HTTP ${actual}; expected ${allowed.join(", ")}${apiErrorSuffix(json)}`);
  }
}

function assertObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} did not return a JSON object`);
  }
}

function assertString(value, label) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${label} missing string value`);
  }
}

async function checkAuthRouteShape(fetchImpl, apiBaseUrl, timeoutMs) {
  const response = await apiFetch(fetchImpl, apiBaseUrl, "/api/auth/login", {
    method: "POST",
    timeoutMs,
    body: { email: "not-an-email", password: "" },
  });
  assertStatus(response.status, [400, 401, 422], "auth route shape", response.json);
  assertObject(response.json, "auth route shape");
  if (!("code" in response.json) && !("message" in response.json) && !("error" in response.json)) {
    throw new Error("auth route shape returned JSON without an API error field");
  }
  return `POST /api/auth/login returned API JSON with HTTP ${response.status}`;
}

async function checkProtectedRoute(fetchImpl, apiBaseUrl, path, timeoutMs) {
  const response = await apiFetch(fetchImpl, apiBaseUrl, path, { timeoutMs });
  assertStatus(response.status, [401, 403], `${path} anonymous guard`, response.json);
  assertObject(response.json, `${path} anonymous guard`);
  return `${path} rejected anonymous access with API JSON`;
}

async function registerAccount(fetchImpl, apiBaseUrl, options, metadata) {
  if (metadata?.registration !== "public") {
    throw new Error(`public registration is ${metadata?.registration ?? "unknown"}`);
  }
  const email = options.email ?? defaultEmail();
  const password = options.password ?? defaultPassword();
  const response = await apiFetch(fetchImpl, apiBaseUrl, "/api/auth/register", {
    method: "POST",
    timeoutMs: options.timeoutMs,
    body: {
      email,
      password,
      termsAccepted: true,
      privacyAccepted: true,
    },
  });
  assertStatus(response.status, [201], "registration", response.json);
  assertObject(response.json, "registration");
  assertString(response.json.accessToken, "registration accessToken");
  if (response.json.emailVerificationRequired === true) {
    throw new Error("registration requires email verification; authenticated smoke cannot continue automatically");
  }
  return {
    email,
    password,
    accessToken: response.json.accessToken,
    sessionTokenPresent: typeof response.json.sessionToken === "string" && response.json.sessionToken.length > 0,
  };
}

async function loginAccount(fetchImpl, apiBaseUrl, account, timeoutMs) {
  const response = await apiFetch(fetchImpl, apiBaseUrl, "/api/auth/login", {
    method: "POST",
    timeoutMs,
    body: {
      email: account.email,
      password: account.password,
    },
  });
  assertStatus(response.status, [200], "login", response.json);
  assertObject(response.json, "login");
  if (response.json.requiresTwoFactor === true || response.json.requiresVerification === true) {
    throw new Error("login requires an interactive verification step");
  }
  assertString(response.json.accessToken, "login accessToken");
  return {
    accessToken: response.json.accessToken,
    sessionTokenPresent: typeof response.json.sessionToken === "string" && response.json.sessionToken.length > 0,
  };
}

async function checkAuthenticatedRoutes(fetchImpl, apiBaseUrl, token, timeoutMs) {
  const user = await apiFetch(fetchImpl, apiBaseUrl, "/api/users/me", { token, timeoutMs });
  assertStatus(user.status, [200], "GET /api/users/me", user.json);
  assertObject(user.json, "GET /api/users/me");
  assertString(user.json.id, "current user id");

  const servers = await apiFetch(fetchImpl, apiBaseUrl, "/api/servers", { token, timeoutMs });
  assertStatus(servers.status, [200], "GET /api/servers", servers.json);
  assertObject(servers.json, "GET /api/servers");
  if (!Array.isArray(servers.json.servers)) {
    throw new Error("GET /api/servers did not include servers array");
  }
  if (!Array.isArray(servers.json.serverOrder) || !Array.isArray(servers.json.favoriteOrder)) {
    throw new Error("GET /api/servers did not include serverOrder/favoriteOrder arrays");
  }
  return {
    userId: user.json.id,
    serverCount: servers.json.servers.length,
  };
}

async function createAndVerifyServer(fetchImpl, apiBaseUrl, token, options) {
  const serverName = options.serverName ?? defaultServerName();
  const created = await apiFetch(fetchImpl, apiBaseUrl, "/api/servers", {
    method: "POST",
    token,
    timeoutMs: options.timeoutMs,
    body: { name: serverName },
  });
  assertStatus(created.status, [201], "server create", created.json);
  assertObject(created.json, "server create");
  assertString(created.json.id, "created server id");
  assertString(created.json.defaultChannelId, "created server defaultChannelId");

  const serverId = created.json.id;
  const defaultChannelId = created.json.defaultChannelId;
  const listed = await apiFetch(fetchImpl, apiBaseUrl, "/api/servers", {
    token,
    timeoutMs: options.timeoutMs,
  });
  const found = listed.json?.servers?.some((server) => String(server.id) === String(serverId));
  if (!found) {
    throw new Error("created server was not returned by GET /api/servers");
  }

  const layout = await apiFetch(fetchImpl, apiBaseUrl, `/api/servers/${serverId}/layout`, {
    token,
    timeoutMs: options.timeoutMs,
  });
  assertStatus(layout.status, [200], "server layout", layout.json);
  assertObject(layout.json, "server layout");
  if (!Array.isArray(layout.json.channels)) {
    throw new Error("server layout did not include channels array");
  }

  return {
    serverId,
    defaultChannelId,
    serverName,
    cleanup: "not requested",
  };
}

function extractMessages(value, label) {
  if (Array.isArray(value)) {
    return value;
  }
  if (value && typeof value === "object" && Array.isArray(value.messages)) {
    return value.messages;
  }
  throw new Error(`${label} did not return a message array`);
}

function deriveWebSocketUrl(apiBaseUrl) {
  const url = new URL(apiBaseUrl);
  url.protocol = url.protocol === "http:" ? "ws:" : "wss:";
  url.pathname = "/ws";
  url.search = "";
  url.hash = "";
  return url.toString();
}

function websocketEventData(event) {
  if (typeof event.data === "string") {
    return Promise.resolve(event.data);
  }
  if (event.data instanceof ArrayBuffer) {
    return Promise.resolve(Buffer.from(event.data).toString("utf8"));
  }
  if (ArrayBuffer.isView(event.data)) {
    return Promise.resolve(Buffer.from(event.data.buffer, event.data.byteOffset, event.data.byteLength).toString("utf8"));
  }
  if (event.data && typeof event.data.text === "function") {
    return event.data.text();
  }
  return Promise.resolve(String(event.data ?? ""));
}

function withTimer(timeoutMs, label, setup) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`${label} timed out`)), timeoutMs);
    const settle = (fn, value) => {
      clearTimeout(timeout);
      fn(value);
    };
    setup((value) => settle(resolve, value), (error) => settle(reject, error));
  });
}

class JsonWebSocketSmokeClient {
  constructor(url, timeoutMs) {
    if (typeof globalThis.WebSocket !== "function") {
      throw new Error("WebSocket is not available in this Node.js runtime");
    }
    this.url = url;
    this.timeoutMs = timeoutMs;
    this.socket = new globalThis.WebSocket(url);
    this.events = [];
    this.waiters = [];
    this.closed = false;
    this.closeReason = "";

    this.socket.addEventListener("message", (event) => {
      websocketEventData(event)
        .then((text) => {
          const parsed = JSON.parse(text);
          this.events.push(parsed);
          this.drainWaiters();
        })
        .catch(() => {
          this.events.push({ op: "PARSE_ERROR" });
          this.drainWaiters();
        });
    });
    this.socket.addEventListener("close", (event) => {
      this.closed = true;
      this.closeReason = event?.reason || `code ${event?.code ?? "unknown"}`;
      this.drainWaiters();
    });
    this.socket.addEventListener("error", () => {
      this.closed = true;
      this.closeReason = "socket error";
      this.drainWaiters();
    });
  }

  async open() {
    if (this.socket.readyState === globalThis.WebSocket.OPEN) {
      return;
    }
    await withTimer(this.timeoutMs, "websocket open", (resolve, reject) => {
      const onOpen = () => {
        cleanup();
        resolve();
      };
      const onError = () => {
        cleanup();
        reject(new Error("websocket open failed"));
      };
      const cleanup = () => {
        this.socket.removeEventListener("open", onOpen);
        this.socket.removeEventListener("error", onError);
      };
      this.socket.addEventListener("open", onOpen);
      this.socket.addEventListener("error", onError);
    });
  }

  sendJson(value) {
    this.socket.send(JSON.stringify(value));
  }

  waitFor(label, predicate) {
    const existing = this.events.find(predicate);
    if (existing) {
      return Promise.resolve(existing);
    }
    if (this.closed) {
      return Promise.reject(new Error(`${label} unavailable; websocket closed: ${this.closeReason}`));
    }
    return withTimer(this.timeoutMs, label, (resolve, reject) => {
      this.waiters.push({ predicate, resolve, reject, label });
    });
  }

  drainWaiters() {
    const pending = [];
    for (const waiter of this.waiters) {
      const found = this.events.find(waiter.predicate);
      if (found) {
        waiter.resolve(found);
      } else if (this.closed) {
        waiter.reject(new Error(`${waiter.label} unavailable; websocket closed: ${this.closeReason}`));
      } else {
        pending.push(waiter);
      }
    }
    this.waiters = pending;
  }

  close() {
    try {
      this.socket.close();
    } catch {}
  }
}

async function connectRealtimeClient(apiBaseUrl, token, server, timeoutMs) {
  const client = new JsonWebSocketSmokeClient(deriveWebSocketUrl(apiBaseUrl), timeoutMs);
  await client.open();
  client.sendJson({
    op: "IDENTIFY",
    d: {
      token,
      clientVersion: CLIENT_VERSION,
      initialStatus: "online",
    },
  });
  await client.waitFor("websocket READY", (event) => event?.op === "READY");
  client.sendJson({ op: "FOCUS_SERVER", d: { serverId: String(server.serverId) } });
  client.sendJson({ op: "FOCUS_CHANNEL", d: { channelId: String(server.defaultChannelId) } });
  await new Promise((resolve) => setTimeout(resolve, 150));
  return client;
}

async function createCanaryMessage(fetchImpl, apiBaseUrl, token, channelId, content, options) {
  const created = await apiFetch(fetchImpl, apiBaseUrl, `/api/channels/${channelId}/messages`, {
    method: "POST",
    token,
    timeoutMs: options.timeoutMs,
    body: { content },
  });
  assertStatus(created.status, [201], "message create", created.json);
  assertObject(created.json, "message create");
  assertString(created.json.id, "created message id");
  if (created.json.content !== content) {
    throw new Error("created message content did not match canary content");
  }
  return created.json;
}

async function fetchCanaryMessage(fetchImpl, apiBaseUrl, token, channelId, messageId, content, options) {
  const fetched = await apiFetch(fetchImpl, apiBaseUrl, `/api/channels/${channelId}/messages?limit=20`, {
    token,
    timeoutMs: options.timeoutMs,
  });
  assertStatus(fetched.status, [200], "message fetch", fetched.json);
  const messages = extractMessages(fetched.json, "message fetch");
  const found = messages.some((message) =>
    String(message?.id) === String(messageId) && message?.content === content,
  );
  if (!found) {
    throw new Error("created message was not returned by authenticated message fetch");
  }
}

async function sendAndFetchMessage(fetchImpl, apiBaseUrl, token, server, options) {
  const content = `verdant backend smoke ${Date.now()} ${randomId()}`;
  let realtime = null;
  if (options.websocketFlow) {
    realtime = await connectRealtimeClient(apiBaseUrl, token, server, options.timeoutMs);
  }

  try {
    const created = await createCanaryMessage(
      fetchImpl,
      apiBaseUrl,
      token,
      server.defaultChannelId,
      content,
      options,
    );
    await fetchCanaryMessage(
      fetchImpl,
      apiBaseUrl,
      token,
      server.defaultChannelId,
      created.id,
      content,
      options,
    );

    let websocketReceived = false;
    if (realtime) {
      await realtime.waitFor("websocket MESSAGE_CREATE", (event) => {
        const message = event?.d?.message ?? event?.message;
        return event?.op === "MESSAGE_CREATE"
          && String(message?.id) === String(created.id)
          && message?.content === content;
      });
      websocketReceived = true;
    }

    return {
      messageId: created.id,
      channelId: server.defaultChannelId,
      websocketReceived,
    };
  } finally {
    realtime?.close();
  }
}

async function cleanupCreatedServer(fetchImpl, apiBaseUrl, token, server, options) {
  const deleted = await apiFetch(fetchImpl, apiBaseUrl, `/api/servers/${server.serverId}`, {
    method: "DELETE",
    token,
    timeoutMs: options.timeoutMs,
    body: { serverName: server.serverName },
  });
  assertStatus(deleted.status, [200], "server cleanup", deleted.json);
  assertObject(deleted.json, "server cleanup");
  if (deleted.json.success !== true) {
    throw new Error("server cleanup did not return success=true");
  }
  server.cleanup = "deleted";
  return server.cleanup;
}

export async function runBackendRuntimeSmoke(options, deps = {}) {
  const apiBaseUrl = normalizeApiBaseUrl(options.apiBaseUrl);
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : DEFAULT_TIMEOUT_MS;
  const fetchImpl = deps.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("fetch is not available in this Node.js runtime");
  }

  const checks = [];
  let metadata = null;
  let account = null;
  let login = null;
  let authenticated = null;
  let server = null;
  let message = null;

  try {
    const live = await runLiveApiSmoke({
      apiBaseUrl,
      expectMode: options.expectMode,
      timeoutMs,
      includeMetadata: true,
    }, { fetch: fetchImpl });
    metadata = live.metadata;
    checks.push(check("live-api", "pass", live.summary));
  } catch (error) {
    pushFailure(checks, "live-api", error);
  }

  try {
    checks.push(check("auth-route-shape", "pass", await checkAuthRouteShape(fetchImpl, apiBaseUrl, timeoutMs)));
  } catch (error) {
    pushFailure(checks, "auth-route-shape", error);
  }

  try {
    checks.push(check("anonymous-user-guard", "pass", await checkProtectedRoute(fetchImpl, apiBaseUrl, "/api/users/me", timeoutMs)));
  } catch (error) {
    pushFailure(checks, "anonymous-user-guard", error);
  }

  try {
    checks.push(check("anonymous-server-guard", "pass", await checkProtectedRoute(fetchImpl, apiBaseUrl, "/api/servers", timeoutMs)));
  } catch (error) {
    pushFailure(checks, "anonymous-server-guard", error);
  }

  if (options.createAccount) {
    try {
      account = await registerAccount(fetchImpl, apiBaseUrl, { ...options, timeoutMs }, metadata);
      checks.push(check("registration", "pass", `created disposable user ${account.email}; session token returned: ${account.sessionTokenPresent}`));
    } catch (error) {
      pushFailure(checks, "registration", error);
    }

    if (account?.accessToken) {
      try {
        login = await loginAccount(fetchImpl, apiBaseUrl, account, timeoutMs);
        checks.push(check("login", "pass", `login returned access token; session token returned: ${login.sessionTokenPresent}`));
      } catch (error) {
        pushFailure(checks, "login", error);
      }

      const authToken = login?.accessToken ?? account.accessToken;
      try {
        authenticated = await checkAuthenticatedRoutes(fetchImpl, apiBaseUrl, authToken, timeoutMs);
        checks.push(check("authenticated-basics", "pass", `current user loaded; ${authenticated.serverCount} server(s) returned`));
      } catch (error) {
        pushFailure(checks, "authenticated-basics", error);
      }
    } else {
      checks.push(check("login", "skip", "registration did not produce credentials"));
      checks.push(check("authenticated-basics", "skip", "registration did not produce an access token"));
    }
  } else {
    checks.push(check("registration", "skip", "mutation mode not requested"));
    checks.push(check("login", "skip", "mutation mode not requested"));
    checks.push(check("authenticated-basics", "skip", "mutation mode not requested"));
  }

  const mutationToken = login?.accessToken ?? account?.accessToken;

  if (options.createServer) {
    if (mutationToken) {
      try {
        server = await createAndVerifyServer(fetchImpl, apiBaseUrl, mutationToken, { ...options, timeoutMs });
        checks.push(check("server-create-layout", "pass", `created server ${server.serverId}; default channel ${server.defaultChannelId}`));
      } catch (error) {
        pushFailure(checks, "server-create-layout", error);
      }
    } else {
      checks.push(check("server-create-layout", "skip", "registration did not produce an access token"));
    }
  } else {
    checks.push(check("server-create-layout", "skip", "server mutation not requested"));
  }

  if (options.messageFlow) {
    if (mutationToken && server?.defaultChannelId) {
      try {
        message = await sendAndFetchMessage(fetchImpl, apiBaseUrl, mutationToken, server, { ...options, timeoutMs });
        checks.push(check(
          "message-send-fetch",
          "pass",
          `sent message ${message.messageId}, fetched it from channel ${message.channelId}, websocket received: ${message.websocketReceived}`,
        ));
      } catch (error) {
        pushFailure(checks, "message-send-fetch", error);
      }
    } else {
      checks.push(check("message-send-fetch", "skip", "server creation did not produce a default channel"));
    }
  } else {
    checks.push(check("message-send-fetch", "skip", "message flow not requested"));
  }

  if (options.cleanupServer) {
    if (mutationToken && server?.serverId) {
      try {
        await cleanupCreatedServer(fetchImpl, apiBaseUrl, mutationToken, server, { ...options, timeoutMs });
        checks.push(check("server-cleanup", "pass", `deleted server ${server.serverId}`));
      } catch (error) {
        pushFailure(checks, "server-cleanup", error);
      }
    } else {
      checks.push(check("server-cleanup", "skip", "server creation did not complete"));
    }
  } else {
    checks.push(check("server-cleanup", "skip", "cleanup not requested"));
  }

  const status = worstStatus(checks);
  const ok = status !== "fail";
  return {
    ok,
    exitCode: ok ? 0 : 1,
    apiBaseUrl,
    summary: ok
      ? `backend runtime smoke passed (${checks.filter((item) => item.status === "pass").length} passed, ${checks.filter((item) => item.status === "skip").length} skipped)`
      : `backend runtime smoke failed (${checks.filter((item) => item.status === "fail").length} failed)`,
    checks,
    metadata: metadata
      ? {
          mode: metadata.mode,
          registration: metadata.registration,
          emailProvider: metadata.emailProvider,
          uploadPolicy: metadata.uploadPolicy,
          apiUrl: metadata.apiUrl,
          wsUrl: metadata.wsUrl,
          capabilities: metadata.capabilities,
        }
      : null,
    createdAccount: Boolean(account),
    createdServer: Boolean(server),
    sentMessage: Boolean(message),
    serverCleanup: server?.cleanup ?? null,
  };
}

async function main() {
  let options;
  try {
    options = parseBackendRuntimeSmokeArgs(process.argv.slice(2));
    if (options.help) {
      console.log(usage());
      return 0;
    }
    const result = await runBackendRuntimeSmoke(options);
    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else if (options.quiet) {
      console.log(`${result.ok ? "PASS" : "FAIL"} backend-runtime-smoke`);
    } else {
      console.log(`${result.ok ? "PASS" : "FAIL"} backend-runtime-smoke - ${result.summary}`);
      for (const item of result.checks) {
        const label = item.status.toUpperCase().padEnd(4, " ");
        console.log(`${label} ${item.name} - ${item.detail}`);
      }
    }
    return result.exitCode;
  } catch (error) {
    const message = formatErrorMessage(error);
    if (options?.json) {
      console.log(JSON.stringify({ ok: false, error: sanitizeDetail(message) }, null, 2));
    } else {
      console.error(`FAIL backend-runtime-smoke - ${sanitizeDetail(message)}`);
      if (!options?.quiet) {
        console.error(usage());
      }
    }
    return 2;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fileURLToPath(pathToFileURL(process.argv[1]))) {
  process.exitCode = await main();
}
