import assert from "node:assert/strict";
import test from "node:test";

import {
  parseBackendRuntimeSmokeArgs,
  runBackendRuntimeSmoke,
} from "./check-backend-runtime-smoke.mjs";

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      ...headers,
    },
  });
}

function textResponse(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...headers,
    },
  });
}

function fakeFetch(routes) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url: String(url), method: init.method ?? "GET", body: init.body ?? "" });
    const parsed = new URL(String(url));
    const key = `${init.method ?? "GET"} ${parsed.pathname}`;
    const route = routes[key];
    if (!route) {
      return jsonResponse({ code: "NOT_FOUND", message: key }, 404);
    }
    return typeof route === "function" ? route(url, init) : route;
  };
  fetchImpl.calls = calls;
  return fetchImpl;
}

test("parseBackendRuntimeSmokeArgs requires an API origin and parses mutation flags", () => {
  assert.throws(
    () => parseBackendRuntimeSmokeArgs(["--expect-mode", "federated"]),
    /--api-base-url is required/,
  );

  const parsed = parseBackendRuntimeSmokeArgs([
    "--api-base-url",
    "https://api.example.com",
    "--expect-mode",
    "federated",
    "--create-account",
    "--create-server",
    "--message-flow",
    "--cleanup-server",
    "--json",
  ]);

  assert.equal(parsed.apiBaseUrl, "https://api.example.com");
  assert.equal(parsed.expectMode, "federated");
  assert.equal(parsed.createAccount, true);
  assert.equal(parsed.createServer, true);
  assert.equal(parsed.messageFlow, true);
  assert.equal(parsed.cleanupServer, true);
  assert.equal(parsed.json, true);
});

test("runBackendRuntimeSmoke fails when auth route returns HTML instead of API JSON", async () => {
  const fetchImpl = fakeFetch({
    "GET /health": new Response("ok", { status: 200 }),
    "GET /api/instance": jsonResponse({
      name: "Verdant",
      mode: "federated",
      serverVersion: "0.1.0",
      minClientVersion: "0.1.0",
      publicUrl: "https://api.example.com",
      apiUrl: "https://api.example.com",
      wsUrl: "wss://api.example.com/ws",
      cdnUrl: null,
      docsUrl: "https://api.example.com/docs",
      registration: "public",
      billingMode: "disabled",
      emailProvider: "disabled",
      uploadPolicy: "media_validation_only",
      contentScanning: { provider: "none", enabled: false },
      security: { certificatePins: { mode: "advisory", sha256: [] } },
      officialNetworkLinked: false,
      accountLinking: { enabled: false, role: "disabled", proofAlgorithm: "RS256" },
      trustedHosts: ["api.example.com"],
      capabilities: {
        imageUploads: true,
        fileSharing: true,
        messageAttachments: true,
        voiceChat: false,
        videoStreaming: false,
        crossServerEmoji: false,
        animatedAvatar: true,
        animatedBanner: true,
        memberListBanner: true,
        maxUploadBytes: 26214400,
        maxVoiceBitrate: 256000,
      },
    }),
    "POST /api/auth/login": textResponse("<!DOCTYPE html><h1>Error response</h1>", 501),
    "GET /api/users/me": jsonResponse({ code: "AUTH_REQUIRED" }, 401),
    "GET /api/servers": jsonResponse({ code: "AUTH_REQUIRED" }, 401),
  });

  const result = await runBackendRuntimeSmoke(
    {
      apiBaseUrl: "https://api.example.com",
      expectMode: "federated",
      timeoutMs: 5000,
    },
    { fetch: fetchImpl },
  );

  assert.equal(result.ok, false);
  assert.match(result.checks.find((check) => check.name === "auth-route-shape").detail, /HTML/);
});

test("runBackendRuntimeSmoke includes safe network failure causes", async () => {
  const cause = Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:3001"), {
    code: "ECONNREFUSED",
    address: "127.0.0.1",
    port: 3001,
  });
  const fetchImpl = async () => {
    throw new TypeError("fetch failed", { cause });
  };

  const result = await runBackendRuntimeSmoke(
    {
      apiBaseUrl: "https://api.example.com",
      expectMode: "federated",
      timeoutMs: 5000,
    },
    { fetch: fetchImpl },
  );

  assert.equal(result.ok, false);
  const liveApiDetail = result.checks.find((check) => check.name === "live-api").detail;
  assert.match(liveApiDetail, /fetch failed/);
  assert.match(liveApiDetail, /ECONNREFUSED/);
  assert.match(liveApiDetail, /127\.0\.0\.1/);
  assert.match(liveApiDetail, /3001/);
});

test("runBackendRuntimeSmoke can register, authenticate, create a server, and clean it up", async () => {
  let createdServer = false;
  let deletedServer = false;
  const fetchImpl = fakeFetch({
    "GET /health": new Response("ok", { status: 200 }),
    "GET /api/instance": jsonResponse({
      name: "Verdant",
      mode: "federated",
      serverVersion: "0.1.0",
      minClientVersion: "0.1.0",
      publicUrl: "https://api.example.com",
      apiUrl: "https://api.example.com",
      wsUrl: "wss://api.example.com/ws",
      cdnUrl: null,
      docsUrl: "https://api.example.com/docs",
      registration: "public",
      billingMode: "disabled",
      emailProvider: "disabled",
      uploadPolicy: "media_validation_only",
      contentScanning: { provider: "none", enabled: false },
      security: { certificatePins: { mode: "advisory", sha256: [] } },
      officialNetworkLinked: false,
      accountLinking: { enabled: false, role: "disabled", proofAlgorithm: "RS256" },
      trustedHosts: ["api.example.com"],
      capabilities: {
        imageUploads: true,
        fileSharing: true,
        messageAttachments: true,
        voiceChat: false,
        videoStreaming: false,
        crossServerEmoji: false,
        animatedAvatar: true,
        animatedBanner: true,
        memberListBanner: true,
        maxUploadBytes: 26214400,
        maxVoiceBitrate: 256000,
      },
    }),
    "POST /api/auth/login": (url, init) => {
      const body = JSON.parse(init.body);
      if (body.email === "smoke@example.invalid" && body.password === "correct horse battery staple 123!") {
        return jsonResponse({ accessToken: "login-access-token", sessionToken: "login-session-token", user: { id: "42" } });
      }
      return jsonResponse({ code: "VALIDATION_ERROR", message: "invalid" }, 400);
    },
    "GET /api/users/me": (url, init) => {
      const auth = init.headers?.get?.("authorization") ?? init.headers?.authorization;
      return auth ? jsonResponse({ id: "42", email: "smoke@example.invalid" }) : jsonResponse({ code: "AUTH_REQUIRED" }, 401);
    },
    "GET /api/servers": (url, init) => {
      const auth = init.headers?.get?.("authorization") ?? init.headers?.authorization;
      if (!auth) return jsonResponse({ code: "AUTH_REQUIRED" }, 401);
      return jsonResponse({
        servers: createdServer ? [{ id: "100", name: "Smoke", defaultChannelId: "101" }] : [],
        serverOrder: [],
        favoriteOrder: [],
      });
    },
    "POST /api/auth/register": jsonResponse({
      accessToken: "access-token",
      sessionToken: "session-token",
      emailVerificationRequired: false,
      user: { id: "42", email: "smoke@example.invalid" },
    }, 201),
    "POST /api/servers": () => {
      createdServer = true;
      return jsonResponse({ id: "100", name: "Smoke", defaultChannelId: "101" }, 201);
    },
    "GET /api/servers/100/layout": jsonResponse({
      categories: [],
      channels: [{ id: "101", serverId: "100", name: "general", type: 0 }],
    }),
    "DELETE /api/servers/100": () => {
      deletedServer = true;
      return jsonResponse({ success: true });
    },
  });

  const result = await runBackendRuntimeSmoke(
    {
      apiBaseUrl: "https://api.example.com",
      expectMode: "federated",
      timeoutMs: 5000,
      createAccount: true,
      createServer: true,
      cleanupServer: true,
      email: "smoke@example.invalid",
      password: "correct horse battery staple 123!",
      serverName: "Smoke",
    },
    { fetch: fetchImpl },
  );

  assert.equal(result.ok, true);
  assert.equal(createdServer, true);
  assert.equal(deletedServer, true);
  assert.equal(result.createdAccount, true);
  assert.equal(result.createdServer, true);
  assert.ok(result.checks.every((check) => check.status === "pass" || check.status === "skip"));
});

test("runBackendRuntimeSmoke can send and fetch a canary message before cleanup", async () => {
  let createdServer = false;
  let deletedServer = false;
  let createdMessage = null;
  const fetchImpl = fakeFetch({
    "GET /health": new Response("ok", { status: 200 }),
    "GET /api/instance": jsonResponse({
      name: "Verdant",
      mode: "federated",
      serverVersion: "0.1.0",
      minClientVersion: "0.1.0",
      publicUrl: "https://api.example.com",
      apiUrl: "https://api.example.com",
      wsUrl: "wss://api.example.com/ws",
      cdnUrl: null,
      docsUrl: "https://api.example.com/docs",
      registration: "public",
      billingMode: "disabled",
      emailProvider: "disabled",
      uploadPolicy: "media_validation_only",
      contentScanning: { provider: "none", enabled: false },
      security: { certificatePins: { mode: "advisory", sha256: [] } },
      officialNetworkLinked: false,
      accountLinking: { enabled: false, role: "disabled", proofAlgorithm: "RS256" },
      trustedHosts: ["api.example.com"],
      capabilities: {
        imageUploads: true,
        fileSharing: true,
        messageAttachments: true,
        voiceChat: false,
        videoStreaming: false,
        crossServerEmoji: false,
        animatedAvatar: true,
        animatedBanner: true,
        memberListBanner: true,
        maxUploadBytes: 26214400,
        maxVoiceBitrate: 256000,
      },
    }),
    "POST /api/auth/login": (url, init) => {
      const body = JSON.parse(init.body);
      if (body.email === "smoke@example.invalid" && body.password === "correct horse battery staple 123!") {
        return jsonResponse({ accessToken: "login-access-token", sessionToken: "login-session-token", user: { id: "42" } });
      }
      return jsonResponse({ code: "VALIDATION_ERROR", message: "invalid" }, 400);
    },
    "GET /api/users/me": (url, init) => {
      const auth = init.headers?.get?.("authorization") ?? init.headers?.authorization;
      return auth ? jsonResponse({ id: "42", email: "smoke@example.invalid" }) : jsonResponse({ code: "AUTH_REQUIRED" }, 401);
    },
    "GET /api/servers": (url, init) => {
      const auth = init.headers?.get?.("authorization") ?? init.headers?.authorization;
      if (!auth) return jsonResponse({ code: "AUTH_REQUIRED" }, 401);
      return jsonResponse({
        servers: createdServer ? [{ id: "100", name: "Smoke", defaultChannelId: "101" }] : [],
        serverOrder: [],
        favoriteOrder: [],
      });
    },
    "POST /api/auth/register": jsonResponse({
      accessToken: "access-token",
      sessionToken: "session-token",
      emailVerificationRequired: false,
      user: { id: "42", email: "smoke@example.invalid" },
    }, 201),
    "POST /api/servers": () => {
      createdServer = true;
      return jsonResponse({ id: "100", name: "Smoke", defaultChannelId: "101" }, 201);
    },
    "GET /api/servers/100/layout": jsonResponse({
      categories: [],
      channels: [{ id: "101", serverId: "100", name: "general", type: 0 }],
    }),
    "POST /api/channels/101/messages": (url, init) => {
      createdMessage = JSON.parse(init.body);
      return jsonResponse({
        id: "900",
        channelId: "101",
        authorId: "42",
        content: createdMessage.content,
        attachments: [],
        reactions: [],
      }, 201);
    },
    "GET /api/channels/101/messages": () => jsonResponse([
      {
        id: "900",
        channelId: "101",
        authorId: "42",
        content: createdMessage.content,
        attachments: [],
        reactions: [],
      },
    ]),
    "DELETE /api/servers/100": () => {
      deletedServer = true;
      return jsonResponse({ success: true });
    },
  });

  const result = await runBackendRuntimeSmoke(
    {
      apiBaseUrl: "https://api.example.com",
      expectMode: "federated",
      timeoutMs: 5000,
      messageFlow: true,
      createAccount: true,
      createServer: true,
      cleanupServer: true,
      email: "smoke@example.invalid",
      password: "correct horse battery staple 123!",
      serverName: "Smoke",
    },
    { fetch: fetchImpl },
  );

  assert.equal(result.ok, true);
  assert.equal(createdServer, true);
  assert.equal(deletedServer, true);
  assert.equal(result.sentMessage, true);
  assert.match(result.checks.find((check) => check.name === "message-send-fetch").detail, /sent message 900/);
});
