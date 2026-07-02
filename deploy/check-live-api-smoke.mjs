#!/usr/bin/env node
import { fileURLToPath, pathToFileURL } from "node:url";

const ALLOWED_MODES = new Set(["official", "standalone", "linked", "federated"]);
const REQUIRED_CAPABILITIES = [
  "imageUploads",
  "fileSharing",
  "messageAttachments",
  "voiceChat",
  "videoStreaming",
  "crossServerEmoji",
  "animatedAvatar",
  "animatedBanner",
  "memberListBanner",
  "maxUploadBytes",
  "maxVoiceBitrate",
];
const INSTANCE_METADATA_KEYS = new Set([
  "name",
  "mode",
  "serverVersion",
  "minClientVersion",
  "publicUrl",
  "apiUrl",
  "wsUrl",
  "cdnUrl",
  "docsUrl",
  "registration",
  "billingMode",
  "emailProvider",
  "uploadPolicy",
  "contentScanning",
  "security",
  "officialNetworkLinked",
  "accountLinking",
  "trustedHosts",
  "capabilities",
]);
const CONTENT_SCANNING_KEYS = new Set(["provider", "enabled"]);
const SECURITY_KEYS = new Set(["certificatePins"]);
const CERTIFICATE_PINS_KEYS = new Set(["sha256", "mode"]);
const ACCOUNT_LINKING_KEYS = new Set(["enabled", "role", "proofAlgorithm"]);
const CAPABILITY_KEYS = new Set(REQUIRED_CAPABILITIES);
const MAX_INSTANCE_UPLOAD_BYTES = 1024 * 1024 * 1024;
const MAX_INSTANCE_VOICE_BITRATE = 512000;
const REGISTRATION_MODES = new Set(["closed", "invite", "public"]);
const BILLING_MODES = new Set(["disabled", "official_stripe"]);
const EMAIL_PROVIDERS = new Set(["disabled", "console", "resend", "smtp"]);
const UPLOAD_POLICIES = new Set(["disabled", "media_validation_only", "operator_managed"]);
const ACCOUNT_LINKING_ROLES = new Set(["disabled", "issuer", "consumer"]);
const CONTENT_SCAN_PROVIDERS = new Set(["none", "mock"]);
const CERTIFICATE_PIN_MODES = new Set(["advisory"]);
const CERTIFICATE_SHA256_HEX = /^[a-f0-9]{64}$/;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const OFFICIAL_API_ORIGINS = new Set(["https://api.verdant.chat"]);
const VERSION_VALUE = /^(?:unknown|v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/;
const MAX_HEALTH_BODY_BYTES = 1024;
const MAX_INSTANCE_METADATA_BYTES = 64 * 1024;
const PUBLIC_METADATA_SECRET_PATTERNS = [
  /(?:^|[\\/])api[\\/]media[\\/]attachments(?:[\\/]|$)/i,
  /(?:^|[\\/])attachments(?:[\\/]|$)/i,
  /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9_=-]{8,}/i,
  /\bwhsec_[A-Za-z0-9_=-]{8,}/i,
  /\b(?:ghp|github_pat|glpat|doppler)_[A-Za-z0-9_=-]{8,}/i,
  /\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/i,
  /\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?token|client[_-]?secret|secret[_-]?key|private[_-]?key)\s*[:=]/i,
  /\b(?:x-amz-signature|awsaccesskeyid|signature|token|sig|expires)=/i,
];
const RAW_STORAGE_HOST_PATTERNS = [
  /(?:^|\.)r2\.cloudflarestorage\.com$/i,
  /(?:^|\.)r2\.dev$/i,
  /(?:^|\.)s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com$/i,
  /(?:^|\.)s3-website(?:[.-][a-z0-9-]+)*\.amazonaws\.com$/i,
  /(?:^|\.)storage\.googleapis\.com$/i,
  /(?:^|\.)digitaloceanspaces\.com$/i,
  /(?:^|\.)blob\.core\.windows\.net$/i,
  /(?:^|\.)backblazeb2\.com$/i,
  /(?:^|\.)b2clouddownload\.com$/i,
];

function withDefaultScheme(raw) {
  const trimmed = String(raw ?? "").trim();
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

function isLocalHost(hostname) {
  const host = String(hostname ?? "").replace(/^\[|\]$/g, "").toLowerCase();
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

export function normalizeApiBaseUrl(raw) {
  const input = withDefaultScheme(raw);
  let parsed;
  try {
    parsed = new URL(input);
  } catch {
    throw new Error("Enter a valid API origin");
  }
  if (parsed.username || parsed.password) {
    throw new Error("API origin must not include credentials");
  }
  if (parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new Error("API base URL must be an origin, not a path");
  }
  if (parsed.protocol === "https:") {
    return parsed.origin;
  }
  if (parsed.protocol === "http:" && isLocalHost(parsed.hostname)) {
    return parsed.origin;
  }
  throw new Error("API origin must use HTTPS unless it is localhost");
}

function requireString(data, key, label = key, maxLength = 253) {
  if (typeof data?.[key] !== "string" || !data[key].trim()) {
    throw new Error(`instance metadata missing ${label}`);
  }
  assertPublicMetadataString(data[key], label);
  if (data[key].length > maxLength) {
    throw new Error(`instance metadata invalid ${label}`);
  }
}

function stringVariants(value) {
  const variants = new Set([String(value).replace(/\\/g, "/")]);
  let current = String(value);
  for (let i = 0; i < 6; i += 1) {
    let decoded;
    try {
      decoded = decodeURIComponent(current);
    } catch {
      break;
    }
    if (decoded === current) break;
    variants.add(decoded.replace(/\\/g, "/"));
    current = decoded;
  }
  if (/%[0-9a-f]{2}/i.test(current)) {
    throw new Error("remaining encoded metadata");
  }
  return [...variants];
}

function urlLikeTokens(value) {
  return String(value).match(/\bhttps?:\/\/[^\s"'<>]+/gi) ?? [];
}

function bareHostTokens(value) {
  return String(value).match(/\b[a-z0-9][a-z0-9.-]*\.(?:cloudflarestorage\.com|r2\.dev|amazonaws\.com|googleapis\.com|digitaloceanspaces\.com|core\.windows\.net|backblazeb2\.com|b2clouddownload\.com)\b\.?/gi) ?? [];
}

function assertPublicMetadataString(value, label) {
  let variants;
  try {
    variants = stringVariants(value);
  } catch {
    throw new Error(`instance metadata invalid ${label}`);
  }
  for (const variant of variants) {
    for (const pattern of PUBLIC_METADATA_SECRET_PATTERNS) {
      if (pattern.test(variant)) {
        throw new Error(`instance metadata invalid ${label}`);
      }
    }
    for (const token of urlLikeTokens(variant)) {
      try {
        assertPublicMetadataHost(new URL(token).hostname, label);
      } catch (error) {
        if (error instanceof Error && error.message === `instance metadata invalid ${label}`) {
          throw error;
        }
      }
    }
    for (const token of bareHostTokens(variant)) {
      assertPublicMetadataHost(token, label);
    }
  }
}

function assertPublicMetadataHost(hostname, label) {
  const host = String(hostname ?? "").replace(/^\[|\]$/g, "").toLowerCase().replace(/\.+$/g, "");
  for (const pattern of RAW_STORAGE_HOST_PATTERNS) {
    if (pattern.test(host)) {
      throw new Error(`instance metadata invalid ${label}`);
    }
  }
}

function requireVersionString(data, key, label = key) {
  requireString(data, key, label, 64);
  if (!VERSION_VALUE.test(data[key])) {
    throw new Error(`instance metadata invalid ${label}`);
  }
}

function requireOptionalVersionString(data, key, label = key) {
  if (data?.[key] === undefined) {
    return;
  }
  requireVersionString(data, key, label);
}

function requireBoolean(data, key, label = key) {
  if (typeof data?.[key] !== "boolean") {
    throw new Error(`instance metadata missing ${label}`);
  }
}

function requireOptionalBoolean(data, key, label = key) {
  if (data?.[key] === undefined) {
    return;
  }
  requireBoolean(data, key, label);
}

function requireCapabilityNumber(data, key, max, label = key) {
  if (!Number.isInteger(data?.[key]) || data[key] < 0 || data[key] > max) {
    throw new Error(`instance metadata invalid ${label}`);
  }
}

function requireEnum(data, key, allowed, label = key) {
  if (typeof data?.[key] !== "string" || !allowed.has(data[key])) {
    throw new Error(`instance metadata invalid ${label}`);
  }
}

function requireOptionalEnum(data, key, allowed, label = key) {
  if (data?.[key] === undefined) {
    return;
  }
  requireEnum(data, key, allowed, label);
}

function decodedSafePath(parsed, label) {
  const rawPath = parsed.pathname;
  const lowerRawPath = rawPath.toLowerCase();
  if (/%(?:2e|2f|5c)/i.test(lowerRawPath)) {
    throw new Error(`instance metadata invalid ${label}`);
  }
  let decoded;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    throw new Error(`instance metadata invalid ${label}`);
  }
  return decoded.replace(/\\/g, "/").toLowerCase();
}

function parseMetadataUrl(data, key, label = key, protocols = ["https:", "http:", "wss:", "ws:"]) {
  const value = data?.[key];
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`instance metadata missing ${label}`);
  }
  const rawValue = value.trim();
  if (rawValue !== value || rawValue.includes("%")) {
    throw new Error(`instance metadata invalid ${label}`);
  }
  assertPublicMetadataString(rawValue, label);
  let parsed;
  try {
    parsed = new URL(rawValue);
  } catch {
    throw new Error(`instance metadata invalid ${label}`);
  }
  if (!protocols.includes(parsed.protocol)) {
    throw new Error(`instance metadata invalid ${label}`);
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash || !parsed.hostname) {
    throw new Error(`instance metadata invalid ${label}`);
  }
  assertPublicMetadataHost(parsed.hostname, label);
  if ((parsed.protocol === "http:" || parsed.protocol === "ws:") && !isLocalHost(parsed.hostname)) {
    throw new Error(`instance metadata invalid ${label}`);
  }
  return parsed;
}

function requireOriginUrl(data, key, label = key, protocols = ["https:", "http:"]) {
  const parsed = parseMetadataUrl(data, key, label, protocols);
  if (parsed.pathname !== "/") {
    throw new Error(`instance metadata invalid ${label}`);
  }
  return parsed;
}

function requirePathUrl(data, key, label = key, protocols = ["https:", "http:"]) {
  const parsed = parseMetadataUrl(data, key, label, protocols);
  const pathLower = decodedSafePath(parsed, label);
  if (pathLower.includes("/attachments/") || pathLower.endsWith("/attachments")) {
    throw new Error(`instance metadata invalid ${label}`);
  }
  return parsed;
}

function requireNullablePathUrl(data, key, label = key) {
  const value = data?.[key];
  if (value === null) return;
  if (typeof value !== "string") {
    throw new Error(`instance metadata invalid ${label}`);
  }
  requirePathUrl(data, key, label, ["https:", "http:"]);
}

function requireTrustedHosts(data) {
  if (!Array.isArray(data.trustedHosts)) {
    throw new Error("instance metadata missing trustedHosts");
  }
  if (data.trustedHosts.length > 32) {
    throw new Error("instance metadata invalid trustedHosts");
  }
  for (const host of data.trustedHosts) {
    if (typeof host !== "string" || !host.trim() || host.length > 253) {
      throw new Error("instance metadata invalid trustedHosts");
    }
    if (host.includes("://") || host.includes("/") || host.includes("@") || host.includes("?") || host.includes("#")) {
      throw new Error("instance metadata invalid trustedHosts");
    }
    if (host.includes("*") || host.includes("%") || host.includes("_")) {
      throw new Error("instance metadata invalid trustedHosts");
    }
    const bracketedIpv6 = host.startsWith("[") && host.endsWith("]");
    if (!bracketedIpv6 && host.includes(":")) {
      throw new Error("instance metadata invalid trustedHosts");
    }
    let parsed;
    try {
      parsed = new URL(`http://${host}`);
    } catch {
      throw new Error("instance metadata invalid trustedHosts");
    }
    if (parsed.username || parsed.password || !parsed.hostname || parsed.port || parsed.pathname !== "/" || parsed.search || parsed.hash) {
      throw new Error("instance metadata invalid trustedHosts");
    }
    assertPublicMetadataHost(parsed.hostname, "trustedHosts");
    if (!bracketedIpv6) {
      const labels = host.split(".");
      if (labels.some((label) => !DNS_LABEL.test(label))) {
        throw new Error("instance metadata invalid trustedHosts");
      }
    }
  }
}

function assertSameOrigin(actualUrl, expectedOrigin, label) {
  if (!expectedOrigin) return;
  const expected = new URL(expectedOrigin);
  if (actualUrl.origin !== expected.origin) {
    throw new Error(`instance metadata ${label} origin mismatch`);
  }
}

function expectedWsUrlForApiOrigin(apiOrigin) {
  const parsed = new URL(apiOrigin);
  parsed.protocol = parsed.protocol === "https:" ? "wss:" : "ws:";
  parsed.pathname = "/ws";
  parsed.search = "";
  parsed.hash = "";
  return parsed;
}

function rejectUnknownKeys(data, allowed, label) {
  for (const key of Object.keys(data ?? {})) {
    if (!allowed.has(key)) {
      throw new Error(`instance metadata exposes unexpected public field under ${label}`);
    }
  }
}

function requireCertificatePins(data) {
  if (data.certificatePins === undefined) return;
  if (!data.certificatePins || typeof data.certificatePins !== "object" || Array.isArray(data.certificatePins)) {
    throw new Error("instance metadata invalid security.certificatePins");
  }
  rejectUnknownKeys(data.certificatePins, CERTIFICATE_PINS_KEYS, "security.certificatePins");
  if (data.certificatePins.mode !== undefined) {
    requireEnum(data.certificatePins, "mode", CERTIFICATE_PIN_MODES, "security.certificatePins.mode");
  }
  if (data.certificatePins.sha256 === undefined) return;
  if (!Array.isArray(data.certificatePins.sha256) || data.certificatePins.sha256.length > 8) {
    throw new Error("instance metadata invalid security.certificatePins.sha256");
  }
  for (const pin of data.certificatePins.sha256) {
    if (typeof pin !== "string" || !CERTIFICATE_SHA256_HEX.test(pin)) {
      throw new Error("instance metadata invalid security.certificatePins.sha256");
    }
  }
}

export function validateInstanceMetadata(data, options = {}) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("instance metadata must be a JSON object");
  }
  rejectUnknownKeys(data, INSTANCE_METADATA_KEYS, "root");
  for (const key of [
    "name",
    "mode",
    "publicUrl",
    "apiUrl",
    "wsUrl",
    "docsUrl",
    "uploadPolicy",
    "registration",
    "billingMode",
    "emailProvider",
  ]) {
    requireString(data, key);
  }
  requireOptionalVersionString(data, "serverVersion", "serverVersion");
  requireOptionalVersionString(data, "minClientVersion", "minClientVersion");
  if (!ALLOWED_MODES.has(data.mode)) {
    throw new Error("instance metadata mode is invalid");
  }
  if (options.expectMode && data.mode !== options.expectMode) {
    throw new Error(`instance metadata mode mismatch: expected ${options.expectMode}`);
  }
  requireOriginUrl(data, "publicUrl", "publicUrl", ["https:", "http:"]);
  const apiUrl = requireOriginUrl(data, "apiUrl", "apiUrl", ["https:", "http:"]);
  assertSameOrigin(apiUrl, options.apiOrigin, "apiUrl");
  const wsUrl = requirePathUrl(data, "wsUrl", "wsUrl", ["wss:", "ws:"]);
  const expectedWsUrl = expectedWsUrlForApiOrigin(apiUrl.origin);
  if (wsUrl.origin !== expectedWsUrl.origin || wsUrl.pathname !== "/ws") {
    throw new Error("instance metadata invalid wsUrl");
  }
  requireNullablePathUrl(data, "cdnUrl", "cdnUrl");
  requirePathUrl(data, "docsUrl", "docsUrl", ["https:", "http:"]);
  requireEnum(data, "registration", REGISTRATION_MODES);
  requireEnum(data, "billingMode", BILLING_MODES);
  requireEnum(data, "emailProvider", EMAIL_PROVIDERS);
  requireEnum(data, "uploadPolicy", UPLOAD_POLICIES);
  requireBoolean(data, "officialNetworkLinked");
  requireTrustedHosts(data);

  if (data.contentScanning !== undefined && (data.contentScanning === null || typeof data.contentScanning !== "object" || Array.isArray(data.contentScanning))) {
    throw new Error("instance metadata invalid contentScanning");
  }
  if (data.contentScanning !== undefined) {
    rejectUnknownKeys(data.contentScanning, CONTENT_SCANNING_KEYS, "contentScanning");
    requireOptionalEnum(data.contentScanning, "provider", CONTENT_SCAN_PROVIDERS, "contentScanning.provider");
    requireOptionalBoolean(data.contentScanning, "enabled", "contentScanning.enabled");
  }

  if (data.security !== undefined && (data.security === null || typeof data.security !== "object" || Array.isArray(data.security))) {
    throw new Error("instance metadata invalid security");
  }
  if (data.security !== undefined) {
    rejectUnknownKeys(data.security, SECURITY_KEYS, "security");
    requireCertificatePins(data.security);
  }

  if (data.accountLinking !== undefined && (data.accountLinking === null || typeof data.accountLinking !== "object" || Array.isArray(data.accountLinking))) {
    throw new Error("instance metadata invalid accountLinking");
  }
  if (data.accountLinking !== undefined) {
    rejectUnknownKeys(data.accountLinking, ACCOUNT_LINKING_KEYS, "accountLinking");
    requireBoolean(data.accountLinking, "enabled", "accountLinking.enabled");
    requireEnum(data.accountLinking, "role", ACCOUNT_LINKING_ROLES, "accountLinking.role");
    if (data.accountLinking.proofAlgorithm !== "RS256") {
      throw new Error("instance metadata invalid accountLinking.proofAlgorithm");
    }
  }

  if (!data.capabilities || typeof data.capabilities !== "object") {
    throw new Error("instance metadata missing capabilities");
  }
  rejectUnknownKeys(data.capabilities, CAPABILITY_KEYS, "capabilities");
  for (const key of REQUIRED_CAPABILITIES) {
    if (key.startsWith("max")) {
      requireCapabilityNumber(
        data.capabilities,
        key,
        key === "maxUploadBytes" ? MAX_INSTANCE_UPLOAD_BYTES : MAX_INSTANCE_VOICE_BITRATE,
        `capabilities.${key}`,
      );
    } else {
      requireBoolean(data.capabilities, key, `capabilities.${key}`);
    }
  }

  return `${data.mode} instance metadata`;
}

async function withRequestTimeout(timeoutMs, operation) {
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
  } catch (error) {
    controller.abort();
    throw error;
  } finally {
    clearTimeout(timeoutId);
    operationPromise.catch(() => {});
  }
}

async function readTextWithLimit(response, label, maxBytes) {
  const cancelBody = () => {
    if (!response.body) return;
    response.body.cancel().catch(() => {
      // Best effort; the request timeout wrapper also aborts the fetch on errors.
    });
  };

  const lengthHeader = response.headers.get("content-length");
  if (lengthHeader) {
    const length = Number(lengthHeader);
    if (Number.isFinite(length) && length > maxBytes) {
      cancelBody();
      throw new Error(`${label} response too large`);
    }
  }

  if (!response.body) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > maxBytes) {
      throw new Error(`${label} response too large`);
    }
    return text;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytes = 0;
  let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) {
        reader.cancel().catch(() => {});
        throw new Error(`${label} response too large`);
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    return text;
  } finally {
    reader.releaseLock();
  }
}

async function fetchWithTimeout(fetchImpl, url, timeoutMs, handleResponse) {
  return withRequestTimeout(timeoutMs, async (signal) => {
    const response = await fetchImpl(url, {
      redirect: "manual",
      signal,
      headers: {
        "accept": "application/json,text/plain;q=0.8,*/*;q=0.5",
      },
    });
    return await handleResponse(response);
  });
}

async function readJson(response, label) {
  const text = await readTextWithLimit(response, label, MAX_INSTANCE_METADATA_BYTES);
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} did not return valid JSON`);
  }
}

export async function runLiveApiSmoke(options, deps = {}) {
  const apiBaseUrl = normalizeApiBaseUrl(options.apiBaseUrl);
  if (options.expectMode === "official" && !OFFICIAL_API_ORIGINS.has(apiBaseUrl)) {
    throw new Error("official live smoke requires pinned official API origin");
  }
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 10_000;
  const fetchImpl = deps.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("fetch is not available in this Node.js runtime");
  }

  const healthUrl = `${apiBaseUrl}/health`;
  await fetchWithTimeout(fetchImpl, healthUrl, timeoutMs, async (health) => {
    if (!health.ok) {
      throw new Error(`/health returned HTTP ${health.status}`);
    }
    await readTextWithLimit(health, "/health", MAX_HEALTH_BODY_BYTES);
  });

  const instanceUrl = `${apiBaseUrl}/api/instance`;
  const metadata = await fetchWithTimeout(fetchImpl, instanceUrl, timeoutMs, async (instance) => {
    if (!instance.ok) {
      throw new Error(`/api/instance returned HTTP ${instance.status}`);
    }
    return await readJson(instance, "/api/instance");
  });
  const metadataSummary = validateInstanceMetadata(metadata, {
    apiOrigin: apiBaseUrl,
    expectMode: options.expectMode,
  });

  return {
    ok: true,
    apiBaseUrl,
    summary: `healthy API; ${metadataSummary}`,
    metadata: options.includeMetadata ? metadata : undefined,
  };
}

function usage() {
  return `Usage:
  node deploy/check-live-api-smoke.mjs --api-base-url URL [options]

Options:
  --api-base-url URL        HTTPS API origin to check.
  --expect-mode MODE        Require official, standalone, linked, or federated mode.
  --timeout-ms N            Request timeout. Default: 10000.
  --json                    Print JSON result.
  --quiet                   Print only pass/fail summary.
  -h, --help                Show this help.`;
}

function parseArgs(argv) {
  const options = {
    apiBaseUrl: null,
    expectMode: null,
    timeoutMs: 10_000,
    json: false,
    quiet: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const requireValue = () => {
      const value = argv[i + 1];
      if (!value || value.startsWith("--")) {
        throw new Error(`${arg} requires a value`);
      }
      i += 1;
      return value;
    };

    switch (arg) {
      case "-h":
      case "--help":
        options.help = true;
        break;
      case "--api-base-url":
        options.apiBaseUrl = requireValue();
        break;
      case "--expect-mode":
        options.expectMode = requireValue();
        if (!ALLOWED_MODES.has(options.expectMode)) {
          throw new Error("--expect-mode must be official, standalone, linked, or federated");
        }
        break;
      case "--timeout-ms":
        options.timeoutMs = Number(requireValue());
        if (!Number.isFinite(options.timeoutMs) || options.timeoutMs < 1000) {
          throw new Error("--timeout-ms must be at least 1000");
        }
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

async function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
    if (options.help) {
      console.log(usage());
      return 0;
    }
    const result = await runLiveApiSmoke(options);
    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else if (!options.quiet) {
      console.log(`PASS live-api-smoke - ${result.summary}`);
    } else {
      console.log("PASS live-api-smoke");
    }
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (options?.json) {
      console.log(JSON.stringify({ ok: false, error: message }, null, 2));
    } else {
      console.error(`FAIL live-api-smoke - ${message}`);
      if (!options?.quiet) {
        console.error(usage());
      }
    }
    return 1;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fileURLToPath(pathToFileURL(process.argv[1]))) {
  process.exitCode = await main();
}
