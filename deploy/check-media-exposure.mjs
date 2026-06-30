#!/usr/bin/env node
import { fileURLToPath, pathToFileURL } from "node:url";

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_REDIRECTS = 3;
const DEFAULT_ATTACHMENT_KEY = "attachments/verdant-guardrail-check.webp";

export function usage() {
  return `Usage:
  node deploy/check-media-exposure.mjs --base-url URL [options]
  node deploy/check-media-exposure.mjs --media-base-url URL --api-base-url URL [options]

Checks that protected message attachment paths are not anonymously readable
from a self-host or official public media/API origin.

Options:
  --base-url URL          Public media/API origin to test. Required unless split origins are set.
  --media-base-url URL    Public media/CDN origin for raw object-key probes.
  --api-base-url URL      Public API origin for /api/media/attachments/{id} probes.
  --attachment-key KEY    Existing private object key, e.g. attachments/1/2.webp.
  --attachment-id ID      Existing private attachment id for /api/media/attachments/{id}.
  --sample-url URL|PATH   Expected public media sample. Repeatable.
  --strict                Fail inconclusive unless real attachment canaries are given.
  --timeout-ms N          Per-request timeout. Default: ${DEFAULT_TIMEOUT_MS}.
  --max-redirects N       Redirects to follow per request. Default: ${DEFAULT_MAX_REDIRECTS}.
  --json                  Print JSON result.
  -h, --help              Show this help.

Exit codes:
  0 pass
  1 security failure
  2 invalid usage
  3 inconclusive/config failure`;
}

function hasUnsafeRawChars(value) {
  return /[\u0000-\u001f\u007f\\]/.test(value);
}

function hasEncodedTraversal(value) {
  const lower = value.toLowerCase();
  return lower.includes("%2e") || lower.includes("%2f") || lower.includes("%5c");
}

function isLocalHost(hostname) {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}

export function normalizeBaseUrl(raw) {
  if (!raw || hasUnsafeRawChars(raw)) {
    throw new Error("base URL is empty or contains unsafe characters");
  }
  const parsed = new URL(raw);
  if (parsed.username || parsed.password || parsed.hash) {
    throw new Error("base URL must not include credentials or a fragment");
  }
  if (parsed.search) {
    throw new Error("base URL must not include query strings");
  }
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isLocalHost(parsed.hostname))) {
    throw new Error("base URL must use HTTPS unless it is localhost");
  }
  if (hasEncodedTraversal(parsed.pathname)) {
    throw new Error("base URL path contains an encoded traversal sequence");
  }
  parsed.hash = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  return parsed;
}

export function validateAttachmentKey(raw) {
  if (!raw || hasUnsafeRawChars(raw) || raw.startsWith("/") || hasEncodedTraversal(raw)) {
    throw new Error("attachment key is unsafe");
  }
  const parts = raw.split("/");
  if (parts.some((part) => part === "" || part === "." || part === "..")) {
    throw new Error("attachment key contains an invalid path segment");
  }
  if (parts[0].toLowerCase() !== "attachments") {
    throw new Error("attachment key must start with attachments/");
  }
  return parts.join("/");
}

export function joinBasePath(base, path) {
  const cleanPath = String(path).replace(/^\/+/, "");
  const next = new URL(base.toString());
  const basePath = next.pathname.replace(/\/+$/, "");
  next.pathname = `${basePath}/${cleanPath}`.replace(/\/{2,}/g, "/");
  next.search = `v=${Date.now().toString(36)}`;
  return next;
}

export function forbiddenPathsFor({ attachmentKey = DEFAULT_ATTACHMENT_KEY, attachmentId = null } = {}) {
  return [
    ...mediaForbiddenPathsFor(attachmentKey),
    ...apiForbiddenPathsFor(attachmentId),
  ];
}

function mediaForbiddenPathsFor(attachmentKey) {
  const key = validateAttachmentKey(attachmentKey);
  const rest = key.slice("attachments/".length);
  return [
    `attachments/${rest}`,
    `%61ttachments/${rest}`,
    `attach%6dents/${rest}`,
    `ATTACHMENTS/${rest}`,
    `cdn-cgi/image/width=256/attachments/${rest}`,
    `cdn-cgi/image/width=256/%61ttachments/${rest}`,
  ];
}

function apiForbiddenPathsFor(attachmentId) {
  if (attachmentId === null || attachmentId === undefined || String(attachmentId) === "") {
    return [];
  }
  const encodedId = encodeURIComponent(String(attachmentId));
  return [
    `api/media/attachments/${encodedId}`,
    `api/media/%61ttachments/${encodedId}`,
  ];
}

function parseArgs(argv) {
  const options = {
    baseUrl: null,
    mediaBaseUrl: null,
    apiBaseUrl: null,
    attachmentKey: null,
    attachmentId: null,
    sampleUrls: [],
    strict: false,
    timeoutMs: DEFAULT_TIMEOUT_MS,
    maxRedirects: DEFAULT_MAX_REDIRECTS,
    json: false,
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
      case "--base-url":
        options.baseUrl = requireValue();
        break;
      case "--media-base-url":
        options.mediaBaseUrl = requireValue();
        break;
      case "--api-base-url":
        options.apiBaseUrl = requireValue();
        break;
      case "--attachment-key":
        options.attachmentKey = requireValue();
        break;
      case "--attachment-id":
        options.attachmentId = requireValue();
        break;
      case "--sample-url":
      case "--public-path":
        options.sampleUrls.push(requireValue());
        break;
      case "--strict":
        options.strict = true;
        break;
      case "--timeout-ms":
        options.timeoutMs = Number(requireValue());
        if (!Number.isInteger(options.timeoutMs) || options.timeoutMs < 100 || options.timeoutMs > 60000) {
          throw new Error("--timeout-ms must be an integer between 100 and 60000");
        }
        break;
      case "--max-redirects":
        options.maxRedirects = Number(requireValue());
        if (!Number.isInteger(options.maxRedirects) || options.maxRedirects < 0 || options.maxRedirects > 10) {
          throw new Error("--max-redirects must be an integer between 0 and 10");
        }
        break;
      case "--json":
        options.json = true;
        break;
      default:
        throw new Error(`unknown option: ${arg}`);
    }
  }
  return options;
}

function sampleToUrl(base, raw) {
  if (!raw || hasUnsafeRawChars(raw) || hasEncodedTraversal(raw)) {
    throw new Error(`sample URL is unsafe: ${raw}`);
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(raw)) {
    const original = new URL(raw);
    if (original.search) {
      throw new Error("sample URL must not include query strings or signed URLs");
    }
    const parsed = normalizeBaseUrl(raw);
    return parsed;
  }
  return joinBasePath(base, raw);
}

function validateRedirectUrl(rawLocation, currentUrl, originalUrl) {
  if (!rawLocation || hasUnsafeRawChars(rawLocation)) {
    throw new Error("redirect location is empty or unsafe");
  }
  const next = new URL(rawLocation, currentUrl);
  if (next.username || next.password) {
    throw new Error("redirect target must not include credentials");
  }
  if (next.origin !== originalUrl.origin) {
    throw new Error("redirect target must stay on the same origin");
  }
  next.hash = "";
  return next;
}

async function fetchStatus(url, timeoutMs, maxRedirects, { range = true } = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const original = new URL(url.toString());
    let current = new URL(original.toString());
    let redirects = 0;
    while (true) {
      const response = await fetch(current, {
        method: "GET",
        redirect: "manual",
        headers: {
          ...(range ? { Range: "bytes=0-0" } : {}),
          "User-Agent": "verdant-media-exposure-check/1",
        },
        signal: controller.signal,
      });

      if (response.status < 300 || response.status >= 400) {
        return { status: response.status, finalUrl: current.toString(), redirects };
      }

      const location = response.headers.get("location");
      if (!location) {
        return { status: response.status, finalUrl: current.toString(), redirects };
      }
      if (redirects >= maxRedirects) {
        return { status: 0, finalUrl: current.toString(), redirects, error: `too many redirects after ${maxRedirects}` };
      }
      current = validateRedirectUrl(location, current, original);
      redirects += 1;
    }
  } catch (error) {
    return { status: 0, error: error instanceof Error ? error.message : String(error) };
  } finally {
    clearTimeout(timeout);
  }
}

function isPublicStatus(status) {
  return status >= 200 && status < 400;
}

function isDeniedStatus(status) {
  return status >= 400 && status < 500;
}

export async function runCheck(options) {
  if (!options.baseUrl && (!options.mediaBaseUrl || !options.apiBaseUrl)) {
    throw new Error("--base-url is required unless both --media-base-url and --api-base-url are set");
  }
  const base = options.baseUrl ? normalizeBaseUrl(options.baseUrl) : null;
  const mediaBase = normalizeBaseUrl(options.mediaBaseUrl ?? options.baseUrl);
  const apiBase = normalizeBaseUrl(options.apiBaseUrl ?? options.baseUrl);
  const realAttachmentKey = Boolean(options.attachmentKey);
  const realAttachmentId = options.attachmentId !== null && options.attachmentId !== undefined && String(options.attachmentId) !== "";
  const attachmentKey = options.attachmentKey ?? DEFAULT_ATTACHMENT_KEY;
  const forbidden = [
    ...mediaForbiddenPathsFor(attachmentKey).map((path) => ({ kind: "forbidden", path, url: joinBasePath(mediaBase, path) })),
    ...apiForbiddenPathsFor(options.attachmentId).map((path) => ({ kind: "forbidden", path, url: joinBasePath(apiBase, path) })),
  ];
  const samples = options.sampleUrls.map((raw) => ({
    kind: "public",
    path: raw,
    url: sampleToUrl(mediaBase, raw),
  }));

  const checks = [];
  let securityFailures = 0;
  let inconclusive = 0;

  for (const probe of [...forbidden, ...samples]) {
    const result = await fetchStatus(probe.url, options.timeoutMs, options.maxRedirects ?? DEFAULT_MAX_REDIRECTS, { range: true });
    let fullGetResult = null;
    if (probe.kind === "forbidden" && isDeniedStatus(result.status)) {
      fullGetResult = await fetchStatus(probe.url, options.timeoutMs, options.maxRedirects ?? DEFAULT_MAX_REDIRECTS, { range: false });
    }
    const record = {
      kind: probe.kind,
      path: probe.path,
      url: probe.url.toString(),
      status: result.status,
      finalUrl: result.finalUrl,
      redirects: result.redirects,
      error: result.error,
      fullGetStatus: fullGetResult?.status,
      fullGetFinalUrl: fullGetResult?.finalUrl,
      fullGetError: fullGetResult?.error,
      ok: false,
    };

    if (probe.kind === "forbidden") {
      if (fullGetResult && isPublicStatus(fullGetResult.status)) {
        record.securityFailure = true;
        securityFailures += 1;
      } else if (fullGetResult && isDeniedStatus(fullGetResult.status)) {
        record.ok = true;
      } else if (fullGetResult) {
        record.inconclusive = true;
        inconclusive += 1;
      } else if (isDeniedStatus(result.status)) {
        record.ok = true;
      } else if (isPublicStatus(result.status)) {
        record.securityFailure = true;
        securityFailures += 1;
      } else {
        record.inconclusive = true;
        inconclusive += 1;
      }
    } else if (isPublicStatus(result.status)) {
      record.ok = true;
    } else {
      record.inconclusive = true;
      inconclusive += 1;
    }
    checks.push(record);
  }

  if (options.strict && !realAttachmentKey) {
    inconclusive += 1;
    checks.push({
      kind: "strict",
      path: "--attachment-key",
      url: "",
      status: 0,
      ok: false,
      inconclusive: true,
      error: "--strict requires a real attachment key",
    });
  }
  if (options.strict && !realAttachmentId) {
    inconclusive += 1;
    checks.push({
      kind: "strict",
      path: "--attachment-id",
      url: "",
      status: 0,
      ok: false,
      inconclusive: true,
      error: "--strict requires a real attachment id",
    });
  }

  return {
    ok: securityFailures === 0 && inconclusive === 0,
    exitCode: securityFailures > 0 ? 1 : inconclusive > 0 ? 3 : 0,
    securityFailures,
    inconclusive,
    baseUrl: base?.toString() ?? null,
    mediaBaseUrl: mediaBase.toString(),
    apiBaseUrl: apiBase.toString(),
    usedRealAttachmentKey: realAttachmentKey,
    usedRealAttachmentId: realAttachmentId,
    checks,
  };
}

function printResult(result, json) {
  if (json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  console.log(`Checking media exposure at media=${result.mediaBaseUrl} api=${result.apiBaseUrl}`);
  if (!result.usedRealAttachmentKey) {
    console.log("WARN no real --attachment-key supplied; synthetic probes cannot prove existing objects are private.");
  }
  if (!result.usedRealAttachmentId) {
    console.log("WARN no real --attachment-id supplied; the unauthenticated API attachment route was not probed.");
  }
  for (const check of result.checks) {
    const label = check.ok ? "PASS" : check.securityFailure ? "FAIL" : "INCONCLUSIVE";
    const status = check.status || "000";
    console.log(`${label} ${check.kind} ${status} ${check.url || check.path}`);
    if (check.fullGetStatus) {
      console.log(`  full-get ${check.fullGetStatus} ${check.fullGetFinalUrl || ""}`.trimEnd());
    }
    if (check.error) {
      console.log(`  ${check.error}`);
    }
  }
  if (result.ok) {
    console.log("Media exposure check passed.");
  } else if (result.securityFailures > 0) {
    console.error(`Media exposure check failed: ${result.securityFailures} forbidden path(s) were public.`);
  } else {
    console.error(`Media exposure check inconclusive: ${result.inconclusive} check(s) did not return expected status.`);
  }
}

async function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
    if (options.help) {
      console.log(usage());
      return 0;
    }
    if (!options.baseUrl && (!options.mediaBaseUrl || !options.apiBaseUrl)) {
      throw new Error("--base-url is required unless both --media-base-url and --api-base-url are set");
    }
    const result = await runCheck(options);
    printResult(result, options.json);
    return result.exitCode;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    console.error(usage());
    return 2;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fileURLToPath(pathToFileURL(process.argv[1]))) {
  process.exitCode = await main();
}
