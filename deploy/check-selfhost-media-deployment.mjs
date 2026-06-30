#!/usr/bin/env node
import { fileURLToPath, pathToFileURL } from "node:url";
import { normalizeApiBaseUrl, runLiveApiSmoke } from "./check-live-api-smoke.mjs";
import { normalizeBaseUrl, runCheck } from "./check-media-exposure.mjs";

const SELFHOST_MODES = new Set(["standalone", "linked", "federated"]);
const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_REDIRECTS = 3;

export function usage() {
  return `Usage:
  node deploy/check-selfhost-media-deployment.mjs --api-base-url URL --expect-mode MODE [options]

Checks a live self-host deployment's advertised media origin, reverse proxy,
and object-store boundary. MODE must be standalone, linked, or federated.

Options:
  --api-base-url URL        Self-host API origin to check.
  --media-base-url URL      Explicit public media origin. Defaults to /api/instance cdnUrl, then API origin.
  --expect-mode MODE        Required: standalone, linked, or federated.
  --attachment-key KEY      Existing private object key, e.g. attachments/1/2.webp.
  --attachment-id ID        Matching attachment id for /api/media/attachments/{id}.
  --sample-url URL|PATH     Expected public media sample. Repeatable.
  --timeout-ms N            Per-request timeout. Default: ${DEFAULT_TIMEOUT_MS}.
  --max-redirects N         Redirects to follow per request. Default: ${DEFAULT_MAX_REDIRECTS}.
  --json                    Print sanitized JSON result.
  --quiet                   Print only pass/fail summary.
  -h, --help                Show this help.

Exit codes:
  0 pass
  1 security/API failure
  2 invalid usage
  3 inconclusive/config failure`;
}

function requireValue(argv, index, arg) {
  const value = argv[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${arg} requires a value`);
  }
  return value;
}

function validateSelfHostMode(mode) {
  if (!SELFHOST_MODES.has(mode)) {
    throw new Error("--expect-mode must be standalone, linked, or federated");
  }
  return mode;
}

export function parseSelfHostMediaDeploymentArgs(argv) {
  const options = {
    apiBaseUrl: null,
    mediaBaseUrl: null,
    expectMode: null,
    attachmentKey: null,
    attachmentId: null,
    sampleUrls: [],
    timeoutMs: DEFAULT_TIMEOUT_MS,
    maxRedirects: DEFAULT_MAX_REDIRECTS,
    json: false,
    quiet: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const nextValue = () => {
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
        options.apiBaseUrl = nextValue();
        break;
      case "--media-base-url":
        options.mediaBaseUrl = nextValue();
        break;
      case "--expect-mode":
        options.expectMode = validateSelfHostMode(nextValue());
        break;
      case "--attachment-key":
        options.attachmentKey = nextValue();
        break;
      case "--attachment-id":
        options.attachmentId = nextValue();
        break;
      case "--sample-url":
        options.sampleUrls.push(nextValue());
        break;
      case "--timeout-ms":
        options.timeoutMs = Number(nextValue());
        if (!Number.isInteger(options.timeoutMs) || options.timeoutMs < 1000 || options.timeoutMs > 60000) {
          throw new Error("--timeout-ms must be an integer between 1000 and 60000");
        }
        break;
      case "--max-redirects":
        options.maxRedirects = Number(nextValue());
        if (!Number.isInteger(options.maxRedirects) || options.maxRedirects < 0 || options.maxRedirects > 10) {
          throw new Error("--max-redirects must be an integer between 0 and 10");
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

  if (!options.help) {
    if (!options.apiBaseUrl) {
      throw new Error("--api-base-url is required");
    }
    if (!options.expectMode) {
      throw new Error("--expect-mode is required and must be standalone, linked, or federated");
    }
    if (!options.attachmentKey) {
      throw new Error("--attachment-key is required");
    }
    if (!options.attachmentId) {
      throw new Error("--attachment-id is required");
    }
    if (options.sampleUrls.length === 0) {
      throw new Error("--sample-url is required at least once");
    }
  }

  return options;
}

function fetchWithHeaders(fetchImpl, extraHeaders = {}) {
  return async (url, init = {}) => {
    const headers = new Headers(init.headers ?? {});
    for (const [key, value] of Object.entries(extraHeaders ?? {})) {
      headers.set(key, value);
    }
    return fetchImpl(url, { ...init, headers });
  };
}

function mediaBaseFromMetadata(metadata, apiBaseUrl, explicitMediaBaseUrl) {
  if (explicitMediaBaseUrl) {
    return normalizeBaseUrl(explicitMediaBaseUrl);
  }
  if (typeof metadata?.cdnUrl === "string" && metadata.cdnUrl.trim()) {
    return normalizeBaseUrl(metadata.cdnUrl);
  }
  return normalizeBaseUrl(apiBaseUrl);
}

function mediaFailureSummary(media) {
  if (media.securityFailures > 0) {
    return `${media.securityFailures} forbidden attachment path(s) were publicly readable`;
  }
  if (media.inconclusive > 0) {
    return `${media.inconclusive} media check(s) were inconclusive`;
  }
  return "media boundary passed";
}

export async function runSelfHostMediaDeploymentCheck(options, deps = {}) {
  const expectMode = validateSelfHostMode(options.expectMode);
  const apiBaseUrl = normalizeApiBaseUrl(options.apiBaseUrl);
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : DEFAULT_TIMEOUT_MS;
  const maxRedirects = Number.isInteger(options.maxRedirects) ? options.maxRedirects : DEFAULT_MAX_REDIRECTS;
  const fetchImpl = fetchWithHeaders(deps.fetch ?? globalThis.fetch, options.headers);

  if (typeof (deps.fetch ?? globalThis.fetch) !== "function") {
    throw new Error("fetch is not available in this Node.js runtime");
  }

  let live;
  let metadata;
  try {
    live = await runLiveApiSmoke({
      apiBaseUrl,
      expectMode,
      timeoutMs,
      includeMetadata: true,
    }, { fetch: fetchImpl });
    metadata = live.metadata;
    if (!metadata) {
      throw new Error("/api/instance metadata was not returned by live smoke");
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      exitCode: 1,
      apiBaseUrl,
      mediaBaseUrl: null,
      summary: `API metadata check failed: ${message}`,
      error: message,
    };
  }

  let mediaBase;
  try {
    mediaBase = mediaBaseFromMetadata(metadata, apiBaseUrl, options.mediaBaseUrl);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      exitCode: 3,
      apiBaseUrl,
      mediaBaseUrl: null,
      summary: `media origin check failed: ${message}`,
      error: message,
      live,
    };
  }

  const media = await runCheck({
    mediaBaseUrl: mediaBase.toString(),
    apiBaseUrl,
    attachmentKey: options.attachmentKey,
    attachmentId: options.attachmentId,
    sampleUrls: options.sampleUrls ?? [],
    strict: true,
    timeoutMs,
    maxRedirects,
  });

  return {
    ok: media.ok,
    exitCode: media.exitCode,
    apiBaseUrl,
    mediaBaseUrl: mediaBase.toString(),
    expectedMode: expectMode,
    summary: `${live.summary}; ${mediaFailureSummary(media)}`,
    live,
    media,
  };
}

function sanitizeCheck(check) {
  return {
    kind: check.kind,
    status: check.status,
    fullGetStatus: check.fullGetStatus,
    ok: check.ok,
    securityFailure: Boolean(check.securityFailure),
    inconclusive: Boolean(check.inconclusive),
    error: check.error,
    fullGetError: check.fullGetError,
  };
}

function sanitizeResult(result) {
  return {
    ok: result.ok,
    exitCode: result.exitCode,
    apiBaseUrl: result.apiBaseUrl,
    mediaBaseUrl: result.mediaBaseUrl,
    expectedMode: result.expectedMode,
    summary: result.summary,
    error: result.error,
    media: result.media ? {
      ok: result.media.ok,
      exitCode: result.media.exitCode,
      securityFailures: result.media.securityFailures,
      inconclusive: result.media.inconclusive,
      usedRealAttachmentKey: result.media.usedRealAttachmentKey,
      usedRealAttachmentId: result.media.usedRealAttachmentId,
      checks: result.media.checks.map(sanitizeCheck),
    } : undefined,
  };
}

function printResult(result, options) {
  if (options.json) {
    console.log(JSON.stringify(sanitizeResult(result), null, 2));
    return;
  }
  const label = result.ok ? "PASS" : result.exitCode === 1 ? "FAIL" : "INCONCLUSIVE";
  console.log(`${label} selfhost-media-deployment - ${result.summary}`);
  if (!options.quiet && result.media) {
    console.log(`media checks: pass=${result.media.checks.filter((check) => check.ok).length} fail=${result.media.securityFailures} inconclusive=${result.media.inconclusive}`);
  }
}

async function main() {
  let options;
  try {
    options = parseSelfHostMediaDeploymentArgs(process.argv.slice(2));
    if (options.help) {
      console.log(usage());
      return 0;
    }
    const result = await runSelfHostMediaDeploymentCheck(options);
    printResult(result, options);
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
