import { createServer } from "node:http";
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  forbiddenPathsFor,
  joinBasePath,
  normalizeBaseUrl,
  runCheck,
  validateAttachmentKey,
} from "./check-media-exposure.mjs";

let server;
let baseUrl;

before(async () => {
  server = createServer((req, res) => {
    const path = req.url.split("?", 1)[0];
    if (path === "/avatars/sample.webp") {
      res.writeHead(206, { "Content-Type": "image/webp" });
      res.end("p");
      return;
    }
    if (path === "/split-media/avatars/sample.webp") {
      res.writeHead(206, { "Content-Type": "image/webp" });
      res.end("p");
      return;
    }
    if (path.startsWith("/split-media/attachments/") || path.startsWith("/split-api/api/media/attachments/")) {
      res.writeHead(403, { "Content-Type": "text/plain" });
      res.end("forbidden");
      return;
    }
    if (path === "/public-attachment/attachments/private.webp") {
      res.writeHead(200, { "Content-Type": "image/webp" });
      res.end("private");
      return;
    }
    if (path === "/range-blocked/attachments/private.webp") {
      if (req.headers.range) {
        res.writeHead(416, { "Content-Type": "text/plain" });
        res.end("range blocked");
        return;
      }
      res.writeHead(200, { "Content-Type": "image/webp" });
      res.end("private");
      return;
    }
    if (path.startsWith("/redirect-denied/attachments/")) {
      res.writeHead(302, { Location: "/attachments/private.webp" });
      res.end();
      return;
    }
    if (path.startsWith("/redirect-open/attachments/")) {
      res.writeHead(302, { Location: "/avatars/sample.webp" });
      res.end();
      return;
    }
    if (path.startsWith("/redirect-cross-origin/attachments/")) {
      res.writeHead(302, { Location: "https://example.com/avatars/sample.webp" });
      res.end();
      return;
    }
    if (path.startsWith("/redirect-loop/attachments/")) {
      res.writeHead(302, { Location: path });
      res.end();
      return;
    }
    if (path.includes("attachments") || path.includes("%61ttachments") || path.includes("attach%6dents")) {
      res.writeHead(403, { "Content-Type": "text/plain" });
      res.end("forbidden");
      return;
    }
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("not found");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

describe("check-media-exposure URL handling", () => {
  it("builds forbidden raw and encoded attachment paths", () => {
    assert.deepEqual(forbiddenPathsFor(), [
      "attachments/verdant-guardrail-check.webp",
      "%61ttachments/verdant-guardrail-check.webp",
      "attach%6dents/verdant-guardrail-check.webp",
      "ATTACHMENTS/verdant-guardrail-check.webp",
      "cdn-cgi/image/width=256/attachments/verdant-guardrail-check.webp",
      "cdn-cgi/image/width=256/%61ttachments/verdant-guardrail-check.webp",
    ]);
    assert.deepEqual(forbiddenPathsFor({
      attachmentKey: "attachments/123/456.webp",
      attachmentId: "456",
    }), [
      "attachments/123/456.webp",
      "%61ttachments/123/456.webp",
      "attach%6dents/123/456.webp",
      "ATTACHMENTS/123/456.webp",
      "cdn-cgi/image/width=256/attachments/123/456.webp",
      "cdn-cgi/image/width=256/%61ttachments/123/456.webp",
      "api/media/attachments/456",
      "api/media/%61ttachments/456",
    ]);
  });

  it("keeps base path prefixes when joining probe paths", () => {
    const base = normalizeBaseUrl("http://localhost:9000/verdant-uploads/");
    assert.equal(
      joinBasePath(base, "/avatars/sample.webp").toString().replace(/\?v=.*/, ""),
      "http://localhost:9000/verdant-uploads/avatars/sample.webp",
    );
  });

  it("rejects unsafe attachment keys", () => {
    assert.equal(validateAttachmentKey("attachments/1/2.webp"), "attachments/1/2.webp");
    assert.throws(() => validateAttachmentKey("avatars/1.webp"));
    assert.throws(() => validateAttachmentKey("attachments/../2.webp"));
    assert.throws(() => validateAttachmentKey("attachments/%2e%2e/2.webp"));
  });
});

describe("check-media-exposure probes", () => {
  it("passes when forbidden paths deny and public samples read", async () => {
    const result = await runCheck({
      baseUrl,
      attachmentKey: "attachments/private.webp",
      attachmentId: "42",
      sampleUrls: ["avatars/sample.webp"],
      strict: true,
      timeoutMs: 1000,
      maxRedirects: 3,
    });
    assert.equal(result.exitCode, 0);
    assert.equal(result.securityFailures, 0);
    assert.equal(result.inconclusive, 0);
  });

  it("fails when a forbidden attachment path is publicly readable", async () => {
    const result = await runCheck({
      baseUrl: `${baseUrl}/public-attachment`,
      attachmentKey: "attachments/private.webp",
      attachmentId: null,
      sampleUrls: [],
      strict: true,
      timeoutMs: 1000,
      maxRedirects: 3,
    });
    assert.equal(result.exitCode, 1);
    assert.equal(result.securityFailures, 1);
  });

  it("fails when range requests deny but full GET is public", async () => {
    const result = await runCheck({
      baseUrl: `${baseUrl}/range-blocked`,
      attachmentKey: "attachments/private.webp",
      attachmentId: "42",
      sampleUrls: [],
      strict: true,
      timeoutMs: 1000,
      maxRedirects: 3,
    });
    assert.equal(result.exitCode, 1);
    assert.equal(result.securityFailures, 1);
    assert.equal(result.checks[0].status, 416);
    assert.equal(result.checks[0].fullGetStatus, 200);
  });

  it("supports split media and API origins", async () => {
    const result = await runCheck({
      mediaBaseUrl: `${baseUrl}/split-media`,
      apiBaseUrl: `${baseUrl}/split-api`,
      attachmentKey: "attachments/private.webp",
      attachmentId: "42",
      sampleUrls: ["avatars/sample.webp"],
      strict: true,
      timeoutMs: 1000,
      maxRedirects: 3,
    });
    assert.equal(result.exitCode, 0);
    assert.equal(result.mediaBaseUrl, `${baseUrl}/split-media`);
    assert.equal(result.apiBaseUrl, `${baseUrl}/split-api`);
  });

  it("is inconclusive in strict mode without a real attachment key", async () => {
    const result = await runCheck({
      baseUrl,
      attachmentKey: null,
      attachmentId: null,
      sampleUrls: [],
      strict: true,
      timeoutMs: 1000,
      maxRedirects: 3,
    });
    assert.equal(result.exitCode, 3);
  });

  it("is inconclusive in strict mode without a real attachment id", async () => {
    const result = await runCheck({
      baseUrl,
      attachmentKey: "attachments/private.webp",
      attachmentId: null,
      sampleUrls: [],
      strict: true,
      timeoutMs: 1000,
      maxRedirects: 3,
    });
    assert.equal(result.exitCode, 3);
    assert.match(result.checks.at(-1).error, /attachment id/);
  });

  it("follows bounded redirects and preserves forbidden exposure failures", async () => {
    const denied = await runCheck({
      baseUrl: `${baseUrl}/redirect-denied`,
      attachmentKey: "attachments/private.webp",
      attachmentId: "42",
      sampleUrls: [],
      strict: true,
      timeoutMs: 1000,
      maxRedirects: 3,
    });
    assert.equal(denied.exitCode, 0);

    const open = await runCheck({
      baseUrl: `${baseUrl}/redirect-open`,
      attachmentKey: "attachments/private.webp",
      attachmentId: "42",
      sampleUrls: [],
      strict: true,
      timeoutMs: 1000,
      maxRedirects: 3,
    });
    assert.equal(open.exitCode, 1);
    assert.equal(open.securityFailures, 1);
  });

  it("marks redirect loops inconclusive", async () => {
    const result = await runCheck({
      baseUrl: `${baseUrl}/redirect-loop`,
      attachmentKey: "attachments/private.webp",
      attachmentId: "42",
      sampleUrls: [],
      strict: true,
      timeoutMs: 1000,
      maxRedirects: 1,
    });
    assert.equal(result.exitCode, 3);
    assert.match(result.checks[0].error, /too many redirects/);
  });

  it("does not follow cross-origin redirects", async () => {
    const result = await runCheck({
      baseUrl: `${baseUrl}/redirect-cross-origin`,
      attachmentKey: "attachments/private.webp",
      attachmentId: "42",
      sampleUrls: [],
      strict: true,
      timeoutMs: 1000,
      maxRedirects: 3,
    });
    assert.equal(result.exitCode, 3);
    assert.match(result.checks[0].error, /same origin/);
  });
});
