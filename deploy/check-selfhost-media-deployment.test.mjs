import { createServer } from "node:http";
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  parseSelfHostMediaDeploymentArgs,
  runSelfHostMediaDeploymentCheck,
} from "./check-selfhost-media-deployment.mjs";

let server;
let baseUrl;
let flippingMetadataRequests = 0;

function metadata(overrides = {}) {
  return {
    name: "Community",
    mode: "standalone",
    serverVersion: "0.1.0",
    minClientVersion: "0.0.329",
    publicUrl: baseUrl,
    apiUrl: baseUrl,
    wsUrl: baseUrl.replace(/^http:/, "ws:") + "/ws",
    cdnUrl: `${baseUrl}/media`,
    docsUrl: `${baseUrl}/docs`,
    registration: "public",
    billingMode: "disabled",
    emailProvider: "disabled",
    uploadPolicy: "media_validation_only",
    contentScanning: {
      provider: "none",
      enabled: false,
    },
    officialNetworkLinked: false,
    trustedHosts: ["localhost"],
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
      maxUploadBytes: 26_214_400,
      maxVoiceBitrate: 256_000,
    },
    accountLinking: {
      enabled: false,
      role: "disabled",
      proofAlgorithm: "RS256",
    },
    ...overrides,
  };
}

before(async () => {
  server = createServer((req, res) => {
    const path = req.url.split("?", 1)[0];
    if (path === "/health") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
      return;
    }
    if (path === "/api/instance") {
      const response = metadata();
      if (req.headers["x-test-metadata"] === "open-media") {
        response.cdnUrl = `${baseUrl}/open-media`;
      } else if (req.headers["x-test-metadata"] === "no-cdn") {
        response.cdnUrl = null;
      } else if (req.headers["x-test-metadata"] === "flip-open-media") {
        flippingMetadataRequests += 1;
        if (flippingMetadataRequests > 1) {
          response.cdnUrl = `${baseUrl}/open-media`;
        }
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(response));
      return;
    }
    if (path === "/media/avatars/sample.webp" || path === "/split-media/avatars/sample.webp") {
      res.writeHead(206, { "Content-Type": "image/webp" });
      res.end("p");
      return;
    }
    if (path === "/open-media/avatars/sample.webp") {
      res.writeHead(206, { "Content-Type": "image/webp" });
      res.end("p");
      return;
    }
    if (path === "/open-media/attachments/private.webp") {
      res.writeHead(200, { "Content-Type": "image/webp" });
      res.end("private");
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

describe("self-host media deployment args", () => {
  it("requires a non-official expected mode", () => {
    assert.throws(
      () => parseSelfHostMediaDeploymentArgs([
        "--api-base-url",
        baseUrl,
        "--expect-mode",
        "official",
        "--attachment-key",
        "attachments/private.webp",
        "--attachment-id",
        "42",
        "--sample-url",
        "avatars/sample.webp",
      ]),
      /standalone, linked, or federated/,
    );

    assert.throws(
      () => parseSelfHostMediaDeploymentArgs([
        "--api-base-url",
        baseUrl,
        "--attachment-key",
        "attachments/private.webp",
        "--attachment-id",
        "42",
        "--sample-url",
        "avatars/sample.webp",
      ]),
      /expect-mode/,
    );
  });
});

describe("self-host media deployment check", () => {
  it("passes when metadata media origin denies attachments and serves public samples", async () => {
    const result = await runSelfHostMediaDeploymentCheck({
      apiBaseUrl: baseUrl,
      expectMode: "standalone",
      attachmentKey: "attachments/private.webp",
      attachmentId: "42",
      sampleUrls: ["avatars/sample.webp"],
      timeoutMs: 1000,
      maxRedirects: 3,
    });

    assert.equal(result.exitCode, 0);
    assert.equal(result.mediaBaseUrl, `${baseUrl}/media`);
    assert.equal(result.apiBaseUrl, baseUrl);
    assert.match(result.summary, /healthy API/);
  });

  it("fails when the advertised media origin serves raw attachments", async () => {
    const result = await runSelfHostMediaDeploymentCheck({
      apiBaseUrl: baseUrl,
      expectMode: "standalone",
      attachmentKey: "attachments/private.webp",
      attachmentId: "42",
      sampleUrls: ["avatars/sample.webp"],
      timeoutMs: 1000,
      maxRedirects: 3,
      headers: {
        "x-test-metadata": "open-media",
      },
    });

    assert.equal(result.exitCode, 1);
    assert.equal(result.media.securityFailures, 1);
  });

  it("supports an explicit split media origin", async () => {
    const result = await runSelfHostMediaDeploymentCheck({
      apiBaseUrl: baseUrl,
      mediaBaseUrl: `${baseUrl}/split-media`,
      expectMode: "standalone",
      attachmentKey: "attachments/private.webp",
      attachmentId: "42",
      sampleUrls: ["avatars/sample.webp"],
      timeoutMs: 1000,
      maxRedirects: 3,
      headers: {
        "x-test-metadata": "no-cdn",
      },
    });

    assert.equal(result.exitCode, 0);
    assert.equal(result.mediaBaseUrl, `${baseUrl}/split-media`);
  });

  it("uses the single validated metadata response when deriving the media origin", async () => {
    flippingMetadataRequests = 0;
    const result = await runSelfHostMediaDeploymentCheck({
      apiBaseUrl: baseUrl,
      expectMode: "standalone",
      attachmentKey: "attachments/private.webp",
      attachmentId: "42",
      sampleUrls: ["avatars/sample.webp"],
      timeoutMs: 1000,
      maxRedirects: 3,
      headers: {
        "x-test-metadata": "flip-open-media",
      },
    });

    assert.equal(result.exitCode, 0);
    assert.equal(result.mediaBaseUrl, `${baseUrl}/media`);
    assert.equal(flippingMetadataRequests, 1);
  });

  it("fails closed when strict canaries are missing", async () => {
    const result = await runSelfHostMediaDeploymentCheck({
      apiBaseUrl: baseUrl,
      expectMode: "standalone",
      attachmentKey: "attachments/private.webp",
      attachmentId: "",
      sampleUrls: [],
      timeoutMs: 1000,
      maxRedirects: 3,
    });

    assert.equal(result.exitCode, 3);
    assert.ok(result.media.inconclusive > 0);
  });
});
