import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  normalizeApiBaseUrl,
  runLiveApiSmoke,
  validateInstanceMetadata,
} from "./check-live-api-smoke.mjs";

function validMetadata(overrides = {}) {
  return {
    name: "Community",
    mode: "standalone",
    serverVersion: "0.1.0",
    minClientVersion: "0.0.329",
    publicUrl: "https://community.example",
    apiUrl: "https://api.community.example",
    wsUrl: "wss://api.community.example/ws",
    cdnUrl: null,
    docsUrl: "https://community.example/docs",
    registration: "public",
    billingMode: "disabled",
    emailProvider: "disabled",
    uploadPolicy: "media_validation_only",
    contentScanning: {
      provider: "none",
      enabled: false,
    },
    security: {
      certificatePins: {
        sha256: ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        mode: "advisory",
      },
    },
    officialNetworkLinked: false,
    trustedHosts: ["community.example"],
    capabilities: {
      imageUploads: true,
      fileSharing: true,
      messageAttachments: true,
      voiceChat: true,
      videoStreaming: false,
      crossServerEmoji: false,
      animatedAvatar: false,
      animatedBanner: false,
      memberListBanner: false,
      maxUploadBytes: 10485760,
      maxVoiceBitrate: 64000,
    },
    accountLinking: {
      enabled: false,
      role: "disabled",
      proofAlgorithm: "RS256",
    },
    ...overrides,
  };
}

function encodeRepeated(value, rounds) {
  let encoded = value;
  for (let i = 0; i < rounds; i += 1) {
    encoded = encodeURIComponent(encoded);
  }
  return encoded;
}

function delayedTextResponse(text, delayMs, init = {}) {
  return new Response(new ReadableStream({
    start(controller) {
      setTimeout(() => {
        controller.enqueue(new TextEncoder().encode(text));
        controller.close();
      }, delayMs);
    },
  }), init);
}

function oversizedStreamingResponse(label, onCancel, size = 2048) {
  return new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(`${label}${"x".repeat(size)}`));
    },
    cancel() {
      onCancel();
    },
  }), { status: 200 });
}

describe("live API smoke URL validation", () => {
  it("accepts HTTPS origins and local HTTP origins only", () => {
    assert.equal(normalizeApiBaseUrl("api.community.example"), "https://api.community.example");
    assert.equal(normalizeApiBaseUrl("https://api.community.example/"), "https://api.community.example");
    assert.equal(normalizeApiBaseUrl("http://localhost:3001"), "http://localhost:3001");

    assert.throws(() => normalizeApiBaseUrl("http://api.community.example"), /HTTPS/);
    assert.throws(() => normalizeApiBaseUrl("https://api.community.example/path"), /origin/);
    assert.throws(() => normalizeApiBaseUrl("https://user:pass@api.community.example"), /credentials/);
    assert.throws(() => normalizeApiBaseUrl("https://api.community.example?x=1"), /origin/);
  });
});

describe("live API smoke metadata validation", () => {
  it("accepts the expected public instance metadata shape", () => {
    assert.equal(validateInstanceMetadata(validMetadata(), { expectMode: "standalone" }), "standalone instance metadata");
    assert.equal(
      validateInstanceMetadata(validMetadata({
        serverVersion: "unknown",
        minClientVersion: "unknown",
      }), { expectMode: "standalone" }),
      "standalone instance metadata",
    );
  });

  it("accepts the deployed official compatibility metadata shape", () => {
    const currentOfficialShape = validMetadata({
      name: "Verdant",
      mode: "official",
      publicUrl: "https://verdant.chat",
      apiUrl: "https://api.verdant.chat",
      wsUrl: "wss://api.verdant.chat/ws",
      cdnUrl: "https://cdn.pryzmapp.com",
      docsUrl: "https://verdant.chat/docs",
      billingMode: "official_stripe",
      emailProvider: "resend",
      uploadPolicy: "operator_managed",
      officialNetworkLinked: true,
      trustedHosts: ["verdant.chat"],
      capabilities: {
        imageUploads: false,
        fileSharing: false,
        messageAttachments: false,
        voiceChat: true,
        videoStreaming: false,
        crossServerEmoji: false,
        animatedAvatar: true,
        animatedBanner: true,
        memberListBanner: true,
        maxUploadBytes: 26214400,
        maxVoiceBitrate: 256000,
      },
    });
    delete currentOfficialShape.serverVersion;
    delete currentOfficialShape.minClientVersion;
    delete currentOfficialShape.contentScanning;
    delete currentOfficialShape.security;
    delete currentOfficialShape.accountLinking;

    assert.equal(
      validateInstanceMetadata(currentOfficialShape, {
        apiOrigin: "https://api.verdant.chat",
        expectMode: "official",
      }),
      "official instance metadata",
    );
  });

  it("fails closed when required capability and policy fields are missing", () => {
    const missingMessageAttachments = validMetadata();
    delete missingMessageAttachments.capabilities.messageAttachments;
    assert.throws(
      () => validateInstanceMetadata(missingMessageAttachments),
      /capabilities\.messageAttachments/,
    );
    assert.equal(
      validateInstanceMetadata(validMetadata({ contentScanning: { enabled: false } })),
      "standalone instance metadata",
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({ contentScanning: null })),
      /contentScanning/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({ accountLinking: null })),
      /accountLinking/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({ security: null })),
      /security/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        contentScanning: {
          provider: "sk_live_should_not_be_public",
          enabled: true,
        },
      })),
      /contentScanning\.provider/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({ accountLinking: { enabled: false } })),
      /accountLinking\.role/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        security: {
          certificatePins: {
            sha256: ["not-a-fingerprint"],
            mode: "advisory",
          },
        },
      })),
      /security\.certificatePins\.sha256/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        security: {
          certificatePins: {
            sha256: ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            mode: "enforced",
          },
        },
      })),
      /security\.certificatePins\.mode/,
    );
  });

  it("fails closed when public metadata includes secret-bearing extras", () => {
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        contentScanning: {
          provider: "mock",
          enabled: true,
          apiKey: "secret",
        },
      })),
      /unexpected public field under contentScanning/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        bucketName: "private-bucket",
      })),
      /unexpected public field under root/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        capabilities: {
          ...validMetadata().capabilities,
          secretKey: "secret",
        },
      })),
      /unexpected public field under capabilities/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        accountLinking: {
          enabled: true,
          role: "consumer",
          proofAlgorithm: "RS256",
          token: "secret",
        },
      })),
      /unexpected public field under accountLinking/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        security: {
          certificatePins: {
            sha256: ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            mode: "advisory",
            bearerToken: "secret",
          },
        },
      })),
      /unexpected public field under security\.certificatePins/,
    );
  });

  it("does not echo untrusted metadata keys or invalid values in errors", async () => {
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        sk_live_SYNTHETICSECRET12345678: "secret",
      })),
      (error) => {
        assert.match(error.message, /unexpected public field under root/);
        assert.doesNotMatch(error.message, /sk_live/);
        assert.doesNotMatch(error.message, /SYNTHETICSECRET/);
        return true;
      },
    );

    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        mode: "official\nforged-log-line sk_live_SYNTHETICSECRET12345678",
      })),
      (error) => {
        assert.match(error.message, /instance metadata invalid mode/);
        assert.doesNotMatch(error.message, /forged-log-line/);
        assert.doesNotMatch(error.message, /sk_live/);
        return true;
      },
    );

    await assert.rejects(
      () => runLiveApiSmoke({
        apiBaseUrl: "https://api.community.example",
        expectMode: "federated",
      }, {
        fetch: async (url) => {
          if (String(url).endsWith("/health")) {
            return new Response("ok", { status: 200 });
          }
          return new Response(JSON.stringify(validMetadata({ mode: "standalone" })), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        },
      }),
      (error) => {
        assert.match(error.message, /mode mismatch: expected federated/);
        assert.doesNotMatch(error.message, /standalone/);
        return true;
      },
    );
  });

  it("fails closed when allowed public strings carry attachment keys or secret-like values", () => {
    for (const overrides of [
      { name: "attachments/channel/private.webp" },
      { name: "attach%6dents/channel/private.webp" },
      { name: "attachments%25252Fchannel%25252Fprivate.webp" },
      { name: encodeRepeated("attachments/channel/private.webp", 7) },
      { name: "https://private-bucket.s3.us-east-1.amazonaws.com/media" },
      { name: "private-bucket.accountid.r2.cloudflarestorage.com/media" },
      { name: "private-bucket.s3.us-east-1.amazonaws.com/media" },
      { name: "storage.googleapis.com/private-bucket/media" },
      { name: "https://pub-abc123.r2.dev/media" },
      { serverVersion: "attachments/channel/private.webp" },
      { minClientVersion: "https://api.community.example/api/media/attachments/123" },
      { serverVersion: "sk_live_should_not_be_public" },
      { name: "client_secret=should-not-be-public" },
    ]) {
      assert.throws(
        () => validateInstanceMetadata(validMetadata(overrides)),
        /instance metadata invalid/,
      );
    }
  });

  it("fails closed when version fields are not version-shaped or unknown", () => {
    for (const overrides of [
      { serverVersion: "test" },
      { minClientVersion: "latest" },
      { serverVersion: "0.1" },
    ]) {
      assert.throws(
        () => validateInstanceMetadata(validMetadata(overrides)),
        /Version/,
      );
    }
  });

  it("fails closed when allowed public metadata fields carry object payloads", () => {
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        cdnUrl: {
          bucketName: "private-bucket",
        },
      })),
      /cdnUrl/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        trustedHosts: [{ token: "secret" }],
      })),
      /trustedHosts/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        accountLinking: {
          enabled: true,
          role: "consumer",
          proofAlgorithm: { privateKey: "secret" },
        },
      })),
      /accountLinking\.proofAlgorithm/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        security: {
          certificatePins: {
            sha256: [{ privateKey: "secret" }],
            mode: "advisory",
          },
        },
      })),
      /security\.certificatePins\.sha256/,
    );
  });

  it("fails closed on invalid public metadata enums and URL fields", () => {
    assert.throws(
      () => validateInstanceMetadata(validMetadata({ docsUrl: { objectKey: "secret" } })),
      /docsUrl/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({ uploadPolicy: "secret_policy" })),
      /uploadPolicy/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        accountLinking: {
          enabled: true,
          role: "admin",
          proofAlgorithm: "RS256",
        },
      })),
      /accountLinking\.role/,
    );
  });

  it("fails closed on secret-bearing URLs and malformed trusted hosts", () => {
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        cdnUrl: "https://access:secret@cdn.example/attachments/private.webp?sig=abc#frag",
      })),
      /cdnUrl/,
    );
    for (const cdnUrl of [
      "https://cdn.community.example/media/client_secret=should-not-be-public",
      "https://cdn.community.example/media/sk_live_should_not_be_public",
      "https://cdn.community.example/media/access_token=should-not-be-public",
    ]) {
      assert.throws(
        () => validateInstanceMetadata(validMetadata({ cdnUrl })),
        /cdnUrl/,
      );
    }
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        apiUrl: "https://api.community.example/path?token=secret#frag",
      })),
      /apiUrl/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        publicUrl: "http://community.example",
      })),
      /publicUrl/,
    );
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        trustedHosts: ["bucket.example/attachments/private.webp?token=secret"],
      })),
      /trustedHosts/,
    );
  });

  it("fails closed on raw object storage provider origins in public metadata", () => {
    for (const cdnUrl of [
      "https://private-bucket.accountid.r2.cloudflarestorage.com/media",
      "https://private-bucket.accountid.r2.cloudflarestorage.com./media",
      "https://pub-abc123.r2.dev/media",
      "https://pub-abc123.r2.dev./media",
      "https://private-bucket.s3.amazonaws.com/media",
      "https://private-bucket.s3.amazonaws.com./media",
      "https://private-bucket.s3.us-east-1.amazonaws.com/media",
      "https://storage.googleapis.com/private-bucket/media",
      "https://storage.googleapis.com./private-bucket/media",
    ]) {
      assert.throws(
        () => validateInstanceMetadata(validMetadata({ cdnUrl })),
        /cdnUrl/,
      );
    }

    for (const trustedHosts of [
      ["private-bucket.accountid.r2.cloudflarestorage.com"],
      ["private-bucket.accountid.r2.cloudflarestorage.com."],
      ["pub-abc123.r2.dev"],
      ["pub-abc123.r2.dev."],
      ["private-bucket.s3.us-east-1.amazonaws.com"],
      ["private-bucket.s3.us-east-1.amazonaws.com."],
      ["storage.googleapis.com"],
      ["storage.googleapis.com."],
    ]) {
      assert.throws(
        () => validateInstanceMetadata(validMetadata({ trustedHosts })),
        /trustedHosts/,
      );
    }
  });

  it("accepts public CDN path prefixes but rejects attachment paths", () => {
    assert.equal(
      validateInstanceMetadata(validMetadata({ cdnUrl: "https://cdn.community.example/media" })),
      "standalone instance metadata",
    );
    for (const cdnUrl of [
      "https://cdn.community.example/attachments",
      "https://cdn.community.example/%61ttachments/private.webp",
      "https://cdn.community.example/attach%6dents/private.webp",
      "https://cdn.community.example/attachments%2Fprivate.webp",
      "https://cdn.community.example/cdn-cgi/image/width=256/%61ttachments/private.webp",
      "https://cdn.community.example/%2e%2e/avatars/sample.webp",
    ]) {
      assert.throws(
        () => validateInstanceMetadata(validMetadata({ cdnUrl })),
        /cdnUrl/,
      );
    }
    assert.throws(
      () => validateInstanceMetadata(validMetadata({
        docsUrl: "https://community.example/%61ttachments/private.webp",
      })),
      /docsUrl/,
    );
  });

  it("fails closed on malformed trusted host patterns", () => {
    for (const trustedHosts of [
      ["*.example.com"],
      ["-bad.example"],
      ["bad..example"],
      ["bad.example-"],
      ["bad%2eexample.com"],
      ["bad_example.com"],
    ]) {
      assert.throws(
        () => validateInstanceMetadata(validMetadata({ trustedHosts })),
        /trustedHosts/,
      );
    }
  });

  it("fails closed on invalid capability numeric limits", () => {
    for (const capabilities of [
      { ...validMetadata().capabilities, maxUploadBytes: -1 },
      { ...validMetadata().capabilities, maxUploadBytes: 1024 * 1024 * 1024 + 1 },
      { ...validMetadata().capabilities, maxVoiceBitrate: 512001 },
      { ...validMetadata().capabilities, maxVoiceBitrate: 64000.5 },
    ]) {
      assert.throws(
        () => validateInstanceMetadata(validMetadata({ capabilities })),
        /capabilities\./,
      );
    }
  });
});

describe("live API smoke runner", () => {
  it("pins official-mode live smoke to the official API origin", async () => {
    await assert.rejects(
      () => runLiveApiSmoke({
        apiBaseUrl: "https://api.fake-official.example",
        expectMode: "official",
      }, {
        fetch: async () => {
          throw new Error("fetch should not run for unpinned official origins");
        },
      }),
      /pinned official API origin/,
    );
  });

  it("checks health and instance metadata without leaking response bodies on success", async () => {
    const calls = [];
    const result = await runLiveApiSmoke({
      apiBaseUrl: "https://api.community.example",
      expectMode: "standalone",
    }, {
      fetch: async (url) => {
        calls.push(String(url));
        if (String(url).endsWith("/health")) {
          return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(JSON.stringify(validMetadata()), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    });

    assert.equal(result.ok, true);
    assert.deepEqual(calls, [
      "https://api.community.example/health",
      "https://api.community.example/api/instance",
    ]);
    assert.match(result.summary, /standalone instance metadata/);
  });

  it("fails when returned apiUrl does not match the smoked API origin", async () => {
    await assert.rejects(
      () => runLiveApiSmoke({
        apiBaseUrl: "https://api.community.example",
        expectMode: "standalone",
      }, {
        fetch: async (url) => {
          if (String(url).endsWith("/health")) {
            return new Response(JSON.stringify({ ok: true }), {
              status: 200,
              headers: { "content-type": "application/json" },
            });
          }
          return new Response(JSON.stringify(validMetadata({
            apiUrl: "https://api.verdant.chat",
            wsUrl: "wss://api.verdant.chat/ws",
          })), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        },
      }),
      /apiUrl origin mismatch/,
    );
  });

  it("applies the timeout to response body reads", async () => {
    await assert.rejects(
      () => runLiveApiSmoke({
        apiBaseUrl: "https://api.community.example",
        expectMode: "standalone",
        timeoutMs: 10,
      }, {
        fetch: async (url) => {
          if (String(url).endsWith("/health")) {
            return new Response("ok", { status: 200 });
          }
          return delayedTextResponse(JSON.stringify(validMetadata()), 75, {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        },
      }),
      /timed out/,
    );
  });

  it("rejects oversized health and instance metadata bodies", async () => {
    await assert.rejects(
      () => runLiveApiSmoke({
        apiBaseUrl: "https://api.community.example",
        expectMode: "standalone",
      }, {
        fetch: async (url) => {
          if (String(url).endsWith("/health")) {
            return new Response("x".repeat(2048), {
              status: 200,
              headers: { "content-length": "2048" },
            });
          }
          return new Response(JSON.stringify(validMetadata()), { status: 200 });
        },
      }),
      /\/health response too large/,
    );

    await assert.rejects(
      () => runLiveApiSmoke({
        apiBaseUrl: "https://api.community.example",
        expectMode: "standalone",
      }, {
        fetch: async (url) => {
          if (String(url).endsWith("/health")) {
            return new Response("ok", { status: 200 });
          }
          return new Response("x".repeat(70 * 1024), {
            status: 200,
            headers: {
              "content-length": String(70 * 1024),
              "content-type": "application/json",
            },
          });
        },
      }),
      /\/api\/instance response too large/,
    );
  });

  it("cancels oversized streaming response bodies", async () => {
    let healthCanceled = false;
    await assert.rejects(
      () => runLiveApiSmoke({
        apiBaseUrl: "https://api.community.example",
        expectMode: "standalone",
      }, {
        fetch: async (url) => {
          if (String(url).endsWith("/health")) {
            return oversizedStreamingResponse("health", () => {
              healthCanceled = true;
            });
          }
          return new Response(JSON.stringify(validMetadata()), { status: 200 });
        },
      }),
      /\/health response too large/,
    );
    assert.equal(healthCanceled, true);

    let instanceCanceled = false;
    await assert.rejects(
      () => runLiveApiSmoke({
        apiBaseUrl: "https://api.community.example",
        expectMode: "standalone",
      }, {
        fetch: async (url) => {
          if (String(url).endsWith("/health")) {
            return new Response("ok", { status: 200 });
          }
          return oversizedStreamingResponse("instance", () => {
            instanceCanceled = true;
          }, 70 * 1024);
        },
      }),
      /\/api\/instance response too large/,
    );
    assert.equal(instanceCanceled, true);
  });
});
