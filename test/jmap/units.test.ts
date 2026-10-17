import { describe, expect, it } from "vitest";
import { parseJmapConfig } from "../../src/features/jmap/config.js";
import { FixedWindowLimiter, Semaphore } from "../../src/features/jmap/limiter.js";
import { rewriteSession, templateDrift, TEMPLATES } from "../../src/features/jmap/session.js";

describe("session rewrite", () => {
  const legacy = {
    capabilities: {
      "urn:ietf:params:jmap:core": { maxSizeUpload: 50_000_000, maxSizeRequest: 10_000_000, maxCallsInRequest: 64, maxObjectsInGet: 500 },
      "urn:ietf:params:jmap:mail": {},
      "urn:ietf:params:jmap:websocket": {},
    },
    accounts: { "7": { name: "User@Example.test", isPersonal: true } },
    primaryAccounts: { "urn:ietf:params:jmap:mail": "7" },
    username: "User@Example.test",
    apiUrl: "https://legacy.internal/jmap",
    downloadUrl: "https://legacy.internal/jmap/download/{accountId}/{blobId}/{type}/{name}",
    uploadUrl: "https://legacy.internal/jmap/upload/{accountId}",
    eventSourceUrl: "https://legacy.internal/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}",
    state: "s7",
  };
  const opts = { publicBaseUrl: "https://mail.example.test", email: "user@example.test", maxSizeUpload: 20_000_000, maxSizeRequest: 10_000_000, maxCallsInRequest: 64 };

  it("points every URL at the public origin and sets username", () => {
    const s = rewriteSession(legacy, opts);
    expect(s).toMatchObject({
      apiUrl: "https://mail.example.test/jmap",
      downloadUrl: "https://mail.example.test/jmap/download/{accountId}/{blobId}/{type}/{name}",
      uploadUrl: "https://mail.example.test/jmap/upload/{accountId}",
      eventSourceUrl: "https://mail.example.test/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}",
      username: "user@example.test",
      state: "s7",
      primaryAccounts: { "urn:ietf:params:jmap:mail": "7" },
    });
    expect((s["accounts"] as Record<string, { name: string }>)["7"]!.name).toBe("user@example.test");
  });

  it("clamps core limits, drops websocket, keeps other capabilities", () => {
    const caps = rewriteSession(legacy, opts)["capabilities"] as Record<string, Record<string, unknown>>;
    expect(caps["urn:ietf:params:jmap:core"]).toMatchObject({ maxSizeUpload: 20_000_000, maxSizeRequest: 10_000_000, maxCallsInRequest: 64, maxObjectsInGet: 500 });
    expect(caps).not.toHaveProperty("urn:ietf:params:jmap:websocket");
    expect(caps).toHaveProperty("urn:ietf:params:jmap:mail");
    expect(legacy.capabilities).toHaveProperty("urn:ietf:params:jmap:websocket"); // input untouched
  });

  it("detects template drift in legacy-proxy's URLs", () => {
    expect(templateDrift(legacy)).toEqual([]);
    expect(templateDrift({ ...legacy, downloadUrl: "https://x/jmap/blob/{accountId}/{blobId}" })).toEqual(["downloadUrl"]);
    expect(Object.keys(TEMPLATES)).toHaveLength(4);
  });
});

describe("FixedWindowLimiter", () => {
  it("reserves atomically across buckets and reports the wait", () => {
    let t = 0;
    const l = new FixedWindowLimiter(60_000, () => t);
    const a = { key: "a", limit: 2 };
    const g = { key: "g", limit: 3 };
    expect(l.tryReserve([a, g])).toBe(0);
    expect(l.tryReserve([a, g])).toBe(0);
    expect(l.tryReserve([a, g])).toBe(60); // a is full: nothing counted
    expect(l.tryReserve([{ key: "b", limit: 5 }, g])).toBe(0);
    expect(l.tryReserve([{ key: "c", limit: 5 }, g])).toBe(60); // g is full now
    l.refund(["g"]);
    expect(l.tryReserve([{ key: "c", limit: 5 }, g])).toBe(0);
    t = 30_000;
    expect(l.blockedFor([a])).toBe(30);
    t = 60_000;
    expect(l.blockedFor([a, g])).toBe(0);
  });
});

describe("Semaphore", () => {
  it("bounds concurrency and times out waiters", async () => {
    const s = new Semaphore(1);
    const r1 = await s.acquire(10);
    expect(r1).not.toBeNull();
    expect(await s.acquire(5)).toBeNull();
    const p = s.acquire(1000);
    r1!();
    r1!(); // double release is harmless
    const r2 = await p;
    expect(r2).not.toBeNull();
    r2!();
  });
});

describe("jmap config", () => {
  it("has the design defaults", () => {
    const c = parseJmapConfig({ JMAP_PASSWORD_MODE: "true" });
    expect(c.passwordMode).toBe(true);
    expect(c.rateLimit).toEqual({ windowSec: 900, ip: 20, account: 5, global: 30, verifyConcurrency: 4 });
    expect(c.sse).toEqual({ maxAgeSec: 3600, maxPerAccount: 10, maxTotal: 500, recheckSec: 3 });
    expect(c.basicCacheTtlSec).toBe(300);
  });
});
