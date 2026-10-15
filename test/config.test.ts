import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";

const b64 = () => randomBytes(32).toString("base64");
const base = () => ({
  DATABASE_URL: "postgres://u:p@db/gw",
  GATEWAY_ENC_KEY: b64(),
  LEGACY_SESSION_HMAC_KEY: b64(),
  LEGACY_PROXY_URL: "http://legacy-proxy:8080/",
  PUBLIC_BASE_URL: "https://mail.example.test/",
});

describe("loadConfig", () => {
  it("parses with defaults and composes feature sections", () => {
    const c = loadConfig(base());
    expect(c).toMatchObject({ port: 8080, host: "0.0.0.0", logLevel: "info", migrateOnStart: true });
    expect(c.legacyProxyUrl).toBe("http://legacy-proxy:8080");
    expect(c.encKey).toHaveLength(32);
    expect(c.legacyHmacKey).toHaveLength(32);
    expect(c.publicBaseUrl).toBe("https://mail.example.test");
    expect(c.legacyProvider).toBe("gandi");
    expect(c.jmap).toMatchObject({ passwordMode: false, maxSizeUpload: 50_000_000 });
    expect(c.auth).toEqual({ rpName: "Webmail", bulwarkClientSecret: null, sessionTtlMs: 12 * 3600_000 });
    expect(c.push).toMatchObject({ vapid: null, upstreamAlways: false });
  });

  it("honours overrides", () => {
    expect(loadConfig({ ...base(), PORT: "9000", MIGRATE_ON_START: "false", LOG_LEVEL: "debug" })).toMatchObject({
      port: 9000,
      migrateOnStart: false,
      logLevel: "debug",
    });
  });

  it("reports bad keys without echoing their values", () => {
    const secret = "short-secret-value";
    let msg = "";
    try {
      loadConfig({ ...base(), GATEWAY_ENC_KEY: secret, LEGACY_PROXY_URL: "nope" });
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toContain("GATEWAY_ENC_KEY");
    expect(msg).toContain("LEGACY_PROXY_URL");
    expect(msg).not.toContain(secret);
  });

  it("parses ALLOWED_EMAILS lower-cased, trimmed and de-duplicated; empty means nobody", () => {
    expect(loadConfig({ ...base(), ALLOWED_EMAILS: " A@X.fi, b@y.fi,a@x.fi,, " }).allowedEmails).toEqual(["a@x.fi", "b@y.fi"]);
    expect(loadConfig(base()).allowedEmails).toEqual([]);
  });

  it("requires the core keys", () => {
    expect(() => loadConfig({})).toThrow(/DATABASE_URL/);
  });
});
