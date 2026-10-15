import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";

const b64 = () => randomBytes(32).toString("base64");
const base = () => ({
  DATABASE_URL: "postgres://u:p@db/gw",
  GATEWAY_ENC_KEY: b64(),
  LEGACY_SESSION_HMAC_KEY: b64(),
  LEGACY_PROXY_URL: "http://legacy-proxy:8080/",
});

describe("loadConfig", () => {
  it("parses with defaults and composes feature sections", () => {
    const c = loadConfig(base());
    expect(c).toMatchObject({ port: 8080, host: "0.0.0.0", logLevel: "info", migrateOnStart: true });
    expect(c.legacyProxyUrl).toBe("http://legacy-proxy:8080");
    expect(c.encKey).toHaveLength(32);
    expect(c.legacyHmacKey).toHaveLength(32);
    expect(c.jmap).toEqual({});
    expect(c.auth).toEqual({});
    expect(c.push).toEqual({});
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

  it("requires the core keys", () => {
    expect(() => loadConfig({})).toThrow(/DATABASE_URL/);
  });
});
