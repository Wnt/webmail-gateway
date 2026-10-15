import { afterAll, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { resetAuthenticators } from "../src/core/auth-context.js";
import { makeTestContext } from "./helpers.js";

const ctx = await makeTestContext({ OAUTH_CLIENT_SECRET_BULWARK: "s".repeat(40) });
const app = await buildApp(ctx.config, { db: ctx.db, log: ctx.log });
await app.ready();
afterAll(async () => {
  await app.close();
  resetAuthenticators();
  await ctx.db.close();
});

describe("auth static assets and pages", () => {
  it("serves the stylesheet, the page script and the SimpleWebAuthn bundle, immutable", async () => {
    for (const [name, type, needle] of [
      ["auth.css", "text/css", ".passkey"],
      ["auth.js", "text/javascript", "startAuthentication"],
      ["webauthn-14.0.0.js", "text/javascript", "SimpleWebAuthnBrowser"],
    ]) {
      const res = await app.inject({ method: "GET", url: `/auth/static/${name}` });
      expect(res.statusCode, name).toBe(200);
      expect(res.headers["content-type"]).toContain(type);
      expect(res.headers["cache-control"]).toBe("public, max-age=86400, immutable");
      expect(res.body).toContain(needle);
    }
    expect((await app.inject({ method: "GET", url: "/auth/static/nope.js" })).statusCode).toBe(404);
  });

  it("the login page references exactly those assets and carries the security headers", async () => {
    const res = await app.inject({ method: "GET", url: "/auth/login" });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('<link rel="stylesheet" href="/auth/static/auth.css">');
    expect(res.body).toContain('<script defer src="/auth/static/webauthn-14.0.0.js"></script><script defer src="/auth/static/auth.js"></script>');
    expect(res.body).not.toMatch(/<script>|onclick=/);
    expect(res.headers["content-security-policy"]).toBe(
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    );
    expect(res.headers["permissions-policy"]).toContain("publickey-credentials-get=(self)");
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.headers["referrer-policy"]).toBe("no-referrer");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
  });
});
