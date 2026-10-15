import type { FastifyRequest } from "fastify";
import { beforeEach, describe, expect, it } from "vitest";
import { authenticate, registerAuthenticator, resetAuthenticators, type Principal } from "../src/core/auth-context.js";

const req = (auth?: string) => ({ headers: { authorization: auth } }) as unknown as FastifyRequest;
const p = (via: Principal["via"]): Principal => ({ accountId: "a", email: "a@x.fi", scopes: ["mail"], via });

beforeEach(() => resetAuthenticators());

describe("auth context", () => {
  it("returns null with no authenticators", async () => {
    expect(await authenticate(req("Bearer x"))).toBeNull();
  });

  it("first non-null authenticator wins, in registration order", async () => {
    registerAuthenticator(async (r) => (r.headers.authorization?.startsWith("Basic") ? p("basic") : null));
    registerAuthenticator(async (r) => (r.headers.authorization?.startsWith("Bearer") ? p("oauth") : null));
    expect((await authenticate(req("Basic abc")))?.via).toBe("basic");
    expect((await authenticate(req("Bearer abc")))?.via).toBe("oauth");
    expect(await authenticate(req("Digest abc"))).toBeNull();
  });

  it("unregisters", async () => {
    const off = registerAuthenticator(async () => p("basic"));
    expect(await authenticate(req())).not.toBeNull();
    off();
    expect(await authenticate(req())).toBeNull();
  });
});
