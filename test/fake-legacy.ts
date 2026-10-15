import Fastify, { type FastifyInstance } from "fastify";
import { verifyToken } from "../src/core/token.js";

export interface FakeLegacy {
  app: FastifyInstance;
  url: string;
  /** Slugs legacy-proxy "knows" (created by a successful Basic login). Clear it to simulate lost state. */
  accounts: Set<string>;
  /** Passwords accepted by the Basic login, by username. */
  passwords: Map<string, string>;
  /** Every request seen: method, path and auth scheme. */
  calls: { method: string; path: string; scheme: string }[];
  close(): Promise<void>;
}

/**
 * A small stand-in for legacy-proxy: Bearer tokens verified with `hmacKey` and
 * looked up by slug (401 for unknown slugs), Basic logins checked against
 * `passwords` that then register slug `gandi:<user>`. Listens on an ephemeral port.
 */
export async function startFakeLegacy(hmacKey: Buffer): Promise<FakeLegacy> {
  const app = Fastify();
  const accounts = new Set<string>();
  const passwords = new Map<string, string>();
  const calls: FakeLegacy["calls"] = [];

  function authn(header: string | undefined): { slug: string } | null {
    if (!header) return null;
    if (header.startsWith("Bearer ")) {
      const claims = verifyToken(hmacKey, header.slice(7).trim());
      return claims && accounts.has(claims.accountSlug) ? { slug: claims.accountSlug } : null;
    }
    if (header.startsWith("Basic ")) {
      const decoded = Buffer.from(header.slice(6).trim(), "base64").toString("utf8");
      const i = decoded.indexOf(":");
      if (i < 1) return null;
      const user = decoded.slice(0, i);
      if (passwords.get(user) !== decoded.slice(i + 1)) return null;
      const slug = `gandi:${user}`;
      accounts.add(slug);
      return { slug };
    }
    return null;
  }

  app.addHook("onRequest", async (req) => {
    calls.push({ method: req.method, path: req.url, scheme: req.headers.authorization?.split(" ")[0] ?? "none" });
  });
  app.get("/jmap/session", async (req, reply) => {
    const a = authn(req.headers.authorization);
    if (!a) return reply.code(401).send({ error: "unauthorized" });
    return { username: a.slug, apiUrl: "/jmap" };
  });
  app.post("/jmap", async (req, reply) => {
    const a = authn(req.headers.authorization);
    if (!a) return reply.code(401).send({ error: "unauthorized" });
    const body = req.body as { using: string[]; methodCalls: [string, Record<string, unknown>, string][] };
    return {
      sessionState: "s1",
      methodResponses: body.methodCalls.map(([name, args, id]) => [name, { echo: args, slug: a.slug, using: body.using }, id]),
    };
  });
  app.get("/boom", async (_req, reply) => reply.code(500).send({ error: "boom" }));
  app.get("/not-json", async (_req, reply) => reply.type("text/plain").send("hello"));
  app.post("/echo", async (req) => ({ body: req.body }));

  await app.listen({ port: 0, host: "127.0.0.1" });
  const addr = app.server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  return { app, url: `http://127.0.0.1:${port}`, accounts, passwords, calls, close: () => app.close() };
}
