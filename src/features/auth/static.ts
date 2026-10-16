import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { FastifyInstance } from "fastify";

/** `static/auth/` at the package root; the same relative path works from src and dist. */
const STATIC_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../static/auth");

/** The SimpleWebAuthn browser bundle, next to the package's CJS entry (its `exports` map hides subpaths). */
function browserBundlePath(): string {
  const entry = createRequire(import.meta.url).resolve("@simplewebauthn/browser");
  return path.resolve(path.dirname(entry), "../dist/bundle/index.umd.min.js");
}

export const WEBAUTHN_SCRIPT = "webauthn-14.0.0.js";

/**
 * The page script, named after its content: assets are cached immutable for a
 * day, so a changed script needs a new URL or browsers keep running the old
 * one against new pages.
 */
const AUTH_JS = readFileSync(path.join(STATIC_DIR, "auth.js"));
export const AUTH_SCRIPT = `auth-${createHash("sha256").update(AUTH_JS).digest("hex").slice(0, 12)}.js`;

interface Asset {
  body: Buffer;
  type: string;
}

/** The assets the pages need, read once at startup and served immutable. */
export async function staticRoutes(app: FastifyInstance): Promise<void> {
  const assets = new Map<string, Asset>([
    ["auth.css", { body: await readFile(path.join(STATIC_DIR, "auth.css")), type: "text/css; charset=utf-8" }],
    [AUTH_SCRIPT, { body: AUTH_JS, type: "text/javascript; charset=utf-8" }],
    ["logo.svg", { body: await readFile(path.join(STATIC_DIR, "logo.svg")), type: "image/svg+xml" }],
    [WEBAUTHN_SCRIPT, { body: await readFile(browserBundlePath()), type: "text/javascript; charset=utf-8" }],
  ]);
  app.get("/auth/static/:name", async (req, reply) => {
    const asset = assets.get((req.params as { name: string }).name);
    if (!asset) return reply.code(404).send({ error: "not_found" });
    return reply.header("Cache-Control", "public, max-age=86400, immutable").type(asset.type).send(asset.body);
  });
}
