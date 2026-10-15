import type { FastifyReply, FastifyRequest } from "fastify";

/**
 * CSRF gate for the cookie-authenticated, state-changing `/auth/*` routes
 * (Bulwark's `rejectCrossOriginRequest` logic): `Sec-Fetch-Site` is
 * authoritative when present (browsers since 2020; JS cannot set it), else the
 * `Origin` header must be our own origin; neither header means a non-browser
 * client that cannot ride a victim's cookie. The JSON content type is required
 * as well: a cross-site form cannot send it.
 */
export function sameOriginJson(req: FastifyRequest, reply: FastifyReply, origin: string): boolean {
  const ct = req.headers["content-type"] ?? "";
  if (!/^application\/json\b/i.test(ct)) {
    void reply.code(415).send({ error: "json_required" });
    return false;
  }
  const site = req.headers["sec-fetch-site"];
  let ok: boolean;
  if (typeof site === "string") ok = site === "same-origin" || site === "none";
  else {
    const o = req.headers.origin;
    ok = typeof o !== "string" || o === origin;
  }
  if (!ok) void reply.code(403).send({ error: "cross_origin" });
  return ok;
}
