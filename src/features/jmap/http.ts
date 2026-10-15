// Small HTTP helpers shared by the jmap routes: problem responses and the
// header allowlists of design/jmap.md section 5.
import type { IncomingHttpHeaders } from "node:http";
import type { FastifyReply, FastifyRequest } from "fastify";

export const JMAP_ERR = "urn:ietf:params:jmap:error:";

/** RFC 7807 problem details, the shape RFC 8620 section 3.6.1 uses for request-level errors. */
export function sendProblem(
  reply: FastifyReply,
  status: number,
  type = "about:blank",
  extra: Record<string, unknown> = {},
): FastifyReply {
  if (status === 401) reply.header("www-authenticate", 'Bearer realm="webmail"'); // D11: never Basic
  return reply
    .code(status)
    .header("content-type", "application/problem+json")
    .header("cache-control", "no-store")
    .send(JSON.stringify({ type, status, ...extra }));
}

/** Client request headers that may reach legacy-proxy (plus the minted authorization). */
const REQUEST_KEEP = ["content-type", "content-length", "accept", "last-event-id"] as const;

export function forwardHeaders(req: FastifyRequest, opts: { acceptEncoding: boolean }): Record<string, string> {
  const out: Record<string, string> = { "x-request-id": String(req.id) };
  for (const name of REQUEST_KEEP) {
    const v = req.headers[name];
    if (typeof v === "string") out[name] = v;
  }
  const ae = req.headers["accept-encoding"];
  out["accept-encoding"] = opts.acceptEncoding && typeof ae === "string" ? ae : "identity";
  return out;
}

/** legacy-proxy response headers the client may see. CORS, auth challenges, cookies and server banners are dropped. */
const RESPONSE_KEEP = [
  "content-type",
  "content-length",
  "content-encoding",
  "content-disposition",
  "cache-control",
  "vary",
  "retry-after",
  "etag",
  "last-modified",
] as const;

export function copyResponseHeaders(from: IncomingHttpHeaders, reply: FastifyReply): void {
  for (const name of RESPONSE_KEEP) {
    const v = from[name];
    if (typeof v === "string") reply.header(name, v);
  }
}

export function retryAfter(reply: FastifyReply, seconds: number): FastifyReply {
  return reply.header("retry-after", String(Math.max(1, Math.ceil(seconds))));
}
