import type { FastifyInstance, FastifyReply } from "fastify";
import { escapeHtml } from "./util.js";

/**
 * The gateway's few HTML pages: strings plus `escapeHtml`, no template engine,
 * no inline scripts (the CSP forbids them). Assets live under /auth/static.
 */
export const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
  "form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/** Response headers for every /auth/* and /oauth/* answer. */
export function securityHeaders(app: FastifyInstance): void {
  app.addHook("onRequest", async (_req, reply) => {
    reply.header("Cache-Control", "no-store");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("X-Content-Type-Options", "nosniff");
  });
}

export interface PageOptions {
  title: string;
  /** Already-escaped HTML. */
  body: string;
  status?: number;
  lang?: string;
  /** Script files under /auth/static to load (module scripts). */
  scripts?: string[];
}

export function sendPage(reply: FastifyReply, o: PageOptions): FastifyReply {
  const lang = o.lang && /^[a-z]{2}(-[A-Za-z]{2,4})?$/.test(o.lang) ? o.lang : "en";
  const scripts = (o.scripts ?? []).map((s) => `<script type="module" src="/auth/static/${escapeHtml(s)}"></script>`).join("");
  const html =
    `<!doctype html><html lang="${lang}"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width, initial-scale=1">` +
    `<title>${escapeHtml(o.title)}</title><link rel="stylesheet" href="/auth/static/auth.css">` +
    `</head><body><main class="card">${o.body}</main>${scripts}</body></html>`;
  return reply
    .code(o.status ?? 200)
    .header("Content-Security-Policy", CSP)
    .header("Permissions-Policy", "publickey-credentials-get=(self), publickey-credentials-create=(self)")
    .type("text/html; charset=utf-8")
    .send(html);
}

/** A plain message page (errors, "signed out"). */
export function messagePage(reply: FastifyReply, status: number, title: string, text: string, link?: { href: string; label: string }) {
  const a = link ? `<p><a href="${escapeHtml(link.href)}">${escapeHtml(link.label)}</a></p>` : "";
  return sendPage(reply, { status, title, body: `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(text)}</p>${a}` });
}
