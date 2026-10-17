import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { audit, requestMeta } from "./audit.js";
import { clientSecretMatches, postLogoutAllowed, redirectAllowed, resolveScopes, type OAuthClient } from "./clients.js";
import { messagePage } from "./pages.js";
import { openJson, sealJson } from "./sealed.js";
import { appendSetCookie } from "./sessions.js";
import type { AuthState } from "./state.js";
import { isCodeChallenge, parseCookies, scopes as scopeUtil, serializeCookie } from "./util.js";

export const AUTHZ_COOKIE = "gw_authz";
export const AUTHZ_TTL_MS = 600_000;

/** The pending authorization request, sealed into the `gw_authz` cookie by /oauth/authorize. */
export interface PendingAuthz extends Record<string, unknown> {
  client_id: string;
  redirect_uri: string;
  state: string;
  code_challenge: string;
  scopes: string[];
  resource: string | null;
  ui_locales: string;
  /**
   * The request came from a same-origin page or straight from the user (the
   * browser's `Sec-Fetch-Site`): only then may the login page ask for the
   * passkey without a tap. A cross-site page that sends the browser here
   * gets a page that waits for one.
   */
  autostart?: boolean;
}

/** `Sec-Fetch-Site` says this navigation was the user's own or came from this origin. */
export function ownNavigation(req: FastifyRequest): boolean {
  const site = req.headers["sec-fetch-site"];
  return site === "same-origin" || site === "none";
}

type Params = Record<string, unknown>;
const str = (q: Params, name: string): string => (typeof q[name] === "string" ? (q[name] as string) : "");

function noStore(reply: FastifyReply): FastifyReply {
  return reply.header("Cache-Control", "no-store").header("Pragma", "no-cache");
}

function oauthError(reply: FastifyReply, status: number, error: string, description?: string) {
  return noStore(reply)
    .code(status)
    .send(description ? { error, error_description: description } : { error });
}

/** 303 back to the client's registered redirect URI with `state` and `iss` (RFC 9207). */
function back(reply: FastifyReply, redirectUri: string, state: string, issuer: string, params: Record<string, string>) {
  const url = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  if (state) url.searchParams.set("state", state);
  url.searchParams.set("iss", issuer);
  return reply.code(303).redirect(url.toString());
}

export function discoveryDocument(issuer: string): Record<string, unknown> {
  return {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    end_session_endpoint: `${issuer}/oauth/end_session`,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
    revocation_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
    scopes_supported: ["mail"],
    authorization_response_iss_parameter_supported: true,
  };
}

/** Client authentication for the token and revocation endpoints: body (`client_secret_post`) or HTTP Basic. */
function authenticateClient(s: AuthState, req: FastifyRequest, body: Params): { client: OAuthClient; basic: boolean } | null {
  let id = str(body, "client_id");
  let secret = str(body, "client_secret");
  let basic = false;
  const h = req.headers.authorization;
  if (typeof h === "string" && /^Basic\s+/i.test(h)) {
    basic = true;
    try {
      const decoded = Buffer.from(h.replace(/^Basic\s+/i, "").trim(), "base64").toString("utf8");
      const i = decoded.indexOf(":");
      if (i > 0) {
        id = decodeURIComponent(decoded.slice(0, i));
        secret = decodeURIComponent(decoded.slice(i + 1));
      }
    } catch {
      return null;
    }
  }
  const client = s.clients.get(id);
  if (!client || !secret || !clientSecretMatches(client, secret)) return null;
  return { client, basic };
}

export async function oauthRoutes(app: FastifyInstance, s: AuthState): Promise<void> {
  const issuer = s.ctx.config.publicBaseUrl;
  const flowCookie = { path: "/", secure: s.secure, sameSite: "Lax" as const };

  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string", bodyLimit: 4096 }, (_req, body, done) =>
    done(null, Object.fromEntries(new URLSearchParams(String(body)))),
  );

  app.get("/.well-known/oauth-authorization-server", async (_req, reply) =>
    reply.header("Cache-Control", "public, max-age=3600").send(discoveryDocument(issuer)),
  );

  app.get("/oauth/authorize", { logLevel: "silent" }, async (req, reply) => {
    const q = req.query as Params;
    const { ip, userAgent } = requestMeta(req);
    const limited = s.limiter.take("authorize", ip, 30);
    if (!limited.ok) return reply.code(429).header("Retry-After", String(limited.retryAfter)).send({ error: "rate_limited" });

    const client = s.clients.get(str(q, "client_id"));
    const redirectUri = str(q, "redirect_uri");
    // Without a registered redirect there is nowhere safe to send an error.
    if (!client || !redirectUri || !redirectAllowed(client, redirectUri)) {
      void audit(s.ctx, { event: "oauth.authorize.rejected", ip, userAgent, details: { reason: "client_or_redirect" } }, s.now());
      return messagePage(reply, 400, "Not registered", "This application is not registered to sign in here.");
    }
    const state = str(q, "state");
    const err = (error: string, description?: string) => {
      void audit(s.ctx, { event: "oauth.authorize.rejected", clientId: client.id, ip, userAgent, details: { reason: error } }, s.now());
      return back(reply, redirectUri, state.slice(0, 512), issuer, description ? { error, error_description: description } : { error });
    };
    if (state.length > 512) return err("invalid_request", "state too long");
    if (str(q, "response_type") !== "code") return err("unsupported_response_type");
    const challenge = str(q, "code_challenge");
    if (str(q, "code_challenge_method") !== "S256" || !isCodeChallenge(challenge)) return err("invalid_request", "PKCE (S256) is required");
    const scopes = resolveScopes(client, scopeUtil.parse(str(q, "scope")));
    if (!scopes.ok) return err("invalid_scope");
    const resource = str(q, "resource");
    if (resource) {
      let ok = false;
      try {
        const u = new URL(resource);
        ok = !u.hash && (u.protocol === "https:" || u.protocol === "http:");
      } catch {
        ok = false;
      }
      if (!ok) return err("invalid_target");
    }

    const pending: PendingAuthz = {
      client_id: client.id,
      redirect_uri: redirectUri,
      state,
      code_challenge: challenge,
      scopes: scopes.scopes,
      resource: resource || null,
      ui_locales: str(q, "ui_locales").slice(0, 16),
      autostart: ownNavigation(req),
    };
    appendSetCookie(
      reply,
      serializeCookie(AUTHZ_COOKIE, sealJson(s.sealKey, AUTHZ_COOKIE, pending, s.now() + AUTHZ_TTL_MS), {
        ...flowCookie,
        maxAge: AUTHZ_TTL_MS / 1000,
      }),
    );
    void audit(s.ctx, { event: "oauth.authorize", clientId: client.id, ip, userAgent, details: { scopes: scopes.scopes } }, s.now());
    // A5: always a fresh passkey tap, never a reuse of the gateway session.
    return reply.code(303).redirect("/auth/login");
  });

  app.post("/oauth/token", { logLevel: "silent" }, async (req, reply) => {
    const body = (req.body ?? {}) as Params;
    const { ip, userAgent } = requestMeta(req);
    const limited = s.limiter.take("token", ip, 60);
    if (!limited.ok) return oauthError(reply.header("Retry-After", String(limited.retryAfter)), 429, "rate_limited");
    const auth = authenticateClient(s, req, body);
    if (!auth) {
      const failed = s.limiter.take("token-client-fail", ip, 10);
      void audit(s.ctx, { event: "oauth.invalid_client", ip, userAgent, details: { endpoint: "token" } }, s.now());
      if (!failed.ok) return oauthError(reply.header("Retry-After", String(failed.retryAfter)), 429, "rate_limited");
      if (/^Basic\s+/i.test(req.headers.authorization ?? "")) reply.header("WWW-Authenticate", 'Basic realm="oauth"');
      return oauthError(reply, 401, "invalid_client");
    }
    const { client } = auth;
    const grantType = str(body, "grant_type");
    try {
      if (grantType === "authorization_code") {
        const code = str(body, "code");
        const redirectUri = str(body, "redirect_uri");
        const codeVerifier = str(body, "code_verifier");
        if (!code || !redirectUri || !codeVerifier) return oauthError(reply, 400, "invalid_request", "code, redirect_uri and code_verifier are required");
        const t = await s.store.redeemCode({ code, clientId: client.id, redirectUri, codeVerifier });
        if (!t) {
          void audit(s.ctx, { event: "oauth.token.rejected", clientId: client.id, ip, userAgent, details: { grant_type: grantType } }, s.now());
          return oauthError(reply, 400, "invalid_grant");
        }
        void audit(s.ctx, { event: "oauth.token.issued", clientId: client.id, ip, userAgent, details: { grantId: t.grantId } }, s.now());
        return noStore(reply).send({
          access_token: t.accessToken,
          token_type: "Bearer",
          expires_in: t.expiresIn,
          refresh_token: t.refreshToken,
          scope: scopeUtil.join(t.scopes),
        });
      }
      if (grantType === "refresh_token") {
        const refreshToken = str(body, "refresh_token");
        if (!refreshToken) return oauthError(reply, 400, "invalid_request", "refresh_token is required");
        const scope = scopeUtil.parse(str(body, "scope"));
        const t = await s.store.refresh({ refreshToken, clientId: client.id, ...(scope.length ? { scope } : {}) });
        if (!t) {
          void audit(s.ctx, { event: "oauth.refresh.rejected", clientId: client.id, ip, userAgent }, s.now());
          return oauthError(reply, 400, "invalid_grant");
        }
        void audit(s.ctx, { event: "oauth.refresh", clientId: client.id, ip, userAgent, details: { grantId: t.grantId } }, s.now());
        return noStore(reply).send({
          access_token: t.accessToken,
          token_type: "Bearer",
          expires_in: t.expiresIn,
          refresh_token: t.refreshToken,
          scope: scopeUtil.join(t.scopes),
        });
      }
      if (!grantType) return oauthError(reply, 400, "invalid_request", "grant_type is required");
      return oauthError(reply, 400, "unsupported_grant_type");
    } catch (err) {
      // Bulwark retries 503 with backoff but signs the user out after repeated 500s.
      s.ctx.log.error({ err }, "token endpoint failed");
      return oauthError(reply, 503, "temporarily_unavailable");
    }
  });

  app.post("/oauth/revoke", { logLevel: "silent" }, async (req, reply) => {
    const body = (req.body ?? {}) as Params;
    const { ip, userAgent } = requestMeta(req);
    const limited = s.limiter.take("token", ip, 60);
    if (!limited.ok) return oauthError(reply.header("Retry-After", String(limited.retryAfter)), 429, "rate_limited");
    const auth = authenticateClient(s, req, body);
    if (!auth) {
      const failed = s.limiter.take("token-client-fail", ip, 10);
      void audit(s.ctx, { event: "oauth.invalid_client", ip, userAgent, details: { endpoint: "revoke" } }, s.now());
      if (!failed.ok) return oauthError(reply.header("Retry-After", String(failed.retryAfter)), 429, "rate_limited");
      return oauthError(reply, 401, "invalid_client");
    }
    const token = str(body, "token");
    if (!token) return oauthError(reply, 400, "invalid_request", "token is required");
    try {
      await s.store.revokeToken(token, auth.client.id);
    } catch (err) {
      s.ctx.log.error({ err }, "revocation failed");
      return oauthError(reply, 503, "temporarily_unavailable");
    }
    void audit(s.ctx, { event: "oauth.revoke", clientId: auth.client.id, ip, userAgent }, s.now());
    // RFC 7009: an unknown or already revoked token is not an error.
    return noStore(reply).send({});
  });

  app.get("/oauth/end_session", async (req, reply) => {
    const q = req.query as Params;
    const { ip, userAgent } = requestMeta(req);
    const token = s.sessions.fromRequest(req);
    const session = await s.sessions.get(token);
    if (session) {
      await s.sessions.delete(token);
      void audit(s.ctx, { event: "session.end_session", accountId: session.accountId, ip, userAgent }, s.now());
    }
    if (token) s.sessions.clearCookie(reply);
    // An unfinished sign-in does not outlive the sign-out (it would ask for the passkey again).
    clearPendingAuthz(s, reply);
    const client = s.clients.get(str(q, "client_id"));
    const target = str(q, "post_logout_redirect_uri");
    if (client && target && postLogoutAllowed(client, target)) {
      const url = new URL(target);
      const state = str(q, "state");
      if (state) url.searchParams.set("state", state.slice(0, 512));
      return reply.code(303).redirect(url.toString());
    }
    return messagePage(reply, 200, "Signed out", "You have been signed out.", { href: "/", label: "Sign in again" });
  });
}

/** Read and clear the pending authorization request (the login flow consumes it). */
export function readPendingAuthz(s: AuthState, req: FastifyRequest): PendingAuthz | null {
  return openJson<PendingAuthz>(s.sealKey, AUTHZ_COOKIE, parseCookies(req.headers.cookie).get(AUTHZ_COOKIE), s.now());
}

export function clearPendingAuthz(s: AuthState, reply: FastifyReply): void {
  appendSetCookie(reply, serializeCookie(AUTHZ_COOKIE, "", { path: "/", secure: s.secure, sameSite: "Lax", maxAge: 0 }));
}

