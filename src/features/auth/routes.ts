import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { getAccountById } from "../../core/accounts.js";
import { audit, requestMeta } from "./audit.js";
import { sameOrigin } from "./csrf.js";
import { consumeEnrollToken, peekEnrollToken } from "./enroll.js";
import { clearPendingAuthz, readPendingAuthz } from "./oauth.js";
import { messagePage, sendPage } from "./pages.js";
import { openJson, sealJson } from "./sealed.js";
import { appendSetCookie } from "./sessions.js";
import type { AuthState } from "./state.js";
import { b64url, escapeHtml, hashToken, parseCookies, serializeCookie } from "./util.js";
import {
  authenticationOptions,
  CeremonyError,
  CHALLENGE_TTL_MS,
  consumeChallenge,
  deletePasskey,
  listPasskeys,
  passkeyName,
  registrationOptions,
  renamePasskey,
  storeChallenge,
  verifyAuthentication,
  verifyRegistration,
  type ChallengeKind,
  type Passkey,
} from "./webauthn.js";

const CHAL_COOKIE = "gw_chal";
const ENROLL_COOKIE = "gw_enroll";
const WEBAUTHN_SCRIPT = "webauthn-14.0.0.js";

type Body = Record<string, unknown>;
const body = (req: FastifyRequest): Body => (typeof req.body === "object" && req.body !== null ? (req.body as Body) : {});

export async function authRoutes(app: FastifyInstance, s: AuthState): Promise<void> {
  const cookie = (name: string, value: string, path: string, maxAge: number) =>
    serializeCookie(name, value, { path, maxAge, secure: s.secure, sameSite: "Lax" });
  const setChallengeCookie = (reply: FastifyReply, id: string) =>
    appendSetCookie(reply, cookie(CHAL_COOKIE, sealJson(s.sealKey, CHAL_COOKIE, { id }, s.now() + CHALLENGE_TTL_MS), "/auth", CHALLENGE_TTL_MS / 1000));
  const clearCookie = (reply: FastifyReply, name: string, path: string) => appendSetCookie(reply, cookie(name, "", path, 0));
  const challengeId = (req: FastifyRequest): string | undefined =>
    openJson<{ id: string }>(s.sealKey, CHAL_COOKIE, parseCookies(req.headers.cookie).get(CHAL_COOKIE), s.now())?.id;
  const enrollToken = (req: FastifyRequest): string | undefined =>
    openJson<{ token: string }>(s.sealKey, ENROLL_COOKIE, parseCookies(req.headers.cookie).get(ENROLL_COOKIE), s.now())?.token;

  /** Rate limit for the unauthenticated ceremonies: per address and global. */
  function limited(req: FastifyRequest, reply: FastifyReply, bucket: string, max: number): boolean {
    const r = s.limiter.take(bucket, req.ip, max);
    const g = r.ok ? s.limiter.take(`${bucket}:global`, "*", 100) : r;
    if (r.ok && g.ok) return false;
    const retry = (r.ok ? g : r) as { retryAfter: number };
    void audit(s.ctx, { event: "ratelimit", ip: req.ip, details: { bucket } }, s.now());
    void reply.code(429).header("Retry-After", String(retry.retryAfter)).send({ error: "rate_limited" });
    return true;
  }

  async function consumeFor(req: FastifyRequest, kind: ChallengeKind, accountId: string | null): Promise<string> {
    const c = await consumeChallenge(s, challengeId(req), kind);
    if (!c || c.accountId !== accountId) throw new CeremonyError("challenge: missing, expired, reused or for another account");
    return c.challenge;
  }

  function fail(req: FastifyRequest, reply: FastifyReply, event: string, err: unknown, accountId: string | null = null) {
    const { ip, userAgent } = requestMeta(req);
    if (err instanceof CeremonyError) {
      void audit(s.ctx, { event, accountId, ip, userAgent, details: { reason: err.reason } }, s.now());
      if (/counter regression/.test(err.reason)) {
        void audit(s.ctx, { event: "passkey.counter_regression", accountId, ip, userAgent }, s.now());
      }
      return reply.code(err.status).send({ error: err.status === 409 ? "already_registered" : "verification_failed" });
    }
    s.ctx.log.error({ err }, `${event}: unexpected failure`);
    return reply.code(503).send({ error: "temporarily_unavailable" });
  }

  async function startSession(req: FastifyRequest, reply: FastifyReply, accountId: string, passkeyId: Buffer | null): Promise<void> {
    const old = s.sessions.fromRequest(req);
    if (old) await s.sessions.delete(old);
    const { ip, userAgent } = requestMeta(req);
    s.sessions.setCookie(reply, await s.sessions.create({ accountId, passkeyId, ip, userAgent }));
  }

  // --- login (discoverable passkey) ----------------------------------------

  app.get("/auth/login", async (req, reply) => {
    const pending = readPendingAuthz(s, req);
    if (!pending && (await s.sessions.ofRequest(req))) return reply.code(303).redirect("/auth/passkeys");
    return sendPage(reply, {
      title: "Sign in",
      lang: pending?.ui_locales.split(/[\s,]/)[0],
      scripts: [WEBAUTHN_SCRIPT, "auth.js"],
      body:
        `<h1>Sign in</h1><p>Use your passkey to continue${pending ? " to the webmail" : ""}.</p>` +
        `<form id="flow" data-flow="login"><button type="submit" id="go">Sign in with passkey</button></form>` +
        `<p id="msg" class="msg" role="status" aria-live="polite"></p>`,
    });
  });

  app.post("/auth/login/options", async (req, reply) => {
    if (limited(req, reply, "login", 10)) return;
    const options = await authenticationOptions(s);
    setChallengeCookie(reply, await storeChallenge(s, "login", options.challenge, null));
    return options;
  });

  app.post("/auth/login/verify", async (req, reply) => {
    if (!sameOrigin(req, reply, s.origin, { json: true })) return;
    if (limited(req, reply, "login", 10)) return;
    const { ip, userAgent } = requestMeta(req);
    let passkey: Passkey;
    try {
      const challenge = await consumeFor(req, "login", null);
      passkey = await verifyAuthentication(s, { response: body(req) as unknown as AuthenticationResponseJSON, challenge });
    } catch (err) {
      return fail(req, reply, "login.fail", err);
    }
    clearCookie(reply, CHAL_COOKIE, "/auth");
    const account = await getAccountById(s.ctx, passkey.accountId);
    if (!account || !s.ctx.config.allowedEmails.includes(account.email)) {
      void audit(s.ctx, { event: "login.not_allowed", accountId: passkey.accountId, ip, userAgent }, s.now());
      return reply.code(403).send({ error: "account_not_allowed" });
    }
    s.limiter.refund("login", req.ip);
    await startSession(req, reply, account.id, passkey.id);
    const pending = readPendingAuthz(s, req);
    let next = "/auth/passkeys";
    if (pending) {
      const code = await s.store.issueCode({
        clientId: pending.client_id,
        accountId: account.id,
        redirectUri: pending.redirect_uri,
        codeChallenge: pending.code_challenge,
        scopes: pending.scopes,
        resource: pending.resource,
      });
      clearPendingAuthz(s, reply);
      const url = new URL(pending.redirect_uri);
      url.searchParams.set("code", code);
      if (pending.state) url.searchParams.set("state", pending.state);
      url.searchParams.set("iss", s.ctx.config.publicBaseUrl);
      next = url.toString();
      void audit(s.ctx, { event: "oauth.code_issued", accountId: account.id, clientId: pending.client_id, ip, userAgent }, s.now());
    }
    void audit(s.ctx, { event: "login.ok", accountId: account.id, ip, userAgent, details: { passkey: passkey.name } }, s.now());
    return { next };
  });

  // --- enrollment (bootstrap link) -----------------------------------------

  app.get("/auth/enroll/:token", { logLevel: "silent" }, async (req, reply) => {
    if (limited(req, reply, "enroll", 10)) return;
    const token = (req.params as { token: string }).token;
    const peek = await peekEnrollToken(s.ctx, token, s.now());
    if (!peek || !s.ctx.config.allowedEmails.includes(peek.email)) {
      return messagePage(reply, 404, "Link expired", "This enrollment link is invalid, expired or already used. Ask for a new one.");
    }
    // The token leaves the URL bar and history here; the sealed cookie carries it on.
    const ttl = Math.max(1, Math.floor((peek.expiresAt.getTime() - s.now()) / 1000));
    appendSetCookie(reply, cookie(ENROLL_COOKIE, sealJson(s.sealKey, ENROLL_COOKIE, { token }, peek.expiresAt.getTime()), "/auth/enroll", ttl));
    return reply.code(303).redirect("/auth/enroll");
  });

  app.get("/auth/enroll", async (req, reply) => {
    const peek = await peekEnrollToken(s.ctx, enrollToken(req), s.now());
    if (!peek) return messagePage(reply, 404, "Link expired", "This enrollment link is invalid, expired or already used. Ask for a new one.");
    return sendPage(reply, {
      title: "Create a passkey",
      scripts: [WEBAUTHN_SCRIPT, "auth.js"],
      body:
        `<h1>Create a passkey</h1><p>This passkey will sign <strong>${escapeHtml(peek.email)}</strong> in to the webmail.</p>` +
        `<form id="flow" data-flow="enroll"><label for="name">Name</label>` +
        `<input id="name" name="name" maxlength="64" placeholder="e.g. Phone, Laptop" autocomplete="off">` +
        `<button type="submit" id="go">Create passkey</button></form>` +
        `<p id="msg" class="msg" role="status" aria-live="polite"></p>`,
    });
  });

  app.post("/auth/enroll/options", async (req, reply) => {
    if (limited(req, reply, "enroll", 10)) return;
    const peek = await peekEnrollToken(s.ctx, enrollToken(req), s.now());
    if (!peek) return reply.code(410).send({ error: "link_expired" });
    const options = await registrationOptions(s, { id: peek.accountId, email: peek.email });
    setChallengeCookie(reply, await storeChallenge(s, "enroll", options.challenge, peek.accountId));
    return options;
  });

  app.post("/auth/enroll/verify", async (req, reply) => {
    if (!sameOrigin(req, reply, s.origin, { json: true })) return;
    if (limited(req, reply, "enroll", 10)) return;
    const token = enrollToken(req);
    const peek = await peekEnrollToken(s.ctx, token, s.now());
    if (!peek || !token) return reply.code(410).send({ error: "link_expired" });
    const { ip, userAgent } = requestMeta(req);
    const b = body(req);
    let passkey: Passkey;
    try {
      const challenge = await consumeFor(req, "enroll", peek.accountId);
      passkey = await verifyRegistration(s, {
        response: b.response as RegistrationResponseJSON,
        challenge,
        accountId: peek.accountId,
        name: passkeyName(b.name, `Passkey ${new Date(s.now()).toISOString().slice(0, 10)}`),
      });
    } catch (err) {
      return fail(req, reply, "enroll.fail", err, peek.accountId);
    }
    const consumed = await consumeEnrollToken(s.ctx.db, hashToken(token), s.now());
    if (consumed !== peek.accountId) {
      await s.ctx.db.query("DELETE FROM passkey WHERE id = $1", [passkey.id]);
      return reply.code(410).send({ error: "link_expired" });
    }
    clearCookie(reply, CHAL_COOKIE, "/auth");
    clearCookie(reply, ENROLL_COOKIE, "/auth/enroll");
    await startSession(req, reply, peek.accountId, passkey.id);
    void audit(s.ctx, { event: "enroll.ok", accountId: peek.accountId, ip, userAgent, details: { passkey: passkey.name } }, s.now());
    return { next: "/auth/passkeys" };
  });

  // --- passkey management (session) ----------------------------------------

  app.get("/auth/passkeys", async (req, reply) => {
    const session = await s.sessions.ofRequest(req);
    if (!session) return reply.code(303).redirect("/auth/login");
    const keys = await listPasskeys(s, session.accountId);
    const fmt = (d: Date | null) => (d ? escapeHtml(d.toISOString().slice(0, 16).replace("T", " ") + " UTC") : "never");
    const rows = keys
      .map(
        (k) =>
          `<li class="passkey" data-id="${b64url.encode(k.id)}"><div><strong class="name">${escapeHtml(k.name)}</strong>` +
          `${k.backedUp ? ' <span class="tag">synced</span>' : ""}<br><small>created ${fmt(k.createdAt)}, last used ${fmt(k.lastUsedAt)}</small></div>` +
          `<div class="actions"><button type="button" data-action="rename">Rename</button>` +
          `<button type="button" data-action="delete"${keys.length <= 1 ? " disabled title=\"The last passkey cannot be deleted\"" : ""}>Delete</button></div></li>`,
      )
      .join("");
    return sendPage(reply, {
      title: "Passkeys",
      scripts: [WEBAUTHN_SCRIPT, "auth.js"],
      body:
        `<h1>Passkeys</h1><p>Signed in as <strong>${escapeHtml(session.email)}</strong>.</p>` +
        `<ul class="passkeys" id="passkeys">${rows}</ul>` +
        `<form id="flow" data-flow="add"><label for="name">New passkey</label>` +
        `<input id="name" name="name" maxlength="64" placeholder="Name, e.g. Phone" autocomplete="off">` +
        `<button type="submit" id="go">Add passkey</button></form>` +
        `<p id="msg" class="msg" role="status" aria-live="polite"></p>` +
        `<p><button type="button" id="logout" class="link">Sign out</button></p>`,
    });
  });

  app.post("/auth/passkeys/options", async (req, reply) => {
    if (!sameOrigin(req, reply, s.origin, { json: false })) return;
    const session = await s.sessions.ofRequest(req);
    if (!session) return reply.code(401).send({ error: "no_session" });
    if (limited(req, reply, "manage", 30)) return;
    const options = await registrationOptions(s, { id: session.accountId, email: session.email });
    setChallengeCookie(reply, await storeChallenge(s, "add", options.challenge, session.accountId));
    return options;
  });

  app.post("/auth/passkeys/verify", async (req, reply) => {
    if (!sameOrigin(req, reply, s.origin, { json: true })) return;
    const session = await s.sessions.ofRequest(req);
    if (!session) return reply.code(401).send({ error: "no_session" });
    if (limited(req, reply, "manage", 30)) return;
    const { ip, userAgent } = requestMeta(req);
    const b = body(req);
    try {
      const challenge = await consumeFor(req, "add", session.accountId);
      const passkey = await verifyRegistration(s, {
        response: b.response as RegistrationResponseJSON,
        challenge,
        accountId: session.accountId,
        name: passkeyName(b.name, `Passkey ${new Date(s.now()).toISOString().slice(0, 10)}`),
      });
      clearCookie(reply, CHAL_COOKIE, "/auth");
      void audit(s.ctx, { event: "passkey.add", accountId: session.accountId, ip, userAgent, details: { passkey: passkey.name } }, s.now());
      return { ok: true, id: b64url.encode(passkey.id), name: passkey.name };
    } catch (err) {
      return fail(req, reply, "passkey.add_fail", err, session.accountId);
    }
  });

  const credentialId = (req: FastifyRequest): Buffer | null => {
    const id = (req.params as { id: string }).id;
    return b64url.is(id) && id.length <= 1400 ? b64url.decode(id) : null;
  };

  app.patch("/auth/passkeys/:id", async (req, reply) => {
    if (!sameOrigin(req, reply, s.origin, { json: true })) return;
    const session = await s.sessions.ofRequest(req);
    if (!session) return reply.code(401).send({ error: "no_session" });
    if (limited(req, reply, "manage", 30)) return;
    const id = credentialId(req);
    const name = passkeyName(body(req).name, "");
    if (!id || !name) return reply.code(400).send({ error: "invalid_request" });
    if (!(await renamePasskey(s, session.accountId, id, name))) return reply.code(404).send({ error: "not_found" });
    void audit(s.ctx, { event: "passkey.rename", accountId: session.accountId, ...requestMeta(req), details: { name } }, s.now());
    return { ok: true };
  });

  app.delete("/auth/passkeys/:id", async (req, reply) => {
    if (!sameOrigin(req, reply, s.origin, { json: false })) return;
    const session = await s.sessions.ofRequest(req);
    if (!session) return reply.code(401).send({ error: "no_session" });
    if (limited(req, reply, "manage", 30)) return;
    const id = credentialId(req);
    if (!id) return reply.code(400).send({ error: "invalid_request" });
    const outcome = await deletePasskey(s, session.accountId, id);
    if (outcome === "not_found") return reply.code(404).send({ error: "not_found" });
    if (outcome === "last_passkey") return reply.code(409).send({ error: "last_passkey" });
    void audit(s.ctx, { event: "passkey.delete", accountId: session.accountId, ...requestMeta(req) }, s.now());
    return { ok: true };
  });

  app.post("/auth/logout", async (req, reply) => {
    if (!sameOrigin(req, reply, s.origin, { json: false })) return;
    const token = s.sessions.fromRequest(req);
    const session = await s.sessions.get(token);
    if (session) {
      await s.sessions.delete(token);
      void audit(s.ctx, { event: "session.logout", accountId: session.accountId, ...requestMeta(req) }, s.now());
    }
    s.sessions.clearCookie(reply);
    return { next: "/auth/login" };
  });
}
