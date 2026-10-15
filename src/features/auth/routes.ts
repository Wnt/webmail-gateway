import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { getAccountById } from "../../core/accounts.js";
import type { Queryable } from "../../db/pool.js";
import { audit, requestMeta } from "./audit.js";
import { sameOrigin } from "./csrf.js";
import { consumeEnrollToken, peekEnrollToken } from "./enroll.js";
import { holdAuth, holdStepUp } from "./generation.js";
import { clearPendingAuthz, readPendingAuthz } from "./oauth.js";
import { messagePage, sendPage } from "./pages.js";
import { openJson, sealJson } from "./sealed.js";
import { appendSetCookie, STEP_UP_WINDOW_MS, stepUpValid, type Session } from "./sessions.js";
import type { AuthState } from "./state.js";
import { WEBAUTHN_SCRIPT } from "./static.js";
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
  storePasskey,
  verifyAuthentication,
  verifyRegistration,
  type ChallengeKind,
  type Passkey,
} from "./webauthn.js";

const CHAL_COOKIE = "gw_chal";
const ENROLL_COOKIE = "gw_enroll";

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

  /**
   * The new session replaces the browser's old one; call inside the issuing
   * transaction. `verified`: it comes from an assertion with an existing
   * passkey (login), which opens its step-up window; enrollment does not.
   */
  async function startSession(tx: Queryable, req: FastifyRequest, accountId: string, passkeyId: Buffer, verified: boolean): Promise<string> {
    const old = s.sessions.fromRequest(req);
    if (old) await s.sessions.delete(old, tx);
    const { ip, userAgent } = requestMeta(req);
    return s.sessions.create({ accountId, passkeyId, verified, ip, userAgent }, tx);
  }

  /**
   * Adding or deleting a passkey needs a recent assertion with an existing
   * passkey in this session (audit gateway-auth-1): checked here at the start
   * and again under lock where the change is written.
   */
  function needsStepUp(session: Session, reply: FastifyReply): boolean {
    if (stepUpValid(session, s.now())) return false;
    void reply.code(403).send({ error: "reauth_required" });
    return true;
  }

  /** The material a ceremony validated was revoked or reset before anything was issued from it. */
  function stale(req: FastifyRequest, reply: FastifyReply, event: string, accountId: string, status: number, error: string) {
    void audit(s.ctx, { event, accountId, ...requestMeta(req), details: { reason: "revoked meanwhile" } }, s.now());
    return reply.code(status).send({ error });
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
        `<h1>Sign in</h1><p>Use your passkey to continue${pending ? ` to ${escapeHtml(s.ctx.config.auth.rpName)}` : ""}.</p>` +
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
    let generation: number;
    try {
      const challenge = await consumeFor(req, "login", null);
      ({ passkey, generation } = await verifyAuthentication(s, { response: body(req) as unknown as AuthenticationResponseJSON, challenge }));
    } catch (err) {
      return fail(req, reply, "login.fail", err);
    }
    clearCookie(reply, CHAL_COOKIE, "/auth");
    const account = await getAccountById(s.ctx, passkey.accountId);
    if (!account || !s.ctx.config.allowedEmails.includes(account.email)) {
      void audit(s.ctx, { event: "login.not_allowed", accountId: passkey.accountId, ip, userAgent }, s.now());
      return reply.code(403).send({ error: "account_not_allowed" });
    }
    const pending = readPendingAuthz(s, req);
    const issued = await s.ctx.db.transaction(async (tx) => {
      if (!(await holdAuth(tx, { accountId: account.id, generation, passkeyId: passkey.id }))) return null;
      const session = await startSession(tx, req, account.id, passkey.id, true);
      const code = pending
        ? await s.store.issueCode(
            {
              clientId: pending.client_id,
              accountId: account.id,
              passkeyId: passkey.id,
              redirectUri: pending.redirect_uri,
              codeChallenge: pending.code_challenge,
              scopes: pending.scopes,
              resource: pending.resource,
            },
            tx,
          )
        : null;
      return { session, code };
    });
    if (!issued) return stale(req, reply, "login.fail", account.id, 400, "verification_failed");
    s.limiter.refund("login", req.ip);
    s.sessions.setCookie(reply, issued.session);
    let next = "/auth/passkeys";
    if (pending && issued.code) {
      const code = issued.code;
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
        `<h1>Create a passkey</h1><p>This passkey will sign <strong>${escapeHtml(peek.email)}</strong> in to ${escapeHtml(s.ctx.config.auth.rpName)}.</p>` +
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
    let issued: { passkey: Passkey; session: string } | null;
    try {
      const challenge = await consumeFor(req, "enroll", peek.accountId);
      const info = await verifyRegistration(s, { response: b.response as RegistrationResponseJSON, challenge });
      // Link, passkey and session in one transaction under the generation:
      // a reset (which deletes the link) is either before it or after it.
      issued = await s.ctx.db.transaction(async (tx) => {
        if (!(await holdAuth(tx, { accountId: peek.accountId, generation: peek.generation }))) return null;
        if ((await consumeEnrollToken(tx, hashToken(token), s.now())) !== peek.accountId) return null;
        const passkey = await storePasskey(s, tx, {
          info,
          accountId: peek.accountId,
          name: passkeyName(b.name, `Passkey ${new Date(s.now()).toISOString().slice(0, 10)}`),
        });
        return { passkey, session: await startSession(tx, req, peek.accountId, passkey.id, false) };
      });
    } catch (err) {
      return fail(req, reply, "enroll.fail", err, peek.accountId);
    }
    if (!issued) return stale(req, reply, "enroll.fail", peek.accountId, 410, "link_expired");
    const { passkey } = issued;
    clearCookie(reply, CHAL_COOKIE, "/auth");
    clearCookie(reply, ENROLL_COOKIE, "/auth/enroll");
    s.sessions.setCookie(reply, issued.session);
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
    // Seconds left of the step-up window: the page asks for a passkey first once it has run out.
    const manageFor = session.verifiedAt === null ? 0 : Math.max(0, Math.floor((session.verifiedAt + STEP_UP_WINDOW_MS - s.now()) / 1000));
    return sendPage(reply, {
      title: "Passkeys",
      scripts: [WEBAUTHN_SCRIPT, "auth.js"],
      body:
        `<h1>Passkeys</h1><p>Signed in as <strong>${escapeHtml(session.email)}</strong>.</p>` +
        `<ul class="passkeys" id="passkeys" data-manage-for="${manageFor}">${rows}</ul>` +
        `<p><small>Adding or deleting a passkey asks for one of your passkeys first, unless you signed in within the last ${STEP_UP_WINDOW_MS / 60_000} minutes.</small></p>` +
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
    if (needsStepUp(session, reply)) return;
    const options = await registrationOptions(s, { id: session.accountId, email: session.email });
    setChallengeCookie(reply, await storeChallenge(s, "add", options.challenge, session.accountId));
    return options;
  });

  app.post("/auth/passkeys/verify", async (req, reply) => {
    if (!sameOrigin(req, reply, s.origin, { json: true })) return;
    const session = await s.sessions.ofRequest(req);
    if (!session) return reply.code(401).send({ error: "no_session" });
    if (limited(req, reply, "manage", 30)) return;
    if (needsStepUp(session, reply)) return;
    const { ip, userAgent } = requestMeta(req);
    const b = body(req);
    try {
      const challenge = await consumeFor(req, "add", session.accountId);
      const info = await verifyRegistration(s, { response: b.response as RegistrationResponseJSON, challenge });
      // The session must still be live (not reset, not ended with its passkey) when the passkey is written.
      const passkey = await s.ctx.db.transaction(async (tx) => {
        const held = await holdAuth(tx, {
          accountId: session.accountId,
          generation: session.generation,
          session: { idHash: session.idHash, now: s.now() },
        });
        if (!held) return null;
        // Registering never renews the step-up: only an assertion with an existing passkey does.
        if (!(await holdStepUp(tx, session, s.now()))) return "reauth_required" as const;
        return storePasskey(s, tx, {
          info,
          accountId: session.accountId,
          name: passkeyName(b.name, `Passkey ${new Date(s.now()).toISOString().slice(0, 10)}`),
        });
      });
      if (!passkey) return stale(req, reply, "passkey.add_fail", session.accountId, 401, "no_session");
      if (passkey === "reauth_required") return reply.code(403).send({ error: "reauth_required" });
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
    const renamed = await renamePasskey(s, session.accountId, id, name, session);
    if (renamed !== "renamed") return reply.code(renamed === "not_found" ? 404 : 401).send({ error: renamed });
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
    if (needsStepUp(session, reply)) return;
    const outcome = await deletePasskey(s, session.accountId, id, session);
    if (outcome.status !== "deleted") {
      const status = { not_found: 404, last_passkey: 409, no_session: 401, reauth_required: 403 }[outcome.status];
      return reply.code(status).send({ error: outcome.status });
    }
    const details = { sessions: outcome.sessions, grants: outcome.grants };
    void audit(s.ctx, { event: "passkey.delete", accountId: session.accountId, ...requestMeta(req), details }, s.now());
    return { ok: true };
  });

  // --- step-up: prove an existing passkey before adding or deleting one ------

  app.post("/auth/passkeys/reauth/options", async (req, reply) => {
    if (!sameOrigin(req, reply, s.origin, { json: false })) return;
    const session = await s.sessions.ofRequest(req);
    if (!session) return reply.code(401).send({ error: "no_session" });
    if (limited(req, reply, "manage", 30)) return;
    const options = await authenticationOptions(s, await listPasskeys(s, session.accountId));
    setChallengeCookie(reply, await storeChallenge(s, "reauth", options.challenge, session.accountId));
    return options;
  });

  app.post("/auth/passkeys/reauth/verify", async (req, reply) => {
    if (!sameOrigin(req, reply, s.origin, { json: true })) return;
    const session = await s.sessions.ofRequest(req);
    if (!session) return reply.code(401).send({ error: "no_session" });
    if (limited(req, reply, "manage", 30)) return;
    const { ip, userAgent } = requestMeta(req);
    let verified: { passkey: Passkey; generation: number };
    try {
      const challenge = await consumeFor(req, "reauth", session.accountId);
      verified = await verifyAuthentication(s, { response: body(req) as unknown as AuthenticationResponseJSON, challenge });
      if (verified.passkey.accountId !== session.accountId) throw new CeremonyError("step-up: another account's passkey");
    } catch (err) {
      return fail(req, reply, "passkey.reauth_fail", err, session.accountId);
    }
    const { passkey, generation } = verified;
    const ok = await s.ctx.db.transaction(async (tx) => {
      const held = await holdAuth(tx, {
        accountId: session.accountId,
        generation,
        passkeyId: passkey.id,
        session: { idHash: session.idHash, now: s.now() },
      });
      if (held) await s.sessions.markVerified(tx, session.idHash, passkey.id);
      return held;
    });
    if (!ok) return stale(req, reply, "passkey.reauth_fail", session.accountId, 401, "no_session");
    clearCookie(reply, CHAL_COOKIE, "/auth");
    void audit(s.ctx, { event: "passkey.reauth", accountId: session.accountId, ip, userAgent, details: { passkey: passkey.name } }, s.now());
    return { ok: true, manageFor: STEP_UP_WINDOW_MS / 1000 };
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
