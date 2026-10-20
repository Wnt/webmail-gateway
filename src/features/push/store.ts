import type { Db, Queryable } from "../../db/pool.js";

/** SQL for the push tables (migrations/200_push.sql). Every function takes the db (or a tx) first. */

// ---------------------------------------------------------------- relay records

/** How long an anonymous relay record, or an unverified PushSubscription, may wait for verification. */
export const PENDING_WINDOW_MS = 10 * 60 * 1000;

export interface RelaySub {
  relayId: string;
  endpoint: string;
  p256dh: string;
  auth: string;
  accountLabel: string | null;
  verificationCode: string | null;
  createdAt: Date;
  lastPushAt: Date | null;
  goneAt: Date | null;
  failCount: number;
}

interface RelayRow {
  relay_id: string;
  endpoint: string;
  p256dh: string;
  auth: string;
  account_label: string | null;
  verification_code: string | null;
  created_at: Date;
  last_push_at: Date | null;
  gone_at: Date | null;
  fail_count: number;
}

const toRelay = (r: RelayRow): RelaySub => ({
  relayId: r.relay_id,
  endpoint: r.endpoint,
  p256dh: r.p256dh,
  auth: r.auth,
  accountLabel: r.account_label,
  verificationCode: r.verification_code,
  createdAt: r.created_at,
  lastPushAt: r.last_push_at,
  goneAt: r.gone_at,
  failCount: r.fail_count,
});

/** Register (or re-register) a browser endpoint. Always clears the verification code and revives a gone record. */
export async function upsertRelaySub(
  db: Queryable,
  s: { relayId: string; endpoint: string; p256dh: string; auth: string; accountLabel: string | null; pendingSource?: string | null },
): Promise<void> {
  // pending_source is charged once, at insert: refreshing a pending record never moves its charge to
  // another source (which would let sources trade quota), and a linked record never gets one again.
  await db.query(
    `INSERT INTO push_relay_sub (relay_id, endpoint, p256dh, auth, account_label, pending_source)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (relay_id) DO UPDATE SET
       incarnation = CASE
         WHEN push_relay_sub.endpoint = EXCLUDED.endpoint AND push_relay_sub.p256dh = EXCLUDED.p256dh
              AND push_relay_sub.auth = EXCLUDED.auth THEN push_relay_sub.incarnation
         ELSE gen_random_uuid()::text END,
       endpoint = EXCLUDED.endpoint, p256dh = EXCLUDED.p256dh, auth = EXCLUDED.auth,
       account_label = EXCLUDED.account_label, verification_code = NULL,
       updated_at = now(), gone_at = NULL, fail_count = 0,
       pending_source = CASE WHEN push_relay_sub.linked_at IS NULL THEN push_relay_sub.pending_source END`,
    [s.relayId, s.endpoint, s.p256dh, s.auth, s.accountLabel, s.pendingSource ?? null],
  );
}

/**
 * Anonymous registrations are "pending" until a verified PushSubscription
 * links them (gateway-data-2). They are bounded per source and globally, and
 * expire after the setup window; re-registering an existing record (Bulwark
 * does that on every enable and daily resync) adds no row and is never refused.
 */
export interface PendingLimits {
  /** A pending record not re-registered or linked within this window is deleted. */
  windowMs: number;
  /** Most pending records at once, in total. */
  maxPending: number;
  /** Most pending records at once from one source (client IP, IPv6 /64). */
  maxPendingPerSource: number;
}

export type RegisterOutcome = "ok" | "source_full" | "global_full";

/** Arbitrary constant for pg_advisory_xact_lock: serialises the pending-quota check with the insert. */
const PENDING_LOCK_KEY = 7_283_520;

export async function registerRelaySub(
  db: Db,
  s: { relayId: string; endpoint: string; p256dh: string; auth: string; accountLabel: string | null; source: string },
  limits: PendingLimits,
): Promise<RegisterOutcome> {
  return db.transaction(async (tx) => {
    await tx.query("SELECT pg_advisory_xact_lock($1)", [PENDING_LOCK_KEY]);
    // Expired pending records go first, so they neither count nor linger until the next GC.
    await tx.query(
      "DELETE FROM push_relay_sub WHERE linked_at IS NULL AND updated_at < now() - make_interval(secs => $1::double precision / 1000)",
      [limits.windowMs],
    );
    // Lock the record itself: a concurrent anonymous DELETE must not turn this refresh (exempt from the
    // quotas) into a fresh insert. If the record is already gone, the quotas apply as to any new one.
    const existing = await tx.query("SELECT 1 FROM push_relay_sub WHERE relay_id = $1 FOR UPDATE", [s.relayId]);
    const exists = existing.rows.length > 0;
    const { rows } = await tx.query<{ referenced: boolean; source: number; total: number }>(
      `SELECT EXISTS (SELECT 1 FROM push_jmap_sub s WHERE s.relay_id = $1 AND ${DELIVERABLE}) AS referenced,
              (SELECT count(*)::int FROM push_relay_sub WHERE linked_at IS NULL AND pending_source = $2) AS source,
              (SELECT count(*)::int FROM push_relay_sub WHERE linked_at IS NULL) AS total`,
      [s.relayId, s.source],
    );
    const r = rows[0]!;
    if (!exists && !r.referenced) {
      if (r.total >= limits.maxPending) return "global_full";
      if (r.source >= limits.maxPendingPerSource) return "source_full";
    }
    await upsertRelaySub(tx, { ...s, pendingSource: s.source });
    // A record deleted and registered again under an id that a verified subscription still uses is not pending.
    if (r.referenced) await linkRelaySub(tx, s.relayId);
    return "ok";
  });
}

/** A verified PushSubscription points at this record: it is no longer pending. */
export async function linkRelaySub(db: Queryable, relayId: string): Promise<void> {
  await db.query(
    "UPDATE push_relay_sub SET linked_at = COALESCE(linked_at, now()), pending_source = NULL WHERE relay_id = $1",
    [relayId],
  );
}

export async function getRelaySub(db: Queryable, relayId: string): Promise<RelaySub | null> {
  const { rows } = await db.query<RelayRow>("SELECT * FROM push_relay_sub WHERE relay_id = $1", [relayId]);
  return rows[0] ? toRelay(rows[0]) : null;
}

export async function deleteRelaySub(db: Queryable, relayId: string): Promise<void> {
  await db.query("DELETE FROM push_relay_sub WHERE relay_id = $1", [relayId]);
}

/** The emulated "PushVerification delivery": the code lands where Bulwark polls for it. */
export async function setRelayVerificationCode(db: Queryable, relayId: string, code: string): Promise<boolean> {
  const res = await db.query("UPDATE push_relay_sub SET verification_code = $2 WHERE relay_id = $1", [relayId, code]);
  return (res.rowCount ?? 0) > 0;
}

/**
 * `active/:id`: null for an unknown id. Active means not gone and either a
 * verified, unexpired emulated subscription points at it, or it is fresh.
 */
export async function relayActive(db: Queryable, relayId: string, graceMs: number): Promise<boolean | null> {
  const { rows } = await db.query<{ gone: boolean; fresh: boolean; referenced: boolean }>(
    `SELECT r.gone_at IS NOT NULL AS gone,
            r.created_at > now() - make_interval(secs => $2::double precision / 1000) AS fresh,
            EXISTS (SELECT 1 FROM push_jmap_sub s WHERE s.relay_id = r.relay_id AND ${DELIVERABLE}) AS referenced
       FROM push_relay_sub r WHERE r.relay_id = $1`,
    [relayId, graceMs],
  );
  const r = rows[0];
  if (!r) return null;
  return !r.gone && (r.referenced || r.fresh);
}

/** `revoked`: the subscription lost its authorization before the send (nothing is recorded on the relay). */
export type SendOutcome = "ok" | "gone" | "failed" | "rejected" | "revoked";

/** Record a send result. `rejected` (400/401/403) marks the record gone after 3 in a row. */
export async function recordRelayResult(db: Queryable, relayId: string, outcome: SendOutcome): Promise<void> {
  if (outcome === "ok") {
    await db.query("UPDATE push_relay_sub SET last_push_at = now(), fail_count = 0 WHERE relay_id = $1", [relayId]);
  } else if (outcome === "gone") {
    await db.query("UPDATE push_relay_sub SET gone_at = now() WHERE relay_id = $1", [relayId]);
  } else if (outcome === "rejected") {
    await db.query(
      `UPDATE push_relay_sub SET fail_count = fail_count + 1,
         gone_at = CASE WHEN fail_count + 1 >= 3 THEN now() ELSE gone_at END
       WHERE relay_id = $1`,
      [relayId],
    );
  } else {
    await db.query("UPDATE push_relay_sub SET fail_count = fail_count + 1 WHERE relay_id = $1", [relayId]);
  }
}

// ------------------------------------------------------- emulated JMAP subscriptions

/**
 * Push authorization of the emulated subscription `s` (audit gateway-data-1),
 * read from the database on every use so that a revocation made anywhere,
 * including the bootstrap CLI's process, holds:
 *  - the account's auth generation has not moved since it was created
 *    (`bootstrap --reset` bumps it);
 *  - its grant has not been revoked. A grant that merely expired keeps push
 *    going (notifications outlive sign-in by design) until it is revoked on
 *    purpose, which `TokenStore.revokeIn` also does to expired grants;
 *  - a subscription without a grant (password mode, or from before grants
 *    were recorded) ends with the account's next deliberate revocation of a
 *    grant or passkey (`account.auth_revoked_at`);
 *  - its grant's passkey, if temporary (migration 103), has not expired:
 *    unlike a grant's own expiry, that one ends push at once, before the
 *    sweeper revokes the grant.
 */
const authorizedSql = (t: string) => `EXISTS (SELECT 1 FROM account a
          WHERE a.id = ${t}.account_id AND a.auth_generation = ${t}.auth_generation
            AND (${t}.grant_id IS NOT NULL OR a.auth_revoked_at IS NULL OR a.auth_revoked_at < ${t}.created_at))
  AND NOT EXISTS (SELECT 1 FROM oauth_grant g
                  WHERE g.id = ${t}.grant_id AND g.revoked_at IS NOT NULL AND g.revoked_reason <> 'expired')
  AND NOT EXISTS (SELECT 1 FROM oauth_grant g JOIN passkey p ON p.id = g.passkey_id
                  WHERE g.id = ${t}.grant_id AND p.expires_at <= now())`;
const AUTHORIZED = authorizedSql("s");
/** The same rules for an APNs device registration (alias `d`, migration 240): it always has a grant. */
const APNS_AUTHORIZED = authorizedSql("d");

/** A subscription that can receive pushes: verified, unexpired, authorized. */
const DELIVERABLE = `s.verified_at IS NOT NULL AND s.expires > now() AND ${AUTHORIZED}`;

export interface JmapSub {
  id: string;
  accountId: string;
  /** The OAuth grant whose token created it; null in password mode. */
  grantId: string | null;
  deviceClientId: string;
  relayId: string;
  url: string;
  types: string[] | null;
  expires: Date;
  verificationCode: string;
  verifiedAt: Date | null;
  createdAt: Date;
}

interface JmapSubRow {
  id: string;
  account_id: string;
  grant_id: string | null;
  device_client_id: string;
  relay_id: string;
  url: string;
  types: string[] | null;
  expires: Date;
  verification_code: string;
  verified_at: Date | null;
  created_at: Date;
}

const toJmapSub = (r: JmapSubRow): JmapSub => ({
  id: r.id,
  accountId: r.account_id,
  grantId: r.grant_id,
  deviceClientId: r.device_client_id,
  relayId: r.relay_id,
  url: r.url,
  types: r.types,
  expires: r.expires,
  verificationCode: r.verification_code,
  verifiedAt: r.verified_at,
  createdAt: r.created_at,
});

/** The account's subscriptions. Revoked ones are gone as far as clients can tell, so a re-sync after signing in again creates a new one. */
export async function listJmapSubs(db: Queryable, accountId: string): Promise<JmapSub[]> {
  const { rows } = await db.query<JmapSubRow>(
    `SELECT * FROM push_jmap_sub s WHERE s.account_id = $1 AND ${AUTHORIZED} ORDER BY s.created_at, s.id`,
    [accountId],
  );
  return rows.map(toJmapSub);
}

/** Bound to `grantId` and to the account's current auth generation. */
export async function insertJmapSub(db: Queryable, s: Omit<JmapSub, "verifiedAt" | "createdAt">): Promise<void> {
  await db.query(
    `INSERT INTO push_jmap_sub (id, account_id, grant_id, device_client_id, relay_id, url, types, expires, verification_code, auth_generation)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, (SELECT auth_generation FROM account WHERE id = $2))`,
    [s.id, s.accountId, s.grantId, s.deviceClientId, s.relayId, s.url, s.types, s.expires, s.verificationCode],
  );
}

/**
 * Insert unless the account already has `max` subscriptions. Unverified ones
 * count too, and expire after the setup window (garbageCollect). The account
 * row lock makes the count and the insert atomic against concurrent
 * PushSubscription/set calls.
 */
export async function insertJmapSubWithinQuota(db: Db, s: Omit<JmapSub, "verifiedAt" | "createdAt">, max: number): Promise<boolean> {
  return db.transaction(async (tx) => {
    await tx.query("SELECT 1 FROM account WHERE id = $1 FOR UPDATE", [s.accountId]);
    // Abandoned set-ups give their slot back now, not only at the next garbage collection.
    await tx.query(
      `DELETE FROM push_jmap_sub WHERE account_id = $1 AND verified_at IS NULL
         AND created_at < now() - make_interval(secs => $2::double precision / 1000)`,
      [s.accountId, PENDING_WINDOW_MS],
    );
    // Revoked subscriptions do not count (clients no longer see them; garbageCollect deletes them).
    const { rows } = await tx.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM push_jmap_sub s WHERE s.account_id = $1 AND ${AUTHORIZED}`,
      [s.accountId],
    );
    if ((rows[0]?.n ?? 0) >= max) return false;
    await insertJmapSub(tx, s);
    return true;
  });
}

export async function updateJmapSub(
  db: Queryable,
  id: string,
  accountId: string,
  patch: { types?: string[] | null; expires?: Date; verified?: boolean },
): Promise<void> {
  const sets: string[] = [];
  const vals: unknown[] = [id, accountId];
  if ("types" in patch) {
    vals.push(patch.types ?? null);
    sets.push(`types = $${vals.length}`);
  }
  if (patch.expires) {
    vals.push(patch.expires);
    sets.push(`expires = $${vals.length}`);
  }
  if (patch.verified) sets.push("verified_at = COALESCE(verified_at, now())");
  if (sets.length === 0) return;
  await db.query(`UPDATE push_jmap_sub SET ${sets.join(", ")} WHERE id = $1 AND account_id = $2`, vals);
}

/** Delete; a relay record no other verified subscription uses becomes pending again (and expires unless re-linked). */
export async function deleteJmapSub(db: Queryable, id: string, accountId: string): Promise<boolean> {
  const { rows } = await db.query<{ relay_id: string }>(
    "DELETE FROM push_jmap_sub WHERE id = $1 AND account_id = $2 RETURNING relay_id",
    [id, accountId],
  );
  if (!rows[0]) return false;
  await db.query(
    `UPDATE push_relay_sub r SET linked_at = NULL, updated_at = now()
      WHERE r.relay_id = $1 AND r.linked_at IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM push_jmap_sub s WHERE s.relay_id = r.relay_id AND ${DELIVERABLE})`,
    [rows[0].relay_id],
  );
  return true;
}

/**
 * Does the account have a browser subscription or an APNs device that can
 * receive pushes (P1: only then keep an upstream subscription, and so an
 * IDLE connection)? An account with only the native app counts too.
 */
export async function hasActiveSubs(db: Queryable, accountId: string): Promise<boolean> {
  const { rows } = await db.query<{ web: boolean; apns: boolean }>(
    `SELECT EXISTS (SELECT 1 FROM push_jmap_sub s JOIN push_relay_sub r ON r.relay_id = s.relay_id
                     WHERE s.account_id = $1 AND ${DELIVERABLE} AND r.gone_at IS NULL) AS web,
            EXISTS (SELECT 1 FROM push_apns_device d WHERE d.account_id = $1 AND d.gone_at IS NULL AND ${APNS_AUTHORIZED}) AS apns`,
    [accountId],
  );
  return rows[0]?.web === true || rows[0]?.apns === true;
}

export interface PushTarget {
  accountId: string;
  relayId: string;
  endpoint: string;
  p256dh: string;
  auth: string;
  /** A deliverable emulated subscription of the account that points at the relay record (what authorizes this target). */
  subId?: string;
  /** The relay record's incarnation when the target was read (migration 230). */
  incarnation?: string;
  /** The endpoint also serves another account's subscriptions (a browser with several logins). */
  shared?: boolean;
}

/** The account is (still) in `ALLOWED_EMAILS` (`$n` is that list): removing it ends its pushes at once. */
const ALLOWED = (n: number, t = "s") => `EXISTS (SELECT 1 FROM account ae WHERE ae.id = ${t}.account_id AND ae.email = ANY ($${n}::text[]))`;

/** Distinct endpoints that should get the account's EmailDelivery pushes. `allowed`: the configured allowlist. */
export async function targetsForAccount(db: Queryable, accountId: string, allowed: readonly string[]): Promise<PushTarget[]> {
  const { rows } = await db.query<{
    relay_id: string; endpoint: string; p256dh: string; auth: string; sub_id: string; incarnation: string; shared: boolean;
  }>(
    `SELECT DISTINCT ON (r.endpoint) r.relay_id, r.endpoint, r.p256dh, r.auth, s.id AS sub_id, r.incarnation,
            EXISTS (SELECT 1 FROM push_jmap_sub s2 JOIN push_relay_sub r2 ON r2.relay_id = s2.relay_id
                     WHERE r2.endpoint = r.endpoint AND s2.account_id <> s.account_id AND r2.gone_at IS NULL) AS shared
       FROM push_jmap_sub s JOIN push_relay_sub r ON r.relay_id = s.relay_id
      WHERE s.account_id = $1 AND ${DELIVERABLE} AND ${ALLOWED(2)} AND r.gone_at IS NULL
        AND (s.types IS NULL OR 'EmailDelivery' = ANY (s.types))
      ORDER BY r.endpoint, r.updated_at DESC, s.created_at DESC`,
    [accountId, [...allowed]],
  );
  return rows.map((r) => ({
    accountId, relayId: r.relay_id, endpoint: r.endpoint, p256dh: r.p256dh, auth: r.auth,
    subId: r.sub_id, incarnation: r.incarnation, shared: r.shared,
  }));
}

/** Is `target` still a recipient (and its account still allowlisted)? Checked before every send attempt, retries included. */
/**
 * Before every send attempt: the target is still what it was when the push
 * was queued. The subscription it was read with (when known) is still a
 * deliverable, authorized EmailDelivery subscription of the account pointing
 * at the relay record, and that record still exists, is not gone and is the
 * same incarnation with the same endpoint and keys (a deleted, re-registered
 * or replaced record or subscription revokes what was queued for it; a
 * retry never goes out under other authority than the one it was made for,
 * which its preview ticket names).
 */
export async function targetStillAuthorized(db: Queryable, target: PushTarget, allowed: readonly string[]): Promise<boolean> {
  return (await targetCheck(db, target, allowed)) !== null;
}

/**
 * `targetStillAuthorized`, and, when it is, whether the endpoint now also
 * serves another account (read again for every attempt: a second login may
 * have subscribed the same browser while the push waited).
 */
export async function targetCheck(db: Queryable, target: PushTarget, allowed: readonly string[]): Promise<{ shared: boolean } | null> {
  const { rows } = await db.query<{ shared: boolean }>(
    `SELECT EXISTS (SELECT 1 FROM push_jmap_sub s2 JOIN push_relay_sub r2 ON r2.relay_id = s2.relay_id
                     WHERE r2.endpoint = r.endpoint AND s2.account_id <> s.account_id AND r2.gone_at IS NULL) AS shared
       FROM push_jmap_sub s JOIN push_relay_sub r ON r.relay_id = s.relay_id
      WHERE s.account_id = $1 AND s.relay_id = $2 AND r.gone_at IS NULL
        AND r.endpoint = $4 AND r.p256dh = $5 AND r.auth = $6
        AND ($7::text IS NULL OR s.id = $7) AND ($8::text IS NULL OR r.incarnation = $8)
        AND (s.types IS NULL OR 'EmailDelivery' = ANY (s.types))
        AND ${DELIVERABLE} AND ${ALLOWED(3)} LIMIT 1`,
    [target.accountId, target.relayId, [...allowed], target.endpoint, target.p256dh, target.auth, target.subId ?? null, target.incarnation ?? null],
  );
  return rows[0] ? { shared: rows[0].shared === true } : null;
}

/**
 * A preview ticket (preview-ticket.ts) can still be used: the very
 * subscription it was minted under is still deliverable, authorized and an
 * EmailDelivery subscription of the account, it still points at the relay
 * record, and that record is not gone. Returns the record's endpoint, keys
 * and incarnation (the caller checks they are the ones the ticket was minted
 * for), or null. A new subscription or grant on the same relay id, or the
 * record deleted and registered again, never revives an older ticket.
 */
export async function previewTicketTarget(
  db: Queryable,
  t: { accountId: string; relayId: string; subId: string },
  allowed: readonly string[],
): Promise<{ endpoint: string; p256dh: string; auth: string; incarnation: string } | null> {
  const { rows } = await db.query<{ endpoint: string; p256dh: string; auth: string; incarnation: string }>(
    `SELECT r.endpoint, r.p256dh, r.auth, r.incarnation FROM push_jmap_sub s JOIN push_relay_sub r ON r.relay_id = s.relay_id
      WHERE s.id = $1 AND s.account_id = $2 AND s.relay_id = $3 AND r.gone_at IS NULL
        AND (s.types IS NULL OR 'EmailDelivery' = ANY (s.types))
        AND ${DELIVERABLE} AND ${ALLOWED(4)} LIMIT 1`,
    [t.subId, t.accountId, t.relayId, [...allowed]],
  );
  return rows[0] ?? null;
}

// -------------------------------------------------------------- upstream subscription

export type UpstreamStatus = "none" | "creating" | "verifying" | "active" | "failed";

export interface Upstream {
  accountId: string;
  hookId: string;
  upstreamId: string | null;
  legacyAccountId: string | null;
  status: UpstreamStatus;
  verificationCode: string | null;
  expires: Date | null;
  verifiedAt: Date | null;
  baselineAt: Date | null;
  lastEventAt: Date | null;
  lastCheckAt: Date | null;
  lastCheckOk: boolean | null;
  nextAttemptAt: Date | null;
  attempts: number;
  lastError: string | null;
  /** Last processed JMAP Email state (for Email/changes), or null. */
  emailState: string | null;
}

interface UpstreamRow {
  account_id: string;
  hook_id: string;
  upstream_id: string | null;
  legacy_account_id: string | null;
  status: UpstreamStatus;
  verification_code: string | null;
  expires: Date | null;
  verified_at: Date | null;
  baseline_at: Date | null;
  last_event_at: Date | null;
  last_check_at: Date | null;
  last_check_ok: boolean | null;
  next_attempt_at: Date | null;
  attempts: number;
  last_error: string | null;
  email_state: string | null;
}

const toUpstream = (r: UpstreamRow): Upstream => ({
  accountId: r.account_id,
  hookId: r.hook_id,
  upstreamId: r.upstream_id,
  legacyAccountId: r.legacy_account_id,
  status: r.status,
  verificationCode: r.verification_code,
  expires: r.expires,
  verifiedAt: r.verified_at,
  baselineAt: r.baseline_at,
  lastEventAt: r.last_event_at,
  lastCheckAt: r.last_check_at,
  lastCheckOk: r.last_check_ok,
  nextAttemptAt: r.next_attempt_at,
  attempts: r.attempts,
  lastError: r.last_error,
  emailState: r.email_state,
});

const UPSTREAM_COLS: Record<keyof Omit<Upstream, "accountId">, string> = {
  hookId: "hook_id",
  upstreamId: "upstream_id",
  legacyAccountId: "legacy_account_id",
  status: "status",
  verificationCode: "verification_code",
  expires: "expires",
  verifiedAt: "verified_at",
  baselineAt: "baseline_at",
  lastEventAt: "last_event_at",
  lastCheckAt: "last_check_at",
  lastCheckOk: "last_check_ok",
  nextAttemptAt: "next_attempt_at",
  attempts: "attempts",
  lastError: "last_error",
  emailState: "email_state",
};

export async function getUpstream(db: Queryable, accountId: string): Promise<Upstream | null> {
  const { rows } = await db.query<UpstreamRow>("SELECT * FROM push_upstream WHERE account_id = $1", [accountId]);
  return rows[0] ? toUpstream(rows[0]) : null;
}

export async function getUpstreamByHook(db: Queryable, hookId: string): Promise<Upstream | null> {
  const { rows } = await db.query<UpstreamRow>("SELECT * FROM push_upstream WHERE hook_id = $1", [hookId]);
  return rows[0] ? toUpstream(rows[0]) : null;
}

export async function updateUpstream(
  db: Queryable,
  accountId: string,
  patch: Partial<Omit<Upstream, "accountId">>,
): Promise<void> {
  const sets: string[] = [];
  const vals: unknown[] = [accountId];
  for (const [k, v] of Object.entries(patch)) {
    const col = UPSTREAM_COLS[k as keyof typeof UPSTREAM_COLS];
    if (!col) continue;
    vals.push(v);
    sets.push(`${col} = $${vals.length}`);
  }
  if (sets.length === 0) return;
  await db.query(`UPDATE push_upstream SET ${sets.join(", ")} WHERE account_id = $1`, vals);
}

/**
 * Take the per-account lease (inserting a `none` row if there is none yet).
 * Returns the row, or null when someone else holds an unexpired lease.
 */
export async function acquireUpstreamLease(
  db: Queryable,
  accountId: string,
  newHookId: string,
  leaseMs: number,
): Promise<Upstream | null> {
  await db.query(
    `INSERT INTO push_upstream (account_id, hook_id, status) VALUES ($1, $2, 'none') ON CONFLICT (account_id) DO NOTHING`,
    [accountId, newHookId],
  );
  const { rows } = await db.query<UpstreamRow>(
    `UPDATE push_upstream SET lease_until = now() + make_interval(secs => $2::double precision / 1000)
      WHERE account_id = $1 AND (lease_until IS NULL OR lease_until < now())
      RETURNING *`,
    [accountId, leaseMs],
  );
  return rows[0] ? toUpstream(rows[0]) : null;
}

export async function releaseUpstreamLease(db: Queryable, accountId: string): Promise<void> {
  await db.query("UPDATE push_upstream SET lease_until = NULL WHERE account_id = $1", [accountId]);
}

/** Store the PushVerification code for a hook (first write wins; must match the upstream id once known). */
export async function storeUpstreamCode(
  db: Queryable,
  hookId: string,
  pushSubscriptionId: string | null,
  code: string,
): Promise<boolean> {
  const res = await db.query(
    `UPDATE push_upstream SET verification_code = $3
      WHERE hook_id = $1 AND verification_code IS NULL AND status IN ('creating', 'verifying')
        AND (upstream_id IS NULL OR $2::text IS NULL OR upstream_id = $2)`,
    [hookId, pushSubscriptionId, code],
  );
  return (res.rowCount ?? 0) > 0;
}

/** Accounts the reconciler looks at: anything with an upstream row in use, active subs or APNs devices, or (always-mode) an upstream credential. */
export async function accountsToReconcile(db: Queryable, always: boolean): Promise<string[]> {
  const { rows } = await db.query<{ id: string }>(
    `SELECT account_id AS id FROM push_upstream WHERE status <> 'none'
     UNION SELECT s.account_id FROM push_jmap_sub s WHERE ${DELIVERABLE}
     UNION SELECT d.account_id FROM push_apns_device d WHERE d.gone_at IS NULL AND ${APNS_AUTHORIZED}
     UNION SELECT id FROM account WHERE $1::boolean AND (gandi_secret IS NOT NULL OR upstream_secret IS NOT NULL)`,
    [always],
  );
  return rows.map((r) => r.id);
}

// ------------------------------------------------------------------- dedupe / claim

/** Atomically claim messages; returns the ids this caller won (never announced before). */
export async function claimEmails(
  db: Queryable,
  accountId: string,
  items: { emailId: string; receivedAt: Date }[],
): Promise<Set<string>> {
  if (items.length === 0) return new Set();
  const { rows } = await db.query<{ email_id: string }>(
    `INSERT INTO push_notified (account_id, email_id, received_at)
     SELECT $1, e.id, e.received_at FROM unnest($2::text[], $3::timestamptz[]) AS e(id, received_at)
     ON CONFLICT DO NOTHING RETURNING email_id`,
    [accountId, items.map((i) => i.emailId), items.map((i) => i.receivedAt.toISOString())],
  );
  return new Set(rows.map((r) => r.email_id));
}

export async function notifiedIds(db: Queryable, accountId: string, ids: string[]): Promise<Set<string>> {
  if (ids.length === 0) return new Set();
  const { rows } = await db.query<{ email_id: string }>(
    "SELECT email_id FROM push_notified WHERE account_id = $1 AND email_id = ANY ($2::text[])",
    [accountId, ids],
  );
  return new Set(rows.map((r) => r.email_id));
}

/**
 * Housekeeping: old dedupe rows, long-expired or never-verified emulated
 * subs, dead, orphaned or expired pending relay records, revoked APNs
 * devices and ones APNs called gone a month ago.
 */
export async function garbageCollect(db: Queryable, pendingWindowMs = PENDING_WINDOW_MS): Promise<void> {
  const window = "make_interval(secs => $1::double precision / 1000)";
  await db.query("DELETE FROM push_notified WHERE notified_at < now() - interval '7 days'");
  await db.query("DELETE FROM push_summary WHERE created_at < now() - interval '7 days'");
  await db.query("DELETE FROM push_jmap_sub WHERE expires < now() - interval '7 days'");
  await db.query(`DELETE FROM push_jmap_sub s WHERE NOT (${AUTHORIZED})`);
  await db.query(`DELETE FROM push_jmap_sub WHERE verified_at IS NULL AND created_at < now() - ${window}`, [pendingWindowMs]);
  await db.query(`DELETE FROM push_apns_device d WHERE NOT (${APNS_AUTHORIZED})`);
  await db.query("DELETE FROM push_apns_device WHERE gone_at < now() - interval '30 days'");
  await db.query(`DELETE FROM push_relay_sub WHERE linked_at IS NULL AND updated_at < now() - ${window}`, [pendingWindowMs]);
  await db.query(
    `DELETE FROM push_relay_sub r
      WHERE (r.gone_at IS NOT NULL AND r.gone_at < now() - interval '30 days')
         OR (r.updated_at < now() - interval '30 days'
             AND NOT EXISTS (SELECT 1 FROM push_jmap_sub s WHERE s.relay_id = r.relay_id))`,
  );
}

// ------------------------------------------------------------- APNs devices (native app)

/** Most APNs registrations per account (design/ios-native-app.md). */
export const MAX_APNS_DEVICES_PER_ACCOUNT = 10;

export type ApnsEnvironment = "production" | "sandbox";

export interface ApnsDevice {
  id: string;
  accountId: string;
  grantId: string;
  token: string;
  environment: ApnsEnvironment;
  topic: string;
  /** base64url of the device's 65-byte P-256 point. */
  publicKey: string;
  name: string | null;
  locale: "fi" | "en" | null;
  createdAt: Date;
  lastPushAt: Date | null;
  failCount: number;
  goneAt: Date | null;
  /** New on every (re-)registration of the row (migration 240): what a send and its result are for. */
  incarnation: string;
  /** When the device made `publicKey` (epoch ms, as the app sent it; 0 when it did not). */
  keyCreatedAt: number;
}

interface ApnsRow {
  id: string;
  account_id: string;
  grant_id: string;
  token: string;
  environment: ApnsEnvironment;
  topic: string;
  public_key: string;
  name: string | null;
  locale: "fi" | "en" | null;
  created_at: Date;
  last_push_at: Date | null;
  fail_count: number;
  gone_at: Date | null;
  incarnation: string;
  key_created_at: string | number | bigint;
}

const toApns = (r: ApnsRow): ApnsDevice => ({
  id: r.id,
  accountId: r.account_id,
  grantId: r.grant_id,
  token: r.token,
  environment: r.environment,
  topic: r.topic,
  publicKey: r.public_key,
  name: r.name,
  locale: r.locale,
  createdAt: r.created_at,
  lastPushAt: r.last_push_at,
  failCount: r.fail_count,
  goneAt: r.gone_at,
  incarnation: r.incarnation,
  keyCreatedAt: Number(r.key_created_at),
});

export type ApnsRegisterResult = { ok: true; id: string } | { ok: false; reason: "quota" | "revoked" | "taken" | "superseded" | "stale_key" };

/**
 * Register (or re-register) a device token for `accountId`, bound to
 * `grantId` and the account's current auth generation, with a new
 * incarnation. The same token of the same account replaces its row (new
 * key, new grant, same id) unless the row is bound to a newer grant (by the
 * server's grant creation order, the grant id breaking ties): a delayed
 * registration of a previous sign-in never replaces its successor's
 * binding (`superseded`). Within one grant, a registration whose key is
 * older (`keyCreatedAt`, the device's own clock) than the registered one
 * changes nothing (`stale_key`): a delayed POST of a key the device has
 * since replaced. The same key with the same `keyCreatedAt` renews it; a
 * registration without one counts as 0, so it never replaces a key that
 * has one, and two without one behave as before (the later replaces).
 * A token registered to another account is
 * `taken` while that registration is still authorized and not gone; a
 * dead one (signed out, reset, expired temporary passkey, gone) is
 * replaced, under a new id for another account. Decided by the upsert
 * itself, under the row lock, so concurrent registrations cannot race it.
 * At most `max` live registrations per account.
 *
 * Under the account row lock, which `bootstrap --reset` and every grant
 * revocation also take first: a grant revoked (or an account reset) after
 * the caller's token was checked refuses the registration instead of
 * binding it to the new generation.
 */
export async function registerApnsDevice(
  db: Db,
  d: {
    newId: string;
    accountId: string;
    grantId: string;
    token: string;
    environment: ApnsEnvironment;
    topic: string;
    publicKey: string;
    name: string | null;
    locale: "fi" | "en" | null;
    /** Epoch ms when the device made `publicKey`; 0 (or absent) when the app did not say. */
    keyCreatedAt?: number;
  },
  max = MAX_APNS_DEVICES_PER_ACCOUNT,
): Promise<ApnsRegisterResult> {
  return db.transaction(async (tx) => {
    const acc = await tx.query<{ auth_generation: number }>("SELECT auth_generation FROM account WHERE id = $1 FOR UPDATE", [d.accountId]);
    if (!acc.rows[0]) return { ok: false, reason: "revoked" };
    const live = await tx.query("SELECT 1 FROM oauth_grant WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL", [d.grantId, d.accountId]);
    if (live.rows.length === 0) return { ok: false, reason: "revoked" };
    const { rows } = await tx.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM push_apns_device d
        WHERE d.account_id = $1 AND d.token <> $2 AND d.gone_at IS NULL AND ${APNS_AUTHORIZED}`,
      [d.accountId, d.token],
    );
    if ((rows[0]?.n ?? 0) >= max) return { ok: false, reason: "quota" };
    const ins = await tx.query<{ id: string }>(
      `INSERT INTO push_apns_device AS d (id, account_id, grant_id, auth_generation, token, environment, topic, public_key, name, locale, key_created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       ON CONFLICT (token) DO UPDATE SET
         id = CASE WHEN d.account_id = EXCLUDED.account_id THEN d.id ELSE EXCLUDED.id END,
         account_id = EXCLUDED.account_id, grant_id = EXCLUDED.grant_id, auth_generation = EXCLUDED.auth_generation,
         environment = EXCLUDED.environment, topic = EXCLUDED.topic, public_key = EXCLUDED.public_key,
         name = EXCLUDED.name, locale = EXCLUDED.locale, updated_at = now(), gone_at = NULL, fail_count = 0,
         last_push_at = CASE WHEN d.account_id = EXCLUDED.account_id THEN d.last_push_at END,
         created_at = CASE WHEN d.account_id = EXCLUDED.account_id THEN d.created_at ELSE now() END,
         incarnation = gen_random_uuid()::text, key_created_at = EXCLUDED.key_created_at
       WHERE (d.gone_at IS NOT NULL OR NOT (${APNS_AUTHORIZED})
              OR (d.account_id = EXCLUDED.account_id
                  AND NOT EXISTS (SELECT 1 FROM oauth_grant bound, oauth_grant asking
                                   WHERE bound.id = d.grant_id AND asking.id = EXCLUDED.grant_id
                                     AND (bound.created_at, bound.id) > (asking.created_at, asking.id))))
         AND (d.grant_id <> EXCLUDED.grant_id
              OR EXCLUDED.key_created_at > d.key_created_at
              OR (EXCLUDED.key_created_at = d.key_created_at AND (EXCLUDED.public_key = d.public_key OR d.key_created_at = 0)))
       RETURNING id`,
      [d.newId, d.accountId, d.grantId, acc.rows[0].auth_generation, d.token, d.environment, d.topic, d.publicKey, d.name, d.locale, d.keyCreatedAt ?? 0],
    );
    if (ins.rows[0]) return { ok: true, id: ins.rows[0].id };
    // No row: the token's live registration belongs to another account, to
    // a newer sign-in of this one (a delayed POST of the previous sign-in),
    // or, in this very grant, to a newer key (a delayed POST of a lost key).
    const owner = await tx.query<{ account_id: string; grant_id: string }>("SELECT account_id, grant_id FROM push_apns_device WHERE token = $1", [d.token]);
    const o = owner.rows[0];
    if (o?.account_id !== d.accountId) return { ok: false, reason: "taken" };
    return { ok: false, reason: o.grant_id === d.grantId ? "stale_key" : "superseded" };
  });
}

/** One of the account's registrations, in any state, or null. */
export async function getApnsDevice(db: Queryable, id: string, accountId: string): Promise<ApnsDevice | null> {
  const { rows } = await db.query<ApnsRow>("SELECT * FROM push_apns_device WHERE id = $1 AND account_id = $2", [id, accountId]);
  return rows[0] ? toApns(rows[0]) : null;
}

/** Remove one of the account's registrations. */
export async function deleteApnsDevice(db: Queryable, id: string, accountId: string): Promise<boolean> {
  const res = await db.query("DELETE FROM push_apns_device WHERE id = $1 AND account_id = $2", [id, accountId]);
  return (res.rowCount ?? 0) > 0;
}

/** The account's registrations that should get its pushes: not gone, authorized, the account allowlisted. */
export async function apnsTargetsForAccount(db: Queryable, accountId: string, allowed: readonly string[]): Promise<ApnsDevice[]> {
  const { rows } = await db.query<ApnsRow>(
    `SELECT d.* FROM push_apns_device d
      WHERE d.account_id = $1 AND d.gone_at IS NULL AND ${APNS_AUTHORIZED} AND ${ALLOWED(2, "d")}
      ORDER BY d.created_at, d.id`,
    [accountId, [...allowed]],
  );
  return rows.map(toApns);
}

/**
 * Before every send attempt (retries included): the registration is still
 * the very incarnation the push was made for (and so the same account,
 * grant, token, key and destination), not gone, authorized, and its
 * account allowlisted. A renewal in between, even an identical one, makes
 * the queued send stale.
 */
export async function apnsTargetStillAuthorized(db: Queryable, d: ApnsDevice, allowed: readonly string[]): Promise<boolean> {
  const { rows } = await db.query(
    `SELECT 1 FROM push_apns_device d
      WHERE d.id = $1 AND d.account_id = $2 AND d.grant_id = $3 AND d.token = $4 AND d.public_key = $5
        AND d.environment = $6 AND d.topic = $7 AND d.incarnation = $8
        AND d.gone_at IS NULL AND ${APNS_AUTHORIZED} AND ${ALLOWED(9, "d")} LIMIT 1`,
    [d.id, d.accountId, d.grantId, d.token, d.publicKey, d.environment, d.topic, d.incarnation, [...allowed]],
  );
  return rows.length > 0;
}

export type ApnsSendOutcome = "ok" | "gone" | "failed" | "revoked";

/**
 * Record a send result for the incarnation it was sent to: a late answer
 * for an earlier incarnation (a renewal or revival happened meanwhile)
 * changes nothing.
 */
export async function recordApnsResult(db: Queryable, d: Pick<ApnsDevice, "id" | "token" | "incarnation">, outcome: ApnsSendOutcome): Promise<void> {
  const where = "WHERE id = $1 AND token = $2 AND incarnation = $3";
  const args = [d.id, d.token, d.incarnation];
  if (outcome === "ok") await db.query(`UPDATE push_apns_device SET last_push_at = now(), fail_count = 0 ${where}`, args);
  else if (outcome === "gone") await db.query(`UPDATE push_apns_device SET gone_at = now() ${where}`, args);
  else if (outcome === "failed") await db.query(`UPDATE push_apns_device SET fail_count = fail_count + 1 ${where}`, args);
}
