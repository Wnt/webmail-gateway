import type { Queryable } from "../../db/pool.js";

/** SQL for the push tables (migrations/200_push.sql). Every function takes the db (or a tx) first. */

// ---------------------------------------------------------------- relay records

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
  s: { relayId: string; endpoint: string; p256dh: string; auth: string; accountLabel: string | null },
): Promise<void> {
  await db.query(
    `INSERT INTO push_relay_sub (relay_id, endpoint, p256dh, auth, account_label)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (relay_id) DO UPDATE SET
       endpoint = EXCLUDED.endpoint, p256dh = EXCLUDED.p256dh, auth = EXCLUDED.auth,
       account_label = EXCLUDED.account_label, verification_code = NULL,
       updated_at = now(), gone_at = NULL, fail_count = 0`,
    [s.relayId, s.endpoint, s.p256dh, s.auth, s.accountLabel],
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
            EXISTS (SELECT 1 FROM push_jmap_sub s
                    WHERE s.relay_id = r.relay_id AND s.verified_at IS NOT NULL AND s.expires > now()) AS referenced
       FROM push_relay_sub r WHERE r.relay_id = $1`,
    [relayId, graceMs],
  );
  const r = rows[0];
  if (!r) return null;
  return !r.gone && (r.referenced || r.fresh);
}

export type SendOutcome = "ok" | "gone" | "failed" | "rejected";

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

export interface JmapSub {
  id: string;
  accountId: string;
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
  deviceClientId: r.device_client_id,
  relayId: r.relay_id,
  url: r.url,
  types: r.types,
  expires: r.expires,
  verificationCode: r.verification_code,
  verifiedAt: r.verified_at,
  createdAt: r.created_at,
});

export async function listJmapSubs(db: Queryable, accountId: string): Promise<JmapSub[]> {
  const { rows } = await db.query<JmapSubRow>(
    "SELECT * FROM push_jmap_sub WHERE account_id = $1 ORDER BY created_at, id",
    [accountId],
  );
  return rows.map(toJmapSub);
}

export async function insertJmapSub(db: Queryable, s: Omit<JmapSub, "verifiedAt" | "createdAt">): Promise<void> {
  await db.query(
    `INSERT INTO push_jmap_sub (id, account_id, device_client_id, relay_id, url, types, expires, verification_code)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [s.id, s.accountId, s.deviceClientId, s.relayId, s.url, s.types, s.expires, s.verificationCode],
  );
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

export async function deleteJmapSub(db: Queryable, id: string, accountId: string): Promise<boolean> {
  const res = await db.query("DELETE FROM push_jmap_sub WHERE id = $1 AND account_id = $2", [id, accountId]);
  return (res.rowCount ?? 0) > 0;
}

/** Does the account have a subscription that can receive pushes (P1: only then keep an upstream)? */
export async function hasActiveSubs(db: Queryable, accountId: string): Promise<boolean> {
  const { rows } = await db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM push_jmap_sub s JOIN push_relay_sub r ON r.relay_id = s.relay_id
      WHERE s.account_id = $1 AND s.verified_at IS NOT NULL AND s.expires > now() AND r.gone_at IS NULL`,
    [accountId],
  );
  return (rows[0]?.n ?? 0) > 0;
}

export interface PushTarget {
  relayId: string;
  endpoint: string;
  p256dh: string;
  auth: string;
}

/** Distinct endpoints that should get the account's EmailDelivery pushes. */
export async function targetsForAccount(db: Queryable, accountId: string): Promise<PushTarget[]> {
  const { rows } = await db.query<{ relay_id: string; endpoint: string; p256dh: string; auth: string }>(
    `SELECT DISTINCT ON (r.endpoint) r.relay_id, r.endpoint, r.p256dh, r.auth
       FROM push_jmap_sub s JOIN push_relay_sub r ON r.relay_id = s.relay_id
      WHERE s.account_id = $1 AND s.verified_at IS NOT NULL AND s.expires > now() AND r.gone_at IS NULL
        AND (s.types IS NULL OR 'EmailDelivery' = ANY (s.types))
      ORDER BY r.endpoint, r.updated_at DESC`,
    [accountId],
  );
  return rows.map((r) => ({ relayId: r.relay_id, endpoint: r.endpoint, p256dh: r.p256dh, auth: r.auth }));
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

/** Accounts the reconciler looks at: anything with an upstream row in use, active subs, or (always-mode) a password. */
export async function accountsToReconcile(db: Queryable, always: boolean): Promise<string[]> {
  const { rows } = await db.query<{ id: string }>(
    `SELECT account_id AS id FROM push_upstream WHERE status <> 'none'
     UNION SELECT account_id FROM push_jmap_sub WHERE verified_at IS NOT NULL AND expires > now()
     UNION SELECT id FROM account WHERE $1::boolean AND gandi_secret IS NOT NULL`,
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

/** Housekeeping: old dedupe rows, long-expired emulated subs, dead or orphaned relay records. */
export async function garbageCollect(db: Queryable): Promise<void> {
  await db.query("DELETE FROM push_notified WHERE notified_at < now() - interval '7 days'");
  await db.query("DELETE FROM push_jmap_sub WHERE expires < now() - interval '7 days'");
  await db.query(
    `DELETE FROM push_relay_sub r
      WHERE (r.gone_at IS NOT NULL AND r.gone_at < now() - interval '30 days')
         OR (r.updated_at < now() - interval '30 days'
             AND NOT EXISTS (SELECT 1 FROM push_jmap_sub s WHERE s.relay_id = r.relay_id))`,
  );
}
