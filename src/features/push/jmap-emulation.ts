import { randomBytes, timingSafeEqual } from "node:crypto";
import type { Principal } from "../../core/auth-context.js";
import { JmapMethodError } from "../../core/hooks.js";
import type { AppContext } from "../../types.js";
import type { PushStats } from "./stats.js";
import {
  deleteJmapSub,
  insertJmapSub,
  listJmapSubs,
  setRelayVerificationCode,
  updateJmapSub,
  type JmapSub,
} from "./store.js";

/**
 * RFC 8620 section 7.2 PushSubscription/get and /set, answered by the gateway
 * itself (design/push.md section 3). Subscriptions belong to the principal's
 * gateway account. The only URLs accepted are our own relay's
 * `<PUBLIC_BASE_URL>/relay/api/push/jmap/<relayId>`; "delivering" the
 * PushVerification means writing the code onto that relay record, where
 * Bulwark polls for it.
 */

export const MAX_SUBS_PER_ACCOUNT = 20;
export const MAX_EXPIRES_MS = 90 * 86_400_000;
const TYPE_RE = /^[A-Za-z][A-Za-z0-9]{0,63}$/;
const CREATE_PROPS = new Set(["deviceClientId", "url", "types", "expires", "keys", "verificationCode"]);
const UPDATE_PROPS = new Set(["verificationCode", "expires", "types"]);
const GET_PROPS = ["id", "deviceClientId", "verificationCode", "expires", "types"] as const;

interface SetError {
  type: string;
  description?: string;
  properties?: string[];
}

const utcDate = (d: Date): string => d.toISOString().replace(/\.\d{3}Z$/, "Z");
const newId = (): string => randomBytes(16).toString("base64url");

function invalid(prop: string, description: string): { error: SetError } {
  return { error: { type: "invalidProperties", properties: [prop], description } };
}

export interface EmulationDeps {
  ctx: AppContext;
  stats: PushStats;
  /** Called after a change that can turn the account's upstream subscription on or off. */
  onChange: (accountId: string) => void;
}

/** `relayId` from one of our relay JMAP URLs, or null. */
export function relayIdFromUrl(url: string, publicBaseUrl: string): string | null {
  let u: URL;
  let base: URL;
  try {
    u = new URL(url);
    base = new URL(publicBaseUrl);
  } catch {
    return null;
  }
  if (u.origin !== base.origin || u.search || u.hash || u.username || u.password) return null;
  const m = /^\/relay\/api\/push\/jmap\/([A-Za-z0-9_-]{8,128})$/.exec(u.pathname);
  return m ? m[1]! : null;
}

function parseTypes(v: unknown): { types: string[] | null } | { error: SetError } {
  if (v === null || v === undefined) return { types: null };
  if (!Array.isArray(v) || v.length > 32 || !v.every((t) => typeof t === "string" && TYPE_RE.test(t))) {
    return invalid("types", "types must be null or a list of type names");
  }
  return { types: [...new Set(v as string[])] };
}

/** Clamp a requested expiry into [now, now + 90 days]. */
function parseExpires(v: unknown, now: number): { expires: Date; clamped: boolean } | { error: SetError } {
  if (v === null || v === undefined) return { expires: new Date(now + MAX_EXPIRES_MS), clamped: true };
  if (typeof v !== "string" || Number.isNaN(Date.parse(v))) return invalid("expires", "expires must be a UTCDate");
  const asked = Date.parse(v);
  const ms = Math.max(now, Math.min(asked, now + MAX_EXPIRES_MS));
  return { expires: new Date(Math.floor(ms / 1000) * 1000), clamped: Math.floor(asked / 1000) !== Math.floor(ms / 1000) };
}

function codesEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

function project(s: JmapSub, props: readonly string[]): Record<string, unknown> {
  const full: Record<string, unknown> = {
    id: s.id,
    deviceClientId: s.deviceClientId,
    verificationCode: s.verifiedAt ? s.verificationCode : null,
    expires: utcDate(s.expires),
    types: s.types,
  };
  const out: Record<string, unknown> = { id: s.id };
  for (const p of props) if (p in full) out[p] = full[p];
  return out;
}

export function createPushSubscriptionHandler(deps: EmulationDeps) {
  const { ctx, stats } = deps;
  const db = ctx.db;

  async function get(accountId: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
    const { ids, properties } = args;
    if (ids !== null && ids !== undefined && !(Array.isArray(ids) && ids.every((i) => typeof i === "string"))) {
      throw new JmapMethodError("invalidArguments", "ids must be null or a list of strings");
    }
    let props: readonly string[] = GET_PROPS;
    if (properties !== null && properties !== undefined) {
      if (!Array.isArray(properties) || !properties.every((p) => typeof p === "string")) {
        throw new JmapMethodError("invalidArguments", "properties must be null or a list of strings");
      }
      props = properties as string[];
    }
    const all = await listJmapSubs(db, accountId);
    if (ids === null || ids === undefined) return { list: all.map((s) => project(s, props)), notFound: [] };
    const byId = new Map(all.map((s) => [s.id, s]));
    const list: Record<string, unknown>[] = [];
    const notFound: string[] = [];
    for (const id of ids as string[]) {
      const s = byId.get(id);
      if (s) list.push(project(s, props));
      else notFound.push(id);
    }
    return { list, notFound };
  }

  async function create(accountId: string, raw: unknown, existing: number): Promise<Record<string, unknown> | { error: SetError }> {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { error: { type: "invalidProperties", description: "not an object" } };
    const o = raw as Record<string, unknown>;
    for (const k of Object.keys(o)) if (!CREATE_PROPS.has(k)) return invalid(k, `unsupported property ${k}`);
    if (existing >= MAX_SUBS_PER_ACCOUNT) {
      return { error: { type: "overQuota", description: "Too many push subscriptions for this account" } };
    }
    if (typeof o.deviceClientId !== "string" || o.deviceClientId.length < 1 || o.deviceClientId.length > 255) {
      return invalid("deviceClientId", "deviceClientId must be a string of 1-255 characters");
    }
    if (o.verificationCode !== undefined && o.verificationCode !== null) {
      return invalid("verificationCode", "verificationCode must be null on create");
    }
    if (o.keys !== undefined && o.keys !== null && typeof o.keys !== "object") return invalid("keys", "keys must be an object");
    const relayId = typeof o.url === "string" ? relayIdFromUrl(o.url, ctx.config.publicBaseUrl) : null;
    if (!relayId) return invalid("url", "url must be this server's push relay");
    const t = parseTypes(o.types);
    if ("error" in t) return t;
    const e = parseExpires(o.expires, Date.now());
    if ("error" in e) return e;

    const id = newId();
    const code = randomBytes(24).toString("base64url");
    await insertJmapSub(db, {
      id,
      accountId,
      deviceClientId: o.deviceClientId,
      relayId,
      url: o.url as string,
      types: t.types,
      expires: e.expires,
      verificationCode: code,
    });
    // The emulated PushVerification "POST" to the relay URL.
    const delivered = await setRelayVerificationCode(db, relayId, code);
    stats.inc("jmap_sub_created");
    ctx.log.info({ accountId, relay: relayId.slice(0, 6), delivered }, "push: emulated subscription created");
    return { id, expires: utcDate(e.expires) };
  }

  async function update(
    accountId: string,
    sub: JmapSub,
    raw: unknown,
  ): Promise<{ result: Record<string, unknown> | null; changed: boolean } | { error: SetError }> {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { error: { type: "invalidPatch" } };
    const o = raw as Record<string, unknown>;
    for (const k of Object.keys(o)) if (!UPDATE_PROPS.has(k)) return invalid(k, `${k} cannot be changed`);
    const patch: { types?: string[] | null; expires?: Date; verified?: boolean } = {};
    let result: Record<string, unknown> | null = null;
    if ("verificationCode" in o) {
      const code = o.verificationCode;
      if (typeof code !== "string" || !codesEqual(code, sub.verificationCode)) {
        stats.inc("jmap_sub_verify_failed");
        return invalid("verificationCode", "incorrect verification code");
      }
      if (!sub.verifiedAt) patch.verified = true;
    }
    if ("types" in o) {
      const t = parseTypes(o.types);
      if ("error" in t) return t;
      patch.types = t.types;
    }
    if ("expires" in o) {
      if (o.expires === null) return invalid("expires", "expires must be a UTCDate");
      const e = parseExpires(o.expires, Date.now());
      if ("error" in e) return e;
      patch.expires = e.expires;
      if (e.clamped) result = { expires: utcDate(e.expires) };
    }
    await updateJmapSub(db, sub.id, accountId, patch);
    if (patch.verified) {
      stats.inc("jmap_sub_verified");
      ctx.log.info({ accountId, relay: sub.relayId.slice(0, 6) }, "push: emulated subscription verified");
    }
    return { result, changed: Boolean(patch.verified || patch.expires) };
  }

  async function set(accountId: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
    const { create: c, update: u, destroy: d } = args;
    const isMap = (v: unknown) => v === null || v === undefined || (typeof v === "object" && !Array.isArray(v));
    if (!isMap(c) || !isMap(u)) throw new JmapMethodError("invalidArguments", "create and update must be maps");
    if (d !== null && d !== undefined && !(Array.isArray(d) && d.every((x) => typeof x === "string"))) {
      throw new JmapMethodError("invalidArguments", "destroy must be a list of ids");
    }
    const created: Record<string, unknown> = {};
    const notCreated: Record<string, SetError> = {};
    const updated: Record<string, unknown> = {};
    const notUpdated: Record<string, SetError> = {};
    const destroyed: string[] = [];
    const notDestroyed: Record<string, SetError> = {};
    let changed = false;

    let count = (await listJmapSubs(db, accountId)).length;
    for (const [key, raw] of Object.entries((c as Record<string, unknown>) ?? {})) {
      const r = await create(accountId, raw, count);
      if ("error" in r) notCreated[key] = r.error as SetError;
      else {
        created[key] = r;
        count++;
      }
    }

    const subs = new Map((await listJmapSubs(db, accountId)).map((s) => [s.id, s]));
    for (const [id, raw] of Object.entries((u as Record<string, unknown>) ?? {})) {
      const sub = subs.get(id);
      if (!sub) {
        notUpdated[id] = { type: "notFound" };
        continue;
      }
      const r = await update(accountId, sub, raw);
      if ("error" in r) notUpdated[id] = r.error;
      else {
        updated[id] = r.result;
        changed ||= r.changed;
      }
    }

    for (const id of (d as string[] | null | undefined) ?? []) {
      if (await deleteJmapSub(db, id, accountId)) {
        destroyed.push(id);
        changed = true;
        stats.inc("jmap_sub_destroyed");
      } else notDestroyed[id] = { type: "notFound" };
    }

    if (changed) deps.onChange(accountId);
    const orNull = <T extends object>(o: T): T | null => (Object.keys(o).length ? o : null);
    return {
      created: orNull(created),
      notCreated: orNull(notCreated),
      updated: orNull(updated),
      notUpdated: orNull(notUpdated),
      destroyed: destroyed.length ? destroyed : null,
      notDestroyed: orNull(notDestroyed),
    };
  }

  return async function handlePushSubscription(
    principal: Principal,
    method: string,
    args: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    if (!principal.scopes.includes("mail")) throw new JmapMethodError("forbidden", "push needs the mail scope");
    if (method === "PushSubscription/get") return get(principal.accountId, args ?? {});
    if (method === "PushSubscription/set") return set(principal.accountId, args ?? {});
    throw new JmapMethodError("unknownMethod", `${method} is not supported`);
  };
}
