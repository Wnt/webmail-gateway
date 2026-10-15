import { hkdfSync } from "node:crypto";
import { open, seal } from "./crypto.js";
import type { CoreContext } from "../types.js";

/** An account row. The sealed Gandi password is never part of this object. */
export interface Account {
  id: string;
  /** Lower-cased. */
  email: string;
  /** legacy-proxy account slug, `<provider>:<username>` (default `gandi:<email>`). */
  legacySlug: string;
  createdAt: Date;
}

type Ctx = Pick<CoreContext, "config" | "db">;

interface Row {
  id: string;
  email: string;
  legacy_slug: string;
  created_at: Date;
}

const COLS = "id, email, legacy_slug, created_at";

const toAccount = (r: Row): Account => ({
  id: r.id,
  email: r.email,
  legacySlug: r.legacy_slug,
  createdAt: r.created_at,
});

export const normalizeEmail = (email: string): string => email.trim().toLowerCase();

export async function getAccountByEmail(ctx: Ctx, email: string): Promise<Account | null> {
  const { rows } = await ctx.db.query<Row>(`SELECT ${COLS} FROM account WHERE email = $1`, [normalizeEmail(email)]);
  return rows[0] ? toAccount(rows[0]) : null;
}

export async function getAccountById(ctx: Ctx, id: string): Promise<Account | null> {
  // Not a uuid -> no such account, rather than a Postgres cast error.
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return null;
  const { rows } = await ctx.db.query<Row>(`SELECT ${COLS} FROM account WHERE id = $1`, [id]);
  return rows[0] ? toAccount(rows[0]) : null;
}

/**
 * Create the account for `email`, or return the existing one. `legacySlug`
 * defaults to `gandi:<email>` on insert; when given explicitly it also
 * overwrites the stored slug of an existing account.
 */
export async function upsertAccount(
  ctx: Ctx,
  input: { email: string; legacySlug?: string },
): Promise<Account> {
  const email = normalizeEmail(input.email);
  if (!email.includes("@")) throw new Error("invalid email");
  const { rows } = await ctx.db.query<Row>(
    `INSERT INTO account (email, legacy_slug) VALUES ($1, $2)
     ON CONFLICT (email) DO UPDATE
       SET legacy_slug = CASE WHEN $3::boolean THEN EXCLUDED.legacy_slug ELSE account.legacy_slug END
     RETURNING ${COLS}`,
    [email, input.legacySlug ?? `gandi:${email}`, input.legacySlug !== undefined],
  );
  return toAccount(rows[0]!);
}

/** Seal and store the Gandi password. The account id is bound as AAD, so a sealed value cannot be moved between rows. */
export async function setGandiPassword(ctx: Ctx, accountId: string, password: string): Promise<void> {
  const sealed = seal(password, ctx.config.encKey, accountId);
  const res = await ctx.db.query("UPDATE account SET gandi_secret = $2 WHERE id = $1", [accountId, sealed]);
  if (!res.rowCount) throw new Error("no such account");
}

/** Decrypt the stored Gandi password, or null if the account has none (or does not exist). */
export async function getGandiPassword(ctx: Ctx, accountId: string): Promise<string | null> {
  const { rows } = await ctx.db.query<{ gandi_secret: Uint8Array | null }>(
    "SELECT gandi_secret FROM account WHERE id = $1",
    [accountId],
  );
  const secret = rows[0]?.gandi_secret;
  if (!secret) return null;
  return open(secret, ctx.config.encKey, accountId).toString("utf8");
}

/** A native JMAP upstream credential (src/core/upstream/jmap.ts). Never logged or returned to clients. */
export interface UpstreamCredential {
  /** How it is sent: `Authorization: Bearer <secret>` or `Basic <username:secret>`. */
  auth: "bearer" | "basic";
  /** The upstream login name for Basic. */
  username: string;
  secret: string;
}

// A6: a purpose key derived from GATEWAY_ENC_KEY, so these values cannot be opened as anything else.
const upstreamKeys = new WeakMap<Buffer, Buffer>();
function upstreamKey(encKey: Buffer): Buffer {
  let k = upstreamKeys.get(encKey);
  if (!k) {
    k = Buffer.from(hkdfSync("sha256", encKey, Buffer.alloc(0), "webmail-gateway/upstream-credential", 32));
    upstreamKeys.set(encKey, k);
  }
  return k;
}

/** Seal and store the account's upstream credential (replacing any previous one). */
export async function setUpstreamCredential(ctx: Ctx, accountId: string, cred: UpstreamCredential): Promise<void> {
  const sealed = seal(JSON.stringify({ v: 1, ...cred }), upstreamKey(ctx.config.encKey), accountId);
  const res = await ctx.db.query("UPDATE account SET upstream_secret = $2 WHERE id = $1", [accountId, sealed]);
  if (!res.rowCount) throw new Error("no such account");
}

/** The account's upstream credential, or null when none is stored (or the account does not exist). */
export async function getUpstreamCredential(ctx: Ctx, accountId: string): Promise<UpstreamCredential | null> {
  const { rows } = await ctx.db.query<{ upstream_secret: Uint8Array | null }>(
    "SELECT upstream_secret FROM account WHERE id = $1",
    [accountId],
  );
  const sealed = rows[0]?.upstream_secret;
  if (!sealed) return null;
  const v = JSON.parse(open(sealed, upstreamKey(ctx.config.encKey), accountId).toString("utf8")) as Partial<UpstreamCredential>;
  if ((v.auth !== "bearer" && v.auth !== "basic") || typeof v.secret !== "string" || typeof v.username !== "string") return null;
  return { auth: v.auth, username: v.username, secret: v.secret };
}
