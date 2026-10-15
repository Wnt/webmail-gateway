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
