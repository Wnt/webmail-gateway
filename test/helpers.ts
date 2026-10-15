import { randomBytes } from "node:crypto";
import { loadConfig, type Config } from "../src/config.js";
import { migrate } from "../src/db/migrate.js";
import { createPgliteDb } from "../src/db/pglite.js";
import type { Db } from "../src/db/pool.js";
import type { AppContext } from "../src/types.js";
import { pino } from "pino";

/** A valid `Config` with random keys; `env` overrides/extends the environment (feature keys, LEGACY_PROXY_URL, ...). */
export function makeTestConfig(env: Record<string, string> = {}): Config {
  return loadConfig({
    DATABASE_URL: "postgres://unused/unused",
    GATEWAY_ENC_KEY: randomBytes(32).toString("base64"),
    LEGACY_SESSION_HMAC_KEY: randomBytes(32).toString("base64"),
    LEGACY_PROXY_URL: "http://127.0.0.1:1",
    PUBLIC_BASE_URL: "https://mail.example.test",
    ALLOWED_EMAILS: "alice@example.test, bob@example.test",
    LOG_LEVEL: "silent",
    ...env,
  });
}

/** Fresh in-memory Postgres with every migration applied. */
export async function makeTestDb(): Promise<Db> {
  const db = await createPgliteDb();
  await migrate(db);
  return db;
}

/** Config + migrated PGlite + silent logger, ready to pass to core functions, plugins or `buildApp`. */
export async function makeTestContext(env: Record<string, string> = {}): Promise<AppContext> {
  return { config: makeTestConfig(env), db: await makeTestDb(), log: pino({ level: "silent" }), fetch };
}

/** A bare passkey row (no key material) for tests that need one to hang sessions, codes or grants on. */
export async function addTestPasskey(ctx: Pick<AppContext, "db">, accountId: string, id: Buffer = randomBytes(16)): Promise<Buffer> {
  await ctx.db.query("INSERT INTO passkey (id, account_id, public_key, name, created_at) VALUES ($1, $2, $3, 'test', now())", [
    id,
    accountId,
    Buffer.from("k"),
  ]);
  return id;
}
