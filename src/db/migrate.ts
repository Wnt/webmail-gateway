import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Db } from "./pool.js";

/** `migrations/` at the package root; the same relative path works from src/db and dist/db. */
export const DEFAULT_MIGRATIONS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../migrations",
);

const FILE_RE = /^(\d{3})_[a-z0-9_]+\.sql$/;
/** Serialises migrators across replicas (pg_advisory_xact_lock). */
const LOCK_KEY = 7_283_501;

export interface MigrationFile {
  version: string;
  name: string;
  sql: string;
  checksum: string;
}

export async function readMigrations(dir: string = DEFAULT_MIGRATIONS_DIR): Promise<MigrationFile[]> {
  const names = (await readdir(dir)).filter((n) => FILE_RE.test(n)).sort();
  const seen = new Set<string>();
  const out: MigrationFile[] = [];
  for (const name of names) {
    const version = FILE_RE.exec(name)![1]!;
    if (seen.has(version)) throw new Error(`duplicate migration number ${version} (${name})`);
    seen.add(version);
    const sql = await readFile(path.join(dir, name), "utf8");
    out.push({ version, name, sql, checksum: createHash("sha256").update(sql).digest("hex") });
  }
  return out;
}

/**
 * Apply every migration in `dir` that is not yet recorded in `schema_migrations`,
 * in filename order, each in its own transaction. Numbers need not be contiguous
 * (ranges: 000-099 core, 100-199 auth, 200-299 push, 300-399 jmap) and a file
 * that appears later with a lower number than an applied one is still applied.
 * Editing an already-applied file is an error (checksum mismatch).
 * Returns the names applied by this call.
 */
export async function migrate(db: Db, dir: string = DEFAULT_MIGRATIONS_DIR): Promise<string[]> {
  const files = await readMigrations(dir);
  await db.transaction(async (tx) => {
    await tx.query("SELECT pg_advisory_xact_lock($1)", [LOCK_KEY]);
    await tx.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
      version text PRIMARY KEY,
      name text NOT NULL,
      checksum text NOT NULL,
      applied_at timestamptz NOT NULL DEFAULT now()
    )`);
  });

  const applied: string[] = [];
  for (const f of files) {
    await db.transaction(async (tx) => {
      await tx.query("SELECT pg_advisory_xact_lock($1)", [LOCK_KEY]);
      const { rows } = await tx.query<{ name: string; checksum: string }>(
        "SELECT name, checksum FROM schema_migrations WHERE version = $1",
        [f.version],
      );
      const existing = rows[0];
      if (existing) {
        if (existing.name !== f.name || existing.checksum !== f.checksum) {
          throw new Error(`migration ${f.version} was applied as ${existing.name} but the file changed (${f.name})`);
        }
        return;
      }
      await tx.exec(f.sql);
      await tx.query("INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)", [
        f.version,
        f.name,
        f.checksum,
      ]);
      applied.push(f.name);
    });
  }
  return applied;
}
