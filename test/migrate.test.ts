import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DEFAULT_MIGRATIONS_DIR, migrate, readMigrations } from "../src/db/migrate.js";
import { createPgliteDb } from "../src/db/pglite.js";
import type { Db } from "../src/db/pool.js";

let db: Db;
let dir: string;
// One PGlite per file (booting it is slow); each test starts from an empty schema.
beforeAll(async () => {
  db = await createPgliteDb();
});
afterAll(() => db.close());
beforeEach(async () => {
  await db.exec("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
  dir = await mkdtemp(path.join(tmpdir(), "mig-"));
});
afterEach(() => rm(dir, { recursive: true, force: true }));

const put = (name: string, sql: string) => writeFile(path.join(dir, name), sql);
const applied = async () =>
  (await db.query<{ name: string }>("SELECT name FROM schema_migrations ORDER BY version")).rows.map((r) => r.name);

describe("migration runner", () => {
  it("applies the real migrations and records them", async () => {
    const names = await migrate(db);
    expect(names[0]).toBe("000_core.sql");
    expect(await applied()).toEqual(names);
    const { rows } = await db.query("SELECT 1 FROM information_schema.tables WHERE table_name = 'account'");
    expect(rows).toHaveLength(1);
  });

  it("is idempotent", async () => {
    await migrate(db);
    expect(await migrate(db)).toEqual([]);
  });

  it("applies in filename order and ignores non-matching files", async () => {
    await put("010_b.sql", "INSERT INTO t VALUES ('b');");
    await put("005_a.sql", "CREATE TABLE t (v text);");
    await put("README.md", "not a migration");
    await put("11_bad_name.sql", "SELECT broken;");
    expect(await migrate(db, dir)).toEqual(["005_a.sql", "010_b.sql"]);
    expect((await db.query("SELECT v FROM t")).rows).toEqual([{ v: "b" }]);
  });

  it("applies a later-added file with a lower number than one already applied", async () => {
    await put("000_a.sql", "CREATE TABLE a (x int);");
    await put("300_jmap.sql", "CREATE TABLE j (x int);");
    await migrate(db, dir);
    await put("200_push.sql", "CREATE TABLE p (x int);");
    expect(await migrate(db, dir)).toEqual(["200_push.sql"]);
  });

  it("rolls back a failing migration and stops", async () => {
    await put("000_ok.sql", "CREATE TABLE ok (x int);");
    await put("001_bad.sql", "CREATE TABLE half (x int); SELECT * FROM does_not_exist;");
    await put("002_never.sql", "CREATE TABLE never (x int);");
    await expect(migrate(db, dir)).rejects.toThrow();
    expect(await applied()).toEqual(["000_ok.sql"]);
    const { rows } = await db.query("SELECT table_name FROM information_schema.tables WHERE table_name IN ('half','never')");
    expect(rows).toHaveLength(0);
  });

  it("refuses when an applied file was edited", async () => {
    await put("000_a.sql", "CREATE TABLE a (x int);");
    await migrate(db, dir);
    await put("000_a.sql", "CREATE TABLE a (x int, y int);");
    await expect(migrate(db, dir)).rejects.toThrow(/changed/);
  });

  it("rejects duplicate numbers", async () => {
    await put("100_x.sql", "SELECT 1;");
    await put("100_y.sql", "SELECT 2;");
    await expect(readMigrations(dir)).rejects.toThrow(/duplicate/);
  });

  it("the shipped migrations directory has no duplicate numbers", async () => {
    const files = await readMigrations(DEFAULT_MIGRATIONS_DIR);
    expect(files.length).toBeGreaterThan(0);
  });
});
