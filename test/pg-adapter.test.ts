import { PGlite } from "@electric-sql/pglite";
import { PGLiteSocketServer } from "@electric-sql/pglite-socket";
import { createServer } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { upsertAccount, getAccountByEmail } from "../src/core/accounts.js";
import { migrate } from "../src/db/migrate.js";
import { createPgDb } from "../src/db/pool.js";
import type { Db } from "../src/db/pool.js";
import { makeTestConfig } from "./helpers.js";

// Exercises the node-postgres adapter (src/db/pool.ts) over the wire, against
// PGlite served on a local TCP port, so it needs no real Postgres.
let pglite: PGlite;
let server: PGLiteSocketServer;
let db: Db;

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => resolve(port));
    });
    s.on("error", reject);
  });
}

beforeAll(async () => {
  pglite = new PGlite();
  await pglite.waitReady;
  const port = await freePort();
  server = new PGLiteSocketServer({ db: pglite, port, host: "127.0.0.1" });
  await server.start();
  // PGlite serves one connection at a time, hence max: 1.
  db = createPgDb(`postgres://postgres:postgres@127.0.0.1:${port}/postgres?sslmode=disable`, { max: 1 });
});
afterAll(async () => {
  await db?.close();
  await server?.stop();
  await pglite?.close();
});

describe("node-postgres adapter", () => {
  it("runs migrations and the accounts repository through pg", async () => {
    expect((await migrate(db))[0]).toBe("000_core.sql");
    expect(await migrate(db)).toEqual([]);
    const ctx = { config: makeTestConfig(), db };
    const a = await upsertAccount(ctx, { email: "Wire@Example.org" });
    expect(await getAccountByEmail(ctx, "wire@example.org")).toEqual(a);
  });

  it("transaction commits on return and rolls back on throw", async () => {
    await db.exec("CREATE TABLE tx_t (v int)");
    await db.transaction(async (tx) => {
      await tx.query("INSERT INTO tx_t VALUES ($1)", [1]);
    });
    await expect(
      db.transaction(async (tx) => {
        await tx.query("INSERT INTO tx_t VALUES ($1)", [2]);
        throw new Error("abort");
      }),
    ).rejects.toThrow("abort");
    expect((await db.query<{ v: number }>("SELECT v FROM tx_t")).rows).toEqual([{ v: 1 }]);
  });
});
