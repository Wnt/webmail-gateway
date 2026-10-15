import { PGlite } from "@electric-sql/pglite";
import type { Db, Queryable } from "./pool.js";

function wrap(q: Pick<PGlite, "query" | "exec">): Queryable {
  return {
    async query<R>(sql: string, params?: unknown[]) {
      const res = await q.query<R>(sql, params as unknown[] | undefined);
      return { rows: res.rows, rowCount: res.affectedRows ?? res.rows.length };
    },
    async exec(sql: string) {
      await q.exec(sql);
    },
  };
}

/**
 * In-process Postgres (WASM) for tests: no Docker, no shared state between
 * agents. Not for production; `src/server.ts` never imports this.
 */
export async function createPgliteDb(): Promise<Db> {
  const pg = new PGlite();
  await pg.waitReady;
  return {
    ...wrap(pg),
    transaction: (fn) => pg.transaction((tx) => fn(wrap(tx))),
    close: () => pg.close(),
  };
}
