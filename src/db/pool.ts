import pg from "pg";

export interface QueryResult<R> {
  rows: R[];
  rowCount: number | null;
}

/** The query surface shared by `Db` and a transaction handle. */
export interface Queryable {
  query<R = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<QueryResult<R>>;
  /** Run one or more statements without parameters (e.g. a migration file). */
  exec(sql: string): Promise<void>;
}

/** Database handle used everywhere. Implemented for node-postgres and PGlite. */
export interface Db extends Queryable {
  /** Run `fn` in a transaction: commit on return, roll back on throw. */
  transaction<T>(fn: (tx: Queryable) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

function queryable(q: pg.Pool | pg.PoolClient): Queryable {
  return {
    async query<R>(sql: string, params?: unknown[]) {
      const res = await q.query(sql, params as unknown[] | undefined);
      return { rows: res.rows as R[], rowCount: res.rowCount };
    },
    async exec(sql: string) {
      await q.query(sql);
    },
  };
}

/** node-postgres backed `Db`. SSL etc. are configured through the connection string. */
export function createPgDb(
  databaseUrl: string,
  opts: { max?: number; onError?: (err: Error) => void } = {},
): Db {
  const pool = new pg.Pool({ connectionString: databaseUrl, max: opts.max ?? 10 });
  // An idle client erroring must not crash the process.
  pool.on("error", (err) => opts.onError?.(err));
  return {
    ...queryable(pool),
    async transaction<T>(fn: (tx: Queryable) => Promise<T>): Promise<T> {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const out = await fn(queryable(client));
        await client.query("COMMIT");
        return out;
      } catch (err) {
        try {
          await client.query("ROLLBACK");
        } catch {
          // connection is gone; the original error is what matters
        }
        throw err;
      } finally {
        client.release();
      }
    },
    close: () => pool.end(),
  };
}
