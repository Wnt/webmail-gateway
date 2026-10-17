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

/** A live LISTEN (see `Db.listen`). */
export interface Listener {
  /** A round trip on the listening connection; rejects when it is dead. */
  ping(): Promise<void>;
  close(): Promise<void>;
}

/** Database handle used everywhere. Implemented for node-postgres and PGlite. */
export interface Db extends Queryable {
  /** Run `fn` in a transaction: commit on return, roll back on throw. */
  transaction<T>(fn: (tx: Queryable) => Promise<T>): Promise<T>;
  close(): Promise<void>;
  /**
   * LISTEN on `channel` over a dedicated connection: `onNotify` gets each
   * payload, `onLost` is called once if the connection fails (the caller
   * reconnects with a new `listen`). Rejects when it cannot connect.
   */
  listen?(channel: string, onNotify: (payload: string) => void, onLost: (err: Error) => void): Promise<Listener>;
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
    async listen(channel, onNotify, onLost): Promise<Listener> {
      const client = new pg.Client({ connectionString: databaseUrl, keepAlive: true, keepAliveInitialDelayMillis: 10_000 });
      let done = false;
      const lost = (err: Error) => {
        if (done) return;
        done = true;
        client.end().catch(() => {});
        onLost(err);
      };
      client.on("error", lost);
      client.on("end", () => lost(new Error("listen connection ended")));
      client.on("notification", (m) => {
        if (m.channel === channel) onNotify(m.payload ?? "");
      });
      try {
        await client.connect();
        await client.query(`LISTEN ${pg.escapeIdentifier(channel)}`);
      } catch (err) {
        done = true;
        await client.end().catch(() => {});
        throw err;
      }
      return {
        ping: async () => {
          await client.query("SELECT 1");
        },
        close: async () => {
          done = true;
          await client.end().catch(() => {});
        },
      };
    },
  };
}
