import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
import { migrate } from "./db/migrate.js";
import { createPgDb } from "./db/pool.js";
import { createLogger } from "./log.js";

const config = loadConfig();
const log = createLogger(config);
const db = createPgDb(config.databaseUrl, { onError: (err) => log.error({ err }, "idle database client error") });

if (config.migrateOnStart) {
  const applied = await migrate(db);
  log.info({ applied }, "migrations up to date");
}

const app = await buildApp(config, { db, log });

let closing = false;
const shutdown = async (signal: string) => {
  if (closing) return;
  closing = true;
  log.info({ signal }, "shutting down");
  try {
    await app.close();
    await db.close();
    process.exit(0);
  } catch (err) {
    log.error({ err }, "error during shutdown");
    process.exit(1);
  }
};
process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));

await app.listen({ port: config.port, host: config.host });
