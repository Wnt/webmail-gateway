import { loadConfig } from "./config.js";
import { migrate } from "./db/migrate.js";
import { createPgDb } from "./db/pool.js";
import { httpFetch } from "./core/http-fetch.js";
import { closeUpstream } from "./core/upstream/index.js";
import { authCliCommands } from "./features/auth/index.js";
import { jmapCliCommands } from "./features/jmap/index.js";
import { pushCliCommands } from "./features/push/index.js";
import { createLogger } from "./log.js";
import type { AppContext, CliCommand } from "./types.js";

const commands: Record<string, CliCommand> = {
  migrate: async (_args, ctx) => {
    const applied = await migrate(ctx.db);
    console.log(applied.length ? `applied: ${applied.join(", ")}` : "up to date");
  },
  ...jmapCliCommands,
  ...authCliCommands,
  ...pushCliCommands,
};

const [name, ...args] = process.argv.slice(2);
const cmd = name ? commands[name] : undefined;
if (!cmd) {
  console.error(`usage: npm run cli -- <command> [args]\ncommands: ${Object.keys(commands).sort().join(", ")}`);
  process.exit(name ? 2 : 1);
}

const config = loadConfig();
const log = createLogger(config);
const db = createPgDb(config.databaseUrl);
const ctx: AppContext = { config, db, log, fetch: httpFetch };
let code = 0;
try {
  code = (await cmd(args, ctx)) ?? 0;
} catch (err) {
  console.error(err instanceof Error ? err.message : err);
  code = 1;
} finally {
  await closeUpstream(ctx);
  await db.close();
}
process.exit(code);
