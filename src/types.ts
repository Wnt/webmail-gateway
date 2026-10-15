import type { FastifyBaseLogger, FastifyPluginAsync } from "fastify";
import type { Config } from "./config.js";
import type { Db } from "./db/pool.js";

/** Injected dependencies for `buildApp`. */
export interface AppDeps {
  db: Db;
  log?: FastifyBaseLogger;
  /** Override for outgoing HTTP (legacy-proxy calls). Defaults to global `fetch`. */
  fetch?: typeof fetch;
}

/**
 * The context handed to every feature plugin (as its plugin options) and to
 * every `src/core` function that needs state. `log` and `fetch` are always set.
 */
export interface AppContext {
  config: Config;
  db: Db;
  log: FastifyBaseLogger;
  fetch: typeof fetch;
}

/** What core functions need: pass a full `AppContext`, or just these. */
export type CoreContext = Pick<AppContext, "config" | "db"> & Partial<Pick<AppContext, "log" | "fetch">>;

/** A feature is a Fastify plugin whose options are the `AppContext`. */
export type FeaturePlugin = FastifyPluginAsync<AppContext>;

/** An admin command runnable through `npm run cli -- <name> [args]`. */
export type CliCommand = (
  args: string[],
  ctx: AppContext,
) => Promise<number | void>;
