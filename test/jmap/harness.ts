// Shared setup for the jmap integration tests: a fake legacy-proxy, a
// migrated PGlite, and a listening gateway with a log capture.
import { randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { pino } from "pino";
import { buildApp } from "../../src/app.js";
import type { Config } from "../../src/config.js";
import type { Db } from "../../src/db/pool.js";
import type { AppContext } from "../../src/types.js";
import { makeTestConfig } from "../helpers.js";
import { startFakeLegacyJmap, type FakeLegacyJmap } from "./fake-legacy-jmap.js";

export interface Gateway {
  app: FastifyInstance;
  base: string;
  config: Config;
  ctx: AppContext;
  logs: string[];
  close(): Promise<void>;
}

export const hmacKey = randomBytes(32);

export function startFake(): Promise<FakeLegacyJmap> {
  return startFakeLegacyJmap(hmacKey);
}

export async function startGateway(db: Db, legacyUrl: string, env: Record<string, string> = {}): Promise<Gateway> {
  const config = makeTestConfig({
    LEGACY_PROXY_URL: legacyUrl,
    LEGACY_SESSION_HMAC_KEY: hmacKey.toString("base64"),
    PUBLIC_BASE_URL: "https://mail.example.test",
    ...env,
  });
  const logs: string[] = [];
  const log = pino({ level: "info" }, { write: (s: string) => void logs.push(s) }) as unknown as AppContext["log"];
  const app = await buildApp(config, { db, log });
  await app.listen({ port: 0, host: "127.0.0.1" });
  const addr = app.server.address();
  const base = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
  const ctx: AppContext = { config, db, log, fetch };
  return { app, base, config, ctx, logs, close: () => app.close() };
}

export const basic = (user: string, pass: string) => `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}`;

export async function resetDb(db: Db): Promise<void> {
  await db.query("TRUNCATE account CASCADE");
}
