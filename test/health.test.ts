import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import type { Db } from "../src/db/pool.js";
import { makeTestConfig, makeTestDb } from "./helpers.js";

let db: Db;
let app: FastifyInstance;
beforeAll(async () => {
  db = await makeTestDb();
  app = await buildApp(makeTestConfig(), { db });
});
afterAll(async () => {
  await app.close();
  await db.close();
});

describe("health endpoints", () => {
  it("/healthz is 200", async () => {
    const res = await app.inject("/healthz");
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: "ok" });
  });

  it("/readyz is 200 while the database answers", async () => {
    const res = await app.inject("/readyz");
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: "ready" });
  });

  it("/readyz is 503 when the database fails, /healthz stays 200", async () => {
    const broken: Db = {
      ...db,
      query: async () => {
        throw new Error("connection refused");
      },
    };
    const bad = await buildApp(makeTestConfig(), { db: broken });
    const ready = await bad.inject("/readyz");
    expect(ready.statusCode).toBe(503);
    expect(ready.json()).toEqual({ status: "unavailable" });
    expect(ready.body).not.toContain("refused");
    expect((await bad.inject("/healthz")).statusCode).toBe(200);
    await bad.close();
  });

  it("registers the push routes (503 without VAPID keys)", async () => {
    expect((await app.inject("/relay/api/push/vapid-public-key")).statusCode).toBe(503);
  });

  it("jmap routes exist and require authentication", async () => {
    for (const url of ["/jmap/session", "/.well-known/jmap"]) {
      expect((await app.inject(url)).statusCode).toBe(401);
    }
  });
});
