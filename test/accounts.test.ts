import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  getAccountByEmail,
  getAccountById,
  getGandiPassword,
  setGandiPassword,
  upsertAccount,
} from "../src/core/accounts.js";
import type { AppContext } from "../src/types.js";
import { makeTestContext } from "./helpers.js";

let ctx: AppContext;
beforeAll(async () => {
  ctx = await makeTestContext();
});
afterAll(() => ctx.db.close());

describe("accounts repository", () => {
  it("upserts, lower-cases the email and defaults the legacy slug", async () => {
    const a = await upsertAccount(ctx, { email: "  Owner@Example.TEST " });
    expect(a.email).toBe("owner@example.test");
    expect(a.legacySlug).toBe("gandi:owner@example.test");
    expect(a.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(a.createdAt).toBeInstanceOf(Date);
  });

  it("is idempotent and keeps the slug unless one is given", async () => {
    const a = await upsertAccount(ctx, { email: "idem@example.org", legacySlug: "custom:idem" });
    const b = await upsertAccount(ctx, { email: "IDEM@example.org" });
    expect(b.id).toBe(a.id);
    expect(b.legacySlug).toBe("custom:idem");
    const c = await upsertAccount(ctx, { email: "idem@example.org", legacySlug: "other:idem" });
    expect(c.id).toBe(a.id);
    expect(c.legacySlug).toBe("other:idem");
  });

  it("looks up by email (any case) and by id; unknown or malformed is null", async () => {
    const a = await upsertAccount(ctx, { email: "lookup@example.org" });
    expect(await getAccountByEmail(ctx, "LOOKUP@example.org")).toEqual(a);
    expect(await getAccountById(ctx, a.id)).toEqual(a);
    expect(await getAccountByEmail(ctx, "nobody@example.org")).toBeNull();
    expect(await getAccountById(ctx, randomUUID())).toBeNull();
    expect(await getAccountById(ctx, "not-a-uuid")).toBeNull();
  });

  it("rejects an email without @", async () => {
    await expect(upsertAccount(ctx, { email: "nope" })).rejects.toThrow("invalid email");
  });

  it("stores the Gandi password sealed and reads it back", async () => {
    const a = await upsertAccount(ctx, { email: "pw@example.org" });
    expect(await getGandiPassword(ctx, a.id)).toBeNull();
    await setGandiPassword(ctx, a.id, "pässi:wörd");
    expect(await getGandiPassword(ctx, a.id)).toBe("pässi:wörd");
    await setGandiPassword(ctx, a.id, "second");
    expect(await getGandiPassword(ctx, a.id)).toBe("second");

    const { rows } = await ctx.db.query<{ gandi_secret: Uint8Array }>(
      "SELECT gandi_secret FROM account WHERE id = $1",
      [a.id],
    );
    expect(Buffer.from(rows[0]!.gandi_secret).includes(Buffer.from("second"))).toBe(false);
  });

  it("binds the sealed password to its row", async () => {
    const a = await upsertAccount(ctx, { email: "bind-a@example.org" });
    const b = await upsertAccount(ctx, { email: "bind-b@example.org" });
    await setGandiPassword(ctx, a.id, "pw-a");
    await ctx.db.query("UPDATE account SET gandi_secret = (SELECT gandi_secret FROM account WHERE id = $1) WHERE id = $2", [a.id, b.id]);
    await expect(getGandiPassword(ctx, b.id)).rejects.toThrow();
  });

  it("setGandiPassword fails for a missing account; getGandiPassword is null", async () => {
    const id = randomUUID();
    await expect(setGandiPassword(ctx, id, "x")).rejects.toThrow("no such account");
    expect(await getGandiPassword(ctx, id)).toBeNull();
  });

  it("enforces lower-case emails at the database level", async () => {
    await expect(ctx.db.query("INSERT INTO account (email, legacy_slug) VALUES ('Up@Case.org', 's')")).rejects.toThrow();
  });
});
