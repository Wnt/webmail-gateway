import { copyFile, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, expect, it } from "vitest";
import { DEFAULT_MIGRATIONS_DIR, migrate } from "../../src/db/migrate.js";
import { createPgliteDb } from "../../src/db/pglite.js";
import { targetsForAccount } from "../../src/features/push/store.js";

// gateway-data-1 across the upgrade: revocations recorded before migrations
// 101/202 still end the push subscriptions made before them.

const db = await createPgliteDb();
const dir = await mkdtemp(path.join(tmpdir(), "gw-mig-"));
afterAll(async () => {
  await db.close();
  await rm(dir, { recursive: true, force: true });
});

it("carries revocations made before the upgrade over to subscriptions without a grant", async () => {
  // The schema as it was before this change.
  for (const f of await readdir(DEFAULT_MIGRATIONS_DIR)) {
    if (!/^(101|202)_/.test(f)) await copyFile(path.join(DEFAULT_MIGRATIONS_DIR, f), path.join(dir, f));
  }
  await migrate(db, dir);
  const account = async (email: string) =>
    (await db.query<{ id: string }>("INSERT INTO account (email, legacy_slug) VALUES ($1, $1) RETURNING id", [email])).rows[0]!.id;
  const revokedGrant = await account("revoked@example.test");
  const reset = await account("reset@example.test");
  const untouched = await account("untouched@example.test");
  const sub = async (accountId: string, relayId: string, createdAt: string) => {
    await db.query("INSERT INTO push_relay_sub (relay_id, endpoint, p256dh, auth) VALUES ($1, $2, 'k', 'a')", [
      relayId,
      `https://push.example.test/push/${relayId}`,
    ]);
    await db.query(
      `INSERT INTO push_jmap_sub (id, account_id, device_client_id, relay_id, url, expires, verification_code, verified_at, created_at)
       VALUES ($1, $2, $1, $1, 'u', now() + interval '30 days', 'c', now(), $3)`,
      [relayId, accountId, createdAt],
    );
  };
  // A Bulwark sign-out revoked the grant after this device subscribed.
  await sub(revokedGrant, "before-signout", "2026-10-01T00:00:00Z");
  await sub(revokedGrant, "after-signout", "2026-10-03T00:00:00Z");
  await db.query(
    `INSERT INTO oauth_grant (client_id, account_id, scopes, created_at, expires_at, revoked_at, revoked_reason)
     VALUES ('bulwark', $1, 'mail', '2026-09-01', '2027-03-01', '2026-10-02', 'client_revoke'),
            ('bulwark', $1, 'mail', '2026-09-01', '2026-09-02', '2026-10-05', 'expired')`,
    [revokedGrant],
  );
  // A reset with no grant left to revoke: only the audit log knows.
  await sub(reset, "before-reset", "2026-10-01T00:00:00Z");
  await db.query("INSERT INTO auth_audit (at, event, account_id, details) VALUES ('2026-10-02', 'bootstrap', $1, '{\"reset\":true}')", [reset]);
  await sub(untouched, "never-revoked", "2026-10-01T00:00:00Z");

  await migrate(db);
  const relays = async (id: string) => (await targetsForAccount(db, id)).map((t) => t.relayId);
  expect(await relays(revokedGrant)).toEqual(["after-signout"]);
  expect(await relays(reset)).toEqual([]);
  expect(await relays(untouched)).toEqual(["never-revoked"]);
});
