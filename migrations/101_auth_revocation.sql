-- Revocation that sticks (audit gateway-auth-2, gateway-auth-3).

-- The account's auth generation. `bootstrap --reset` bumps it in the same
-- transaction that deletes the account's passkeys, sessions, enrollment links,
-- unused codes and ceremonies; every issuer of sessions, passkeys, codes and
-- grants rechecks it under a row lock (src/features/auth/generation.ts), so
-- nothing validated before a reset is written after it.
ALTER TABLE account ADD COLUMN auth_generation integer NOT NULL DEFAULT 0;
-- When a grant or passkey of the account was last revoked or deleted on
-- purpose (not by expiry). Push subscriptions that are bound to no grant
-- (password mode, or from before migration 202) stop at the next one.
ALTER TABLE account ADD COLUMN auth_revoked_at timestamptz;
-- Carried over from before this migration: the last deliberate grant
-- revocation, `bootstrap --reset` or passkey deletion on record.
UPDATE account a SET auth_revoked_at = (
  SELECT max(t) FROM (
    SELECT max(g.revoked_at) AS t FROM oauth_grant g
     WHERE g.account_id = a.id AND g.revoked_at IS NOT NULL AND g.revoked_reason <> 'expired'
    UNION ALL
    SELECT max(e.at) FROM auth_audit e
     WHERE e.account_id = a.id AND (e.event = 'passkey.delete' OR (e.event = 'bootstrap' AND e.details->>'reset' = 'true'))
  ) AS revocations
);

-- A session dies with the passkey that created it. Sessions whose passkey is
-- already gone are exactly the ones the old ON DELETE SET NULL kept alive.
DELETE FROM auth_session WHERE passkey_id IS NULL;
ALTER TABLE auth_session ALTER COLUMN passkey_id SET NOT NULL;
ALTER TABLE auth_session DROP CONSTRAINT auth_session_passkey_id_fkey;
ALTER TABLE auth_session ADD CONSTRAINT auth_session_passkey_id_fkey
  FOREIGN KEY (passkey_id) REFERENCES passkey(id) ON DELETE CASCADE;

-- Codes and grants remember the passkey whose assertion authorized them.
-- Codes live 60 s: the few in flight at migration time are dropped.
DELETE FROM oauth_code;
ALTER TABLE oauth_code ADD COLUMN passkey_id bytea NOT NULL REFERENCES passkey(id) ON DELETE CASCADE;
-- Null: a grant from before this migration (its passkey is unknown); deleting
-- any passkey of the account revokes those too.
ALTER TABLE oauth_grant ADD COLUMN passkey_id bytea REFERENCES passkey(id) ON DELETE SET NULL;
CREATE INDEX oauth_grant_passkey_idx ON oauth_grant (passkey_id);
