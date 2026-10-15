-- Push authorization (audit gateway-data-1). An emulated PushSubscription
-- belongs to the OAuth grant whose token created it and to the account's auth
-- generation at that time (migration 101). Recipient selection reads both, so
-- revoking the grant (sign-out, passkey deletion, token theft detection) or
-- `bootstrap --reset` stops pushes for good, from any process. Natural expiry
-- of the grant or its tokens does not: notifications outlive sign-in.
-- Null grant: password mode, or a subscription from before this migration.
ALTER TABLE push_jmap_sub ADD COLUMN grant_id uuid REFERENCES oauth_grant(id) ON DELETE CASCADE;
ALTER TABLE push_jmap_sub ADD COLUMN auth_generation integer NOT NULL DEFAULT 0;
CREATE INDEX push_jmap_sub_grant_idx ON push_jmap_sub (grant_id);
