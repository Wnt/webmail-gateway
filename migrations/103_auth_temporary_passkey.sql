-- Temporary passkeys (live testing by agents, 2026-10-17). A passkey with
-- `expires_at` stops signing in at that time, and so does everything that
-- came from it: sessions, codes, grants, refresh and access tokens, push
-- subscriptions. Each of those is capped at the passkey's expiry when it is
-- issued and checked against it on every use; the in-process sweeper deletes
-- the expired passkey later (housekeeping only). A temporary passkey's
-- session cannot manage passkeys. Null: an ordinary passkey, unchanged.
-- Sessions, codes and grants already record their passkey (migration 101).
ALTER TABLE passkey ADD COLUMN expires_at timestamptz;
CREATE INDEX passkey_expires_idx ON passkey (expires_at) WHERE expires_at IS NOT NULL;

-- A temporary enrollment link (CLI `enroll --ttl`): the passkey created from
-- it lives `passkey_ttl_s` seconds from its creation and is named `label`.
ALTER TABLE auth_enroll_token ADD COLUMN passkey_ttl_s integer CHECK (passkey_ttl_s > 0);
ALTER TABLE auth_enroll_token ADD COLUMN label text CHECK (char_length(label) BETWEEN 1 AND 64);
