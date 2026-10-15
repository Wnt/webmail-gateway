-- Step-up for passkey management (audit gateway-auth-1). Adding or deleting
-- a passkey needs a recent user-verified assertion, in this session, with a
-- passkey already registered to the account: the login that created the
-- session, or an explicit re-check ('reauth' ceremony). Registering a new
-- passkey never sets it. Clearing the passkey clears the authorization.
-- Existing sessions start without it (their origin is unknown).
ALTER TABLE auth_session ADD COLUMN verified_at timestamptz;
ALTER TABLE auth_session ADD COLUMN verified_passkey_id bytea REFERENCES passkey(id) ON DELETE SET NULL;

ALTER TABLE auth_challenge DROP CONSTRAINT auth_challenge_kind_check;
ALTER TABLE auth_challenge ADD CONSTRAINT auth_challenge_kind_check CHECK (kind IN ('login', 'enroll', 'add', 'reauth'));
