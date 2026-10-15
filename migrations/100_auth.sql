-- Auth feature (range 100-199): passkeys, gateway sessions, OAuth 2.1 state, audit.
-- Every token, session id and enroll token is stored as sha256(token) (bytea);
-- a copy of the database signs nobody in. Timestamps are supplied by the
-- application so tests can drive the clock.

CREATE TABLE passkey (
  id            bytea PRIMARY KEY,                       -- raw WebAuthn credential id
  account_id    uuid NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  public_key    bytea NOT NULL,                          -- COSE public key
  counter       bigint NOT NULL DEFAULT 0,
  transports    text NOT NULL DEFAULT '',                -- space-separated
  aaguid        text,
  backed_up     boolean NOT NULL DEFAULT false,
  name          text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
  created_at    timestamptz NOT NULL,
  last_used_at  timestamptz
);
CREATE INDEX passkey_account_idx ON passkey (account_id);

-- One row per ceremony, consumed by DELETE ... RETURNING (single use under concurrency).
CREATE TABLE auth_challenge (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind        text NOT NULL CHECK (kind IN ('login', 'enroll', 'add')),
  challenge   text NOT NULL,                             -- base64url
  account_id  uuid REFERENCES account(id) ON DELETE CASCADE,  -- enroll/add only
  expires_at  timestamptz NOT NULL
);

CREATE TABLE auth_session (
  id_hash      bytea PRIMARY KEY,
  account_id   uuid NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  passkey_id   bytea REFERENCES passkey(id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  expires_at   timestamptz NOT NULL,
  ip           text,
  user_agent   text
);
CREATE INDEX auth_session_account_idx ON auth_session (account_id);

CREATE TABLE auth_enroll_token (
  token_hash  bytea PRIMARY KEY,
  account_id  uuid NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL,
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz
);

-- The unit of revocation: client x account x scopes (x resource, for MCP later).
CREATE TABLE oauth_grant (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id      text NOT NULL,
  account_id     uuid NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  scopes         text NOT NULL,                          -- space-separated
  resource       text,
  created_at     timestamptz NOT NULL,
  expires_at     timestamptz NOT NULL,
  revoked_at     timestamptz,
  revoked_reason text
);
CREATE INDEX oauth_grant_account_idx ON oauth_grant (account_id);

CREATE TABLE oauth_code (
  code_hash       bytea PRIMARY KEY,
  client_id       text NOT NULL,
  account_id      uuid NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  redirect_uri    text NOT NULL,
  code_challenge  text NOT NULL,
  scopes          text NOT NULL,
  resource        text,
  created_at      timestamptz NOT NULL,
  expires_at      timestamptz NOT NULL,
  used_at         timestamptz,
  grant_id        uuid REFERENCES oauth_grant(id) ON DELETE SET NULL
);

CREATE TABLE oauth_refresh_token (
  token_hash  bytea PRIMARY KEY,
  grant_id    uuid NOT NULL REFERENCES oauth_grant(id) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL,
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  -- The sealed successor pair, kept for the 30 s reuse grace (A10) so a
  -- concurrent refresh from another tab gets the same answer; then cleared.
  successor   bytea
);
CREATE INDEX oauth_refresh_token_grant_idx ON oauth_refresh_token (grant_id);

CREATE TABLE oauth_access_token (
  token_hash  bytea PRIMARY KEY,
  grant_id    uuid NOT NULL REFERENCES oauth_grant(id) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL,
  expires_at  timestamptz NOT NULL
);
CREATE INDEX oauth_access_token_grant_idx ON oauth_access_token (grant_id);

CREATE TABLE auth_audit (
  id          bigserial PRIMARY KEY,
  at          timestamptz NOT NULL,
  event       text NOT NULL,
  account_id  uuid,
  client_id   text,
  ip          text,
  user_agent  text,
  details     jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX auth_audit_at_idx ON auth_audit (at);
