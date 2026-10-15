-- Core schema (range 000-099 is reserved for the skeleton).
-- account: one row per mailbox user. gandi_secret is the Gandi password
-- sealed with AES-256-GCM (src/core/crypto.ts); it is never stored in clear.
CREATE TABLE account (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email        text NOT NULL UNIQUE CHECK (email = lower(email)),
  legacy_slug  text NOT NULL,
  gandi_secret bytea,
  created_at   timestamptz NOT NULL DEFAULT now()
);
