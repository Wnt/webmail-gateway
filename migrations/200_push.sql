-- Push feature (range 200-299). Design: design/push.md section 9.

-- Relay record: one browser Web Push endpoint, keyed by the relay
-- subscriptionId that Bulwark uses (its per-account deviceClientId).
-- Registered unauthenticated through /relay/api/push/register/web; it only
-- receives pushes once an authenticated emulated PushSubscription points at it.
CREATE TABLE push_relay_sub (
  relay_id          text PRIMARY KEY CHECK (relay_id ~ '^[A-Za-z0-9_-]{8,128}$'),
  endpoint          text NOT NULL,
  p256dh            text NOT NULL,
  auth              text NOT NULL,
  account_label     text,
  verification_code text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  last_push_at      timestamptz,
  -- the push service answered 404/410 (or kept rejecting our VAPID key)
  gone_at           timestamptz,
  fail_count        integer NOT NULL DEFAULT 0
);

-- Emulated RFC 8620 PushSubscription, as created by Bulwark through the JMAP proxy.
CREATE TABLE push_jmap_sub (
  id                text PRIMARY KEY,
  account_id        uuid NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  device_client_id  text NOT NULL,
  relay_id          text NOT NULL,
  url               text NOT NULL,
  types             text[],
  expires           timestamptz NOT NULL,
  verification_code text NOT NULL,
  verified_at       timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX push_jmap_sub_account_idx ON push_jmap_sub (account_id);
CREATE INDEX push_jmap_sub_relay_idx ON push_jmap_sub (relay_id);

-- The gateway's own PushSubscription in legacy-proxy: at most one per account.
-- hook_id is the secret path segment of /internal/push/jmap/:hookId.
CREATE TABLE push_upstream (
  account_id        uuid PRIMARY KEY REFERENCES account(id) ON DELETE CASCADE,
  hook_id           text NOT NULL UNIQUE,
  upstream_id       text,
  legacy_account_id text,
  status            text NOT NULL CHECK (status IN ('none', 'creating', 'verifying', 'active', 'failed')),
  verification_code text,
  expires           timestamptz,
  verified_at       timestamptz,
  -- mail received before this is never announced
  baseline_at       timestamptz,
  last_event_at     timestamptz,
  last_check_at     timestamptz,
  last_check_ok     boolean,
  next_attempt_at   timestamptz,
  attempts          integer NOT NULL DEFAULT 0,
  last_error        text,
  lease_until       timestamptz
);

-- Dedupe and claim: a row means "this message was announced (or deliberately
-- skipped as part of an oversized burst)". Pruned after 7 days.
CREATE TABLE push_notified (
  account_id  uuid NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  email_id    text NOT NULL,
  received_at timestamptz NOT NULL,
  notified_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, email_id)
);
