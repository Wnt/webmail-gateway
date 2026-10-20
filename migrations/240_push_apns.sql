-- Native iPhone app (design/ios-native-app.md, "Device registration"): one
-- row per APNs device token. Registered with an OAuth access token of the
-- account (POST /relay/api/push/apns/devices) and bound, like an emulated
-- PushSubscription (migration 202), to that token's grant and to the
-- account's auth generation at that time: revoking the grant (sign-out,
-- passkey deletion), `bootstrap --reset` or a temporary passkey's expiry
-- stops its pushes; the grant's natural expiry does not. The same token
-- registering again replaces the row (new key, new grant).
-- A token registered to another account is not taken over while that
-- registration is still authorized (409); once it is not (signed out, reset,
-- passkey expired) or gone, the new registration replaces it.
-- public_key: the device's P-256 key (base64url of the 65-byte point) that
-- every push is encrypted to; not a secret. gone_at: APNs answered 410
-- Unregistered or 400 BadDeviceToken / DeviceTokenNotForTopic.
-- incarnation: new on every registration of the row (a renewal, a revival,
-- a takeover); a send and its result apply only to the incarnation they
-- were made for, so a late answer for an earlier one changes nothing.
-- key_created_at: when the device made public_key (epoch ms, as the app
-- sends it; 0 when it did not): within one grant a registration carrying an
-- older key never replaces a newer one (a delayed POST of a lost key).
CREATE TABLE push_apns_device (
  id              text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{16,64}$'),
  account_id      uuid NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  grant_id        uuid NOT NULL REFERENCES oauth_grant(id) ON DELETE CASCADE,
  auth_generation integer NOT NULL,
  token           text NOT NULL UNIQUE CHECK (token ~ '^[0-9a-f]{64,200}$'),
  environment     text NOT NULL CHECK (environment IN ('production', 'sandbox')),
  topic           text NOT NULL,
  public_key      text NOT NULL,
  name            text,
  locale          text CHECK (locale IN ('fi', 'en')),
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  last_push_at    timestamptz,
  fail_count      integer NOT NULL DEFAULT 0,
  gone_at         timestamptz,
  incarnation     text NOT NULL DEFAULT gen_random_uuid()::text,
  key_created_at  bigint NOT NULL DEFAULT 0 CHECK (key_created_at >= 0)
);
CREATE INDEX push_apns_device_account_idx ON push_apns_device (account_id);
CREATE INDEX push_apns_device_grant_idx ON push_apns_device (grant_id);
