-- gateway-data-2: a relay record registered anonymously through
-- /relay/api/push/register/web stays "pending" until an authenticated
-- PushSubscription that points at it is verified (linked_at). Pending records
-- are capped (per source and globally) and deleted after a short setup window,
-- so anonymous registrations cannot accumulate. pending_source is the
-- registering client's address (IPv6: its /64), kept only while pending.
ALTER TABLE push_relay_sub ADD COLUMN linked_at timestamptz;
ALTER TABLE push_relay_sub ADD COLUMN pending_source text;
UPDATE push_relay_sub r SET linked_at = now()
 WHERE EXISTS (SELECT 1 FROM push_jmap_sub s WHERE s.relay_id = r.relay_id AND s.verified_at IS NOT NULL);
CREATE INDEX push_relay_sub_pending_idx ON push_relay_sub (updated_at) WHERE linked_at IS NULL;
CREATE INDEX push_relay_sub_pending_source_idx ON push_relay_sub (pending_source) WHERE linked_at IS NULL;
