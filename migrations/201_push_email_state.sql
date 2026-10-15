-- The last JMAP Email state the push pipeline processed for the account, so an
-- EmailDelivery StateChange is answered with Email/changes from that state.
-- Null: unknown (first run, or reset after legacy-proxy re-created the account).
ALTER TABLE push_upstream ADD COLUMN email_state text;
