-- A relay record's incarnation: new for every inserted record and whenever its
-- endpoint or keys change; kept for an unchanged refresh (Bulwark's enable and
-- daily re-sync). A queued push and a preview ticket name the incarnation they
-- were made for, so a record deleted and registered again (even with the same
-- endpoint and keys), or changed and changed back, never continues what was
-- queued or issued for the old one. Not a secret: unique is what counts.
ALTER TABLE push_relay_sub ADD COLUMN incarnation text NOT NULL DEFAULT gen_random_uuid()::text;
