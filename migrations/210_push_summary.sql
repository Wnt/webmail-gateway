-- AI summaries (Phase 5): one cached result per message, so a message is sent
-- to the model at most once. `summary` is sealed (AES-256-GCM under a purpose
-- key derived from GATEWAY_ENC_KEY, AAD = account id + email id), because it is
-- mail content. 'rejected' = the model's answer failed the output checks; it is
-- cached too, so the same message is not summarised again. Timeouts and errors
-- are not cached. Pruned after 7 days, like push_notified.
CREATE TABLE push_summary (
  account_id uuid NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  email_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('ok', 'rejected')),
  summary bytea,
  model text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, email_id),
  CHECK ((status = 'ok') = (summary IS NOT NULL))
);
