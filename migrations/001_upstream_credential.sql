-- Native JMAP upstream (src/core/upstream/jmap.ts): the per-account credential
-- for the upstream server (an API token, or a password for Basic), sealed with
-- AES-256-GCM under an HKDF purpose key of GATEWAY_ENC_KEY, AAD = account id.
-- The legacy upstream keeps using gandi_secret.
ALTER TABLE account ADD COLUMN upstream_secret bytea;
