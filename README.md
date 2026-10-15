# webmail-gateway

Gateway in front of [legacy-proxy](https://github.com/bulwarkmail/legacy-proxy) for the [Bulwark](https://github.com/bulwarkmail/webmail) webmail: passkey-only login, OAuth 2.1, and web push with message previews. Part of a self-hosted webmail for Gandi mail. Licensed AGPL-3.0-or-later.

## Contract deviations

Where the skeleton differs from or extends `COORDINATION.md` (the contract file kept in the coordinator's checkout, `/home/wnt/webmail/COORDINATION.md`):

- **State is passed in, not global.** The contract lists names only. Every function that touches state takes a leading context: `ctx: { config, db }` (a full `AppContext` works) for `accounts.*` and `legacy*`. `mintLegacyToken(slug, username, key?, nowSec?)` has two optional trailing arguments; the key defaults to `LEGACY_SESSION_HMAC_KEY` from the environment, and the gateway itself passes `config.legacyHmacKey`.
- **`hooks` and `auth-context` are process-wide registries** (as the contract's free functions imply). `registerAuthenticator`, `onNewMail` and `registerPushSubscriptionHandler` return an unregister function; `resetAuthenticators()` and `resetHooks()` exist for tests.
- **`handlePushSubscription`** returns the method's response arguments, and throws `JmapMethodError(type, description)` (`forbidden` when no push feature is registered, per D6). The JMAP proxy turns that into `["error", {type, description}, callId]`.
- **Additions:** `src/types.ts` (`AppContext`, `FeaturePlugin`, `CliCommand`); each feature's `index.ts` exports `<feature>Plugin` and `<feature>CliCommands` (merged into `src/cli.ts`); `parse<Feature>Config(env)` in each feature's `config.ts`; `src/core/token.ts` (the raw HMAC token code); `test/helpers.ts` and `test/fake-legacy.ts` for feature tests.
- **`relogin(ctx, account)`** is exported from `core/legacy` (D2): the Basic re-login that `legacyFetch` does on 401, for callers that stream and cannot use `legacyFetch`'s retry.
- **Core config** adds `PUBLIC_BASE_URL` (required) and `LEGACY_PROVIDER` (default `gandi`) as `config.publicBaseUrl` / `config.legacyProvider` (D1, P4).
- **Image tags** are `ghcr.io/wnt/webmail-gateway:sha-<full 40-char commit sha>` and `:main`.

## What and why

Bulwark is a good webmail UI, and legacy-proxy turns Gandi's IMAP/SMTP/Sieve/CardDAV into the JMAP that Bulwark speaks. What neither gives us is a login that does not involve typing the mailbox password into a browser every time. This gateway sits between them and adds:

- **Passkey-only login** with username-free (discoverable) passkeys, and an **OAuth 2.1** server that Bulwark uses in OAuth-only mode.
- A **JMAP proxy** that authenticates callers (OAuth bearer, or Basic in password mode with an allowlist and rate limit) and forwards to legacy-proxy.
- **Push with message previews**: Bulwark-relay-compatible endpoints plus web-push sending, so notifications show sender, subject and a preview even after the browser session has expired.

## Architecture

```
browser -> edge (TLS, routing) -> gateway -> legacy-proxy -> Gandi (IMAP/SMTP/Sieve/CardDAV)
                 \-> Bulwark (UI, everything the gateway does not own)
gateway -> Postgres (accounts, passkeys, OAuth state, push subscriptions)
```

The edge sends `/.well-known/jmap`, `/jmap/*`, `/oauth/*`, `/.well-known/oauth-*`, `/auth/*` and `/relay/api/push/*` to the gateway unchanged, and everything else to Bulwark. The gateway mints short-lived (300 s) HMAC bearer tokens that legacy-proxy accepts, and keeps each account's Gandi password sealed (AES-256-GCM) so it can transparently log back in when legacy-proxy loses its state (on a 401: one Basic login, then one retry). Postgres holds everything durable; tests use in-process PGlite instead.

Layout: `src/app.ts` builds the Fastify app, `src/config.ts` composes the per-feature config, `src/core/` holds the shared modules (`crypto`, `accounts`, `legacy`, `auth-context`, `hooks`, `token`), `src/features/{jmap,auth,push}/` are the feature plugins, and `migrations/NNN_*.sql` are plain SQL (000-099 core, 100-199 auth, 200-299 push, 300-399 jmap).

Related repositories: [bulwarkmail/webmail](https://github.com/bulwarkmail/webmail) (UI), [bulwarkmail/legacy-proxy](https://github.com/bulwarkmail/legacy-proxy), and [Wnt/webmail](https://github.com/Wnt/webmail) (our Bulwark fork).

## Development

Node 24.

```sh
npm ci
npm run typecheck   # tsc --noEmit, src and tests
npm test            # vitest + PGlite, no Docker or Postgres needed
npm run build       # tsc -> dist/
npm start           # node dist/server.js (needs the env below)
npm run migrate     # apply pending migrations (also runs on start unless MIGRATE_ON_START=false)
npm run cli -- <command> [args]   # admin commands; with no command it lists them
```

Configuration is environment-only; see `.env.example` and `src/config.ts`. Core keys: `DATABASE_URL`, `GATEWAY_ENC_KEY` and `LEGACY_SESSION_HMAC_KEY` (both base64 of 32 bytes; the latter must equal legacy-proxy's `SESSION_HMAC_KEY`), `LEGACY_PROXY_URL`, and optionally `PORT` (8080), `HOST`, `LOG_LEVEL`, `MIGRATE_ON_START`. Each feature adds its own keys in `src/features/<feature>/config.ts`.

Endpoints owned by the skeleton: `/healthz` (liveness) and `/readyz` (pings the database; 503 when it fails).

Writing a feature: implement the `FeaturePlugin` in `src/features/<feature>/index.ts` (its options are the `AppContext`: `config`, `db`, `log`, `fetch`), add migrations in your number range, and use `test/helpers.ts` (`makeTestContext`) and `test/fake-legacy.ts` (a stand-in legacy-proxy on an ephemeral port) in tests.

## Auth feature (passkeys and OAuth 2.1)

Design: `design/auth.md` in the coordinator's checkout. The gateway is the OAuth 2.1 authorization server Bulwark signs in through, and its only login UI is a username-free passkey prompt.

- **Endpoints:** `/.well-known/oauth-authorization-server`, `/oauth/authorize` (PKCE S256, exact redirect match, always a fresh passkey tap), `/oauth/token` (`client_secret_post` or Basic; `authorization_code` and `refresh_token`), `/oauth/revoke`, `/oauth/end_session`; `/auth/login`, `/auth/enroll/<token>`, `/auth/passkeys` (list, add, rename, delete, sign out) and their JSON APIs; `/auth/static/*`.
- **Tokens:** opaque, prefixed (`gwc_` code 60 s single use, `gwa_` access 1 h, `gwr_` refresh 30 d rotated with a 30 s idempotent grace, `gws_` session, `gwe_` enroll 15 min), stored as sha256. Revocation emits `hooks.emitTokenRevoked`. Bearer tokens are recognised by the authenticator this feature registers in `core/auth-context`; Bulwark's tokens carry scope `mail`.
- **Config:** core `PUBLIC_BASE_URL` (issuer, WebAuthn origin, RP ID = its host) and `ALLOWED_EMAILS`; `OAUTH_CLIENT_SECRET_BULWARK`, `AUTH_RP_NAME`, `AUTH_SESSION_TTL_H`.
- **Bootstrap and recovery:** `npm run cli -- bootstrap <email> [--reset]` (in the cluster: `kubectl exec -it deploy/webmail-gateway -- node dist/cli.js bootstrap <email>`). It reads the mailbox password from the terminal (or stdin), verifies it through legacy-proxy, stores it sealed, and prints a one-time enrollment URL valid for 15 minutes. `--reset` also deletes the account's passkeys and sessions and revokes its grants.
- **Bulwark (OAuth mode) expects:** `OAUTH_ENABLED=true`, `OAUTH_ONLY=true`, `AUTO_SSO_ENABLED=true`, `OAUTH_ISSUER_URL=<PUBLIC_BASE_URL>`, `OAUTH_CLIENT_ID=bulwark`, `OAUTH_CLIENT_SECRET=<OAUTH_CLIENT_SECRET_BULWARK>`, `JMAP_SERVER_URL=<PUBLIC_BASE_URL>`; optionally `OAUTH_SCOPES=mail` (the default OIDC scopes are accepted and dropped) and `OAUTH_POST_LOGOUT_REDIRECT_URI=<PUBLIC_BASE_URL>/`. Test stacks on plain http need `COOKIE_SECURE=false` in Bulwark, and Bulwark skips `end_session` there (it requires https).

## Container image

`docker build -t webmail-gateway .` gives a multi-stage image running as the non-root `node` user with a `HEALTHCHECK` on `/healthz`. CI pushes `ghcr.io/wnt/webmail-gateway` from `main`.

## Contract

The binding contract for layout, module signatures, migration ranges and routes is `COORDINATION.md` in the coordinator's checkout (`/home/wnt/webmail/COORDINATION.md`); change it only through the coordinator.
