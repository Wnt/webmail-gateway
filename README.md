# webmail-gateway

Gateway in front of a mail upstream for the [Bulwark](https://github.com/bulwarkmail/webmail) webmail: passkey-only login, OAuth 2.1, and web push with message previews. The upstream is either [legacy-proxy](https://github.com/bulwarkmail/legacy-proxy) in front of Gandi mail, or a native JMAP server such as Fastmail (see [Upstreams](#upstreams-legacy-proxy-or-native-jmap)). Licensed AGPL-3.0-or-later.

## Contract deviations

Where the skeleton differs from or extends `COORDINATION.md` (the contract file kept in the coordinator's checkout, `/home/wnt/webmail/COORDINATION.md`):

- **State is passed in, not global.** The contract lists names only. Every function that touches state takes a leading context: `ctx: { config, db }` (a full `AppContext` works) for `accounts.*` and `legacy*`. `mintLegacyToken(slug, username, key?, nowSec?)` has two optional trailing arguments; the key defaults to `LEGACY_SESSION_HMAC_KEY` from the environment, and the gateway itself passes `config.legacyHmacKey`.
- **`hooks` and `auth-context` are process-wide registries** (as the contract's free functions imply). `registerAuthenticator`, `onNewMail` and `registerPushSubscriptionHandler` return an unregister function; `resetAuthenticators()` and `resetHooks()` exist for tests.
- **`handlePushSubscription`** returns the method's response arguments, and throws `JmapMethodError(type, description)` (`forbidden` when no push feature is registered, per D6). The JMAP proxy turns that into `["error", {type, description}, callId]`.
- **Additions:** `src/types.ts` (`AppContext`, `FeaturePlugin`, `CliCommand`); each feature's `index.ts` exports `<feature>Plugin` and `<feature>CliCommands` (merged into `src/cli.ts`); `parse<Feature>Config(env)` in each feature's `config.ts`; `src/core/token.ts` (the raw HMAC token code); `test/helpers.ts` and `test/fake-legacy.ts` for feature tests.
- **`relogin(ctx, account)`** is exported from `core/legacy` (D2): the Basic re-login that `legacyFetch` does on 401, for callers that stream and cannot use `legacyFetch`'s retry.
- **Core config** adds `PUBLIC_BASE_URL` (required) and `LEGACY_PROVIDER` (default `gandi`) as `config.publicBaseUrl` / `config.legacyProvider` (D1, P4).
- **`core/upstream`** (D14) is how features reach the mail server: `getUpstream(ctx)` returns the `legacy` or `jmap` implementation chosen by `UPSTREAM_KIND`. Features no longer call `core/legacy` directly; it stays as the legacy implementation's helper (token minting, re-login, `onLegacyRelogin`). With `UPSTREAM_KIND=jmap`, `LEGACY_PROXY_URL` and `LEGACY_SESSION_HMAC_KEY` are optional (`config.legacyProxyUrl` is then `""`), and empty env values count as unset. Migration `001` adds `account.upstream_secret`, written by `accounts.setUpstreamCredential` (sealed under an HKDF purpose key, A6, AAD = account id).
- **Push payload** (Phase 5): the quiet replacement push adds `email.summary` (≤ 200 chars, plain text) and a top-level `renotify: false` to the contract payload; see [AI summaries](#ai-summaries-phase-5).
- **Image tags** are `ghcr.io/wnt/webmail-gateway:sha-<full 40-char commit sha>` and `:main`.

## What and why

Bulwark is a good webmail UI, and legacy-proxy turns Gandi's IMAP/SMTP/Sieve/CardDAV into the JMAP that Bulwark speaks. What neither gives us is a login that does not involve typing the mailbox password into a browser every time. This gateway sits between them and adds:

- **Passkey-only login** with username-free (discoverable) passkeys, and an **OAuth 2.1** server that Bulwark uses in OAuth-only mode.
- A **JMAP proxy** that authenticates callers (OAuth bearer, or Basic in password mode with an allowlist and rate limit) and forwards to the upstream.
- **Push with message previews**: Bulwark-relay-compatible endpoints plus web-push sending, so notifications show sender, subject and a preview even after the browser session has expired.

## Architecture

```
browser -> edge (TLS, routing) -> gateway -> legacy-proxy -> Gandi (IMAP/SMTP/Sieve/CardDAV)   (UPSTREAM_KIND=legacy)
                                         \-> native JMAP server, e.g. Fastmail                 (UPSTREAM_KIND=jmap)
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

Configuration is environment-only; see `.env.example` and `src/config.ts`. Core keys: `DATABASE_URL`, `GATEWAY_ENC_KEY` and `LEGACY_SESSION_HMAC_KEY` (both base64 of 32 bytes; the latter must equal legacy-proxy's `SESSION_HMAC_KEY`), `LEGACY_PROXY_URL` (legacy upstream; for a native JMAP upstream `UPSTREAM_KIND=jmap`, `UPSTREAM_SESSION_URL`, `UPSTREAM_AUTH` and `UPSTREAM_ALLOWED_ORIGINS` instead, see [Upstreams](#upstreams-legacy-proxy-or-native-jmap)), and optionally `PORT` (8080), `HOST`, `LOG_LEVEL`, `MIGRATE_ON_START`. Each feature adds its own keys in `src/features/<feature>/config.ts`.

Endpoints owned by the skeleton: `/healthz` (liveness) and `/readyz` (pings the database; 503 when it fails).

Writing a feature: implement the `FeaturePlugin` in `src/features/<feature>/index.ts` (its options are the `AppContext`: `config`, `db`, `log`, `fetch`), add migrations in your number range, and use `test/helpers.ts` (`makeTestContext`) and `test/fake-legacy.ts` (a stand-in legacy-proxy on an ephemeral port) in tests.

## Auth feature (passkeys and OAuth 2.1)

Design: `design/auth.md` in the coordinator's checkout. The gateway is the OAuth 2.1 authorization server Bulwark signs in through, and its only login UI is a username-free passkey prompt.

- **Endpoints:** `/.well-known/oauth-authorization-server`, `/oauth/authorize` (PKCE S256, exact redirect match, always a fresh passkey tap), `/oauth/token` (`client_secret_post` or Basic; `authorization_code` and `refresh_token`), `/oauth/revoke`, `/oauth/end_session`; `/auth/login`, `/auth/enroll/<token>`, `/auth/passkeys` (list, add, rename, delete, sign out) and their JSON APIs; `/auth/static/*`.
- **Tokens:** opaque, prefixed (`gwc_` code 60 s single use, `gwa_` access 1 h, `gwr_` refresh 30 d rotated with a 30 s idempotent grace, `gws_` session, `gwe_` enroll 15 min), stored as sha256. Revocation emits `hooks.emitTokenRevoked`. Bearer tokens are recognised by the authenticator this feature registers in `core/auth-context`; Bulwark's tokens carry scope `mail`.
- **Config:** core `PUBLIC_BASE_URL` (issuer, WebAuthn origin, RP ID = its host) and `ALLOWED_EMAILS`; `OAUTH_CLIENT_SECRET_BULWARK`, `AUTH_RP_NAME` (the product name: passkey `rp.name` and the auth pages' header and title), `AUTH_SESSION_TTL_H`.
- **Bootstrap and recovery:** `npm run cli -- bootstrap <email> [--reset]` (in the cluster: `kubectl exec -it deploy/webmail-gateway -- node dist/cli.js bootstrap <email>`). It reads the upstream credential from the terminal (or stdin): the mailbox password with legacy-proxy, the API token with a native JMAP upstream. It verifies it with the upstream, stores it sealed, and prints a one-time enrollment URL valid for 15 minutes. `--reset` also deletes the account's passkeys and sessions, revokes its grants and push subscriptions, and invalidates earlier enrollment links, unused codes and pending ceremonies; it bumps the account's auth generation in the same transaction, so a ceremony that was mid-flight issues nothing (`src/features/auth/generation.ts`).
- **Step-up for passkey management:** adding or deleting a passkey needs a user-verified assertion with a passkey the account already has, made in the same session within the last 5 minutes (`STEP_UP_WINDOW_MS`). Signing in counts, so managing passkeys right after signing in needs no extra prompt; later, the page asks for one passkey first (`/auth/passkeys/reauth/*`). Enrolling through a link and registering a passkey never count. Both ends of a registration and every deletion check it.
- **Revocation:** deleting a passkey ends the gateway sessions it created and revokes the OAuth grants it authorized (grants from before migration 101 recorded no passkey and are revoked by any deletion), and with them those grants' push subscriptions. Other passkeys' sessions and grants stay. Push follows revocation, not expiry: a subscription stops when its grant is revoked (Bulwark sign-out, passkey deletion, refresh-token reuse, reset), never because a session, token or grant expired. After a revocation, signing in again lets Bulwark's re-sync create a new subscription.
- **Bulwark (OAuth mode) expects:** `OAUTH_ENABLED=true`, `OAUTH_ONLY=true`, `AUTO_SSO_ENABLED=true`, `OAUTH_ISSUER_URL=<PUBLIC_BASE_URL>`, `OAUTH_CLIENT_ID=bulwark`, `OAUTH_CLIENT_SECRET=<OAUTH_CLIENT_SECRET_BULWARK>`, `JMAP_SERVER_URL=<PUBLIC_BASE_URL>`; optionally `OAUTH_SCOPES=mail` (the default OIDC scopes are accepted and dropped) and `OAUTH_POST_LOGOUT_REDIRECT_URI=<PUBLIC_BASE_URL>/`. Test stacks on plain http need `COOKIE_SECURE=false` in Bulwark, and Bulwark skips `end_session` there (it requires https).

## Upstreams (legacy-proxy or native JMAP)

`src/core/upstream` hides which mail server sits behind the gateway. Both implementations are first-class; switching is a config change plus re-running `bootstrap`, with no code change.

| | `UPSTREAM_KIND=legacy` (default) | `UPSTREAM_KIND=jmap` |
| --- | --- | --- |
| Server | legacy-proxy in front of Gandi IMAP/SMTP | a native JMAP server: Fastmail in production, Stalwart on test stacks |
| Config | `LEGACY_PROXY_URL`, `LEGACY_SESSION_HMAC_KEY`, `LEGACY_PROVIDER` | `UPSTREAM_SESSION_URL` (Fastmail: `https://api.fastmail.com/jmap/session`), `UPSTREAM_AUTH=bearer` (API token) or `basic` (password), `UPSTREAM_ALLOWED_ORIGINS` (extra origins the session may use; Fastmail: `https://www.fastmailusercontent.com`) |
| Credential per account | the Gandi password, sealed in `gandi_secret` | the API token (or password), sealed in `upstream_secret` |
| Upstream auth | minted 300 s HMAC Bearer token; on 401 one Basic re-login with the Gandi password, then one retry | `Authorization: Bearer <token>` (or Basic). A 401 means the token was revoked or expired: the client gets 401, the log says to re-run bootstrap |
| URLs | legacy-proxy's fixed paths | every URL from the upstream's session (`apiUrl`, `downloadUrl`, `uploadUrl`, `eventSourceUrl`), RFC 6570 templates in any variable order, relative URLs resolved. Each must be on an **allowed origin**: the session URL's own or one listed in `UPSTREAM_ALLOWED_ORIGINS` (scheme, host and port must match; no user info, no template variable in the origin, no https downgrade). GET redirects (at most 3) must stay on allowed origins too, and drop the credential when the origin changes |
| New-mail signal for push | the gateway's own `PushSubscription` in legacy-proxy, posting to `/internal/push/jmap/:hookId` | one upstream EventSource per account with an active device (P1), `types=EmailDelivery`, ping 60 s with a silence watchdog, reconnect with exponential backoff (Retry-After on 429); a reconnect triggers a catch-up run |
| Password mode (`JMAP_PASSWORD_MODE`) | supported | not offered (config error) |

Shared behaviour:
- The public session always advertises the gateway's own URLs (`<PUBLIC_BASE_URL>/jmap`, `/jmap/download/{accountId}/{blobId}/{type}/{name}`, `/jmap/upload/{accountId}`, `/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}`); each request is mapped onto the upstream's template. Account, mailbox and email ids pass through unchanged (P2).
- Capabilities are passed through, minus those that do not work through the gateway: `urn:ietf:params:jmap:websocket` (not proxied) and `urn:ietf:params:jmap:emailpush` (PushSubscription is answered by the push feature, D5), also in `accountCapabilities`. Core limits are clamped to the `JMAP_MAX_*` settings. Shared accounts (`isPersonal: false`) keep their names.
- Upload, download and EventSource are streamed as before; the push pipeline (`Email/changes` from the last state, query fallback on `cannotCalculateChanges`) is the same for both.

**Test stacks:** `tools/stack up <name> --gateway --upstream jmap` runs the gateway against Stalwart's native JMAP (Basic, no legacy-proxy); the default `--upstream legacy` keeps legacy-proxy. The e2e suite (`tools/stack e2e <name>`) runs in both modes.

**Bootstrap** (`npm run cli -- bootstrap <email> [--reset]`) reads the credential from the terminal without echo, or from stdin when piped; it is never printed or logged. With `jmap` it fetches the upstream session with the token and requires that the session's `username`, or the name of its primary mail account, equals `<email>` (which must be in `ALLOWED_EMAILS`); then it stores the token sealed and prints the passkey enrollment link. Exit 3: rejected, or another mailbox's token. Rotating the token is the same command (the old one is replaced; passkeys stay).

### Fastmail

From Fastmail's documentation (read 2026-10-15; the API itself was not called):
- **Session and auth:** the JMAP session resource is `https://api.fastmail.com/jmap/session`; an API token is sent as `Authorization: Bearer {value}` [F1]. Tokens are created in Settings → Privacy & Security → Manage API tokens, type **JMAP**; they are shown once, have no documented expiry, and are not available on the Basic plan [F2].
- **Token scopes** offered for JMAP tokens [F2]: *Read-only access*, *Email*, *Email submission* (requires Email), *Contacts and contact groups*, *Masked Email*. Create the token **without** Read-only, with:
  - minimal: **Email** + **Email submission** (read, organise and send mail; push);
  - recommended: also **Contacts and contact groups** (Bulwark's contacts use JMAP Contacts, RFC 9610 [F1]);
  - not needed: Masked Email. There is no separate vacation-response scope for API tokens (the OAuth scope `urn:ietf:params:jmap:vacationresponse` exists [F1]); whether *Email* covers it shows in the session after bootstrap.
- **Capabilities:** mail, submission, vacation response, contacts and Masked Email are JMAP; **calendars are CalDAV only** ("We will be opening up JMAP access as well, as soon as the specification is finalized") [F1], so Bulwark gets no calendar through the gateway. legacy-proxy's Sieve extension (`urn:bulwark:params:jmap:sieve`) does not exist there, so Bulwark's filter UI is absent.
- **Rate limits:** no published JMAP API rate limits [F1][F3]. Account limits include 500 successful logins per user per 10 minutes "across all services" and 70 MB per message [F3]; Masked Email creation is rate-limited with a `rateLimit` SetError [F1]. The gateway passes 429 + `Retry-After` through (Bulwark waits), the push watcher honours it, and the push pipeline retries with backoff.
- **Download host and EventSource:** not in Fastmail's own docs. A published example session [F4] shows `downloadUrl` on another host (`https://www.fastmailusercontent.com/jmap/download/{accountId}/{blobId}/{name}?type={type}`) and an `eventSourceUrl` without template variables (`https://api.fastmail.com/jmap/event/`); 1Password's write-up of its Fastmail JMAP integration shows the same download template on a `fastmailusercontent.com` host [F5]. Both shapes are handled generically and covered by tests.
- **Allowed origins:** the gateway sends the API token only to the session URL's origin (`https://api.fastmail.com`) and to `UPSTREAM_ALLOWED_ORIGINS`. Fastmail therefore needs:
  ```
  UPSTREAM_KIND=jmap
  UPSTREAM_SESSION_URL=https://api.fastmail.com/jmap/session
  UPSTREAM_ALLOWED_ORIGINS=https://www.fastmailusercontent.com
  ```
  If the real session (or a redirect) uses another origin, nothing is sent there. `bootstrap` exits with `upstream session downloadUrl is on https://…, which is not an allowed upstream origin; if it is legitimate, add it to UPSTREAM_ALLOWED_ORIGINS`; at runtime the same message is logged (`upstream session refused`) and JMAP requests answer 502 until the origin is added and the gateway restarted.
- **Push:** Fastmail's docs do not mention RFC 8620 `PushSubscription`. It would also need a callback URL reachable from the internet, while `/internal` is cluster-only, so the `jmap` upstream uses the EventSource (RFC 8620 section 7.3), which needs no inbound exposure.

To verify at cutover (not testable without a token): the real session's `downloadUrl`/`eventSourceUrl` and their redirects (every origin they use must be in `UPSTREAM_ALLOWED_ORIGINS`), that `EmailDelivery` StateChanges arrive on the EventSource and how often it pings, the session `username` (must equal the gateway account's email), which capabilities a token with the scopes above advertises, and 429 behaviour.

Sources: [F1] Fastmail API documentation, https://www.fastmail.com/dev/ · [F2] Fastmail help, API tokens, https://www.fastmail.help/hc/en-us/articles/5254602856719-API-tokens · [F3] Fastmail help, Account limits, https://www.fastmail.help/hc/en-us/articles/1500000277382 · [F4] example session output (unofficial), https://github.com/joelparkerhenderson/demo-fastmail-api-jmap · [F5] 1Password blog, "How and why we built Masked Email with JMAP", https://1password.com/blog/making-masked-email-with-jmap · RFC 8620 sections 2 and 7.3.

## Push feature (web push with previews)

Design: `design/push.md` in the coordinator's checkout. Bulwark registers browsers at `/relay/api/push/*` (relay-compatible) and creates its JMAP `PushSubscription`s through the gateway, which answers them itself. The gateway keeps one PushSubscription of its own per account in legacy-proxy (only while the account has an active device; `PUSH_UPSTREAM_ALWAYS` overrides), receives its StateChanges at `/internal/push/jmap/:hookId`, and sends RFC 8291 Web Push with sender, subject and a 200-character preview.

- **Finding new mail (plain JMAP):** on `EmailDelivery`, `Email/changes` from the last Email state the gateway processed, then `Email/get` of the created ids, keeping unseen, non-junk, non-draft messages in the Inbox. Without a known state, or on `cannotCalculateChanges`, it queries the newest unseen Inbox mail instead. The reconcile sweep (`PUSH_RECONCILE_INTERVAL_S`, default 300 s) runs that query too, as the safety net for missed StateChanges. Claims in `push_notified` make every message announce at most once. Transient errors are retried after 5 s and 30 s; there are no timing workarounds for a particular upstream.
- **IMAP connections on legacy-proxy** (Gandi caps concurrent IMAP sessions per mailbox):
  - **1 IDLE connection** per account while the gateway's upstream PushSubscription exists, i.e. while at least one device has push enabled.
  - **At most 1 pooled connection at a time** for the push path: per account it runs one JMAP request at a time (event runs and sweeps share a single flight), and legacy-proxy borrows a connection per method. `Email/changes` and `PushSubscription/*` need none; `Mailbox/query`, `Email/query` and `Email/get` borrow one from the per-account pool.
  - The pool itself is legacy-proxy's: up to 3 interactive + 2 bulk connections per account, shared with Bulwark's own traffic. Worst case for one account is therefore 1 IDLE + 5 pooled = 6 sessions, of which push adds the IDLE one.
- **Anonymous registrations** (`register/web` is unauthenticated, like the relay): a record stays *pending* until a verified `PushSubscription` points at it, and a pending record not re-registered or verified within **10 minutes** expires: it stops counting and is deleted at the next registration, or by the hourly cleanup (every 12 reconcile ticks) if none comes. At most `PUSH_RELAY_PENDING_PER_SOURCE` (10) pending records per client address (IPv6: per /64) and `PUSH_RELAY_PENDING_MAX` (200) in total; beyond that `register/web` answers 429 (the limits are checked atomically). Re-registering an existing record (Bulwark's enable and daily resync) is never refused. Destroying the last verified `PushSubscription` makes the record pending again. Unverified `PushSubscription`s also expire after 10 minutes (deleted at the account's next create or by the hourly cleanup); Bulwark verifies within 75 s. Refreshing a pending record never moves its quota charge to another address. Cost: while the pending pool is full (e.g. under a distributed flood), enabling push on a *new* device answers 429 until records expire; existing devices are unaffected. Writes are also limited to 30 per minute per client address.
- **Sending:** push-service redirects are never followed (a 3xx counts as a rejection; three in a row mark the endpoint gone), and every endpoint is checked against the current `PUSH_ENDPOINT_HOSTS` (https, default port, no user info) before each send, so removing a host stops sends to records registered earlier.
- **Config:** `PUSH_VAPID_PUBLIC_KEY`/`PUSH_VAPID_PRIVATE_KEY`/`PUSH_VAPID_SUBJECT` (generate with `npm run cli -- push:vapid-keys`), `PUSH_INTERNAL_BASE_URL`, `PUSH_ENDPOINT_HOSTS`; the rest are in `.env.example`. Counters are logged as `push stats` lines; each push logs `latencyMs` (newest message's `receivedAt` to send) and `eventLatencyMs` (StateChange to send).

### AI summaries (Phase 5)

With `SUMMARY_ENABLED=true` the gateway follows the preview push with a quiet replacement:

1. The preview push goes out at once, unchanged.
2. The newest message of the run is summarised through an **OpenAI-compatible** `POST <SUMMARY_API_URL>/chat/completions` (`SUMMARY_MODEL`, optional `SUMMARY_API_KEY`, `SUMMARY_TIMEOUT_MS` default 120000). The input is the message's text body from the upstream (`Email/get` with `fetchTextBodyValues`), with HTML converted (comments dropped), quoted replies, signatures and URLs removed, and capped at 1,600 characters. The protocol is prompt v3 of `design/summaries` (the Phase 5a benchmark, Qwen3.5-4B): the fixed system prompt, two fixed few-shot exchanges, then the email; the user message names the language (`Finnish` or `English`, a stopword heuristic in the gateway). The request sets `temperature: 0`, `max_tokens: 120`, `chat_template_kwargs: {enable_thinking: false}` and a `response_format` JSON schema, so the answer is `{"ai_instructions": bool, "summary": string}`.
3. The replacement push is the same payload (same `emailIds`, same Topic) plus `email.summary` (≤ 200 characters, plain text) and `renotify: false`. Our Bulwark `sw.js` swaps the text of the notification with the same tag without alerting again.
4. **Apple's push service** (`*.push.apple.com`: Safari, iOS Home Screen web apps) gets the replacement no sooner than `SUMMARY_APPLE_MIN_GAP_MS` (default 35000, 0 = no wait) after the preview; other devices get it at once. WebKit never replaces a notification by tag, so the service worker shows the summary and closes the preview itself, and WebKit refuses `close()` on a notification younger than 30 s. Mail read during the wait is re-checked and skipped; a newer message aborts the wait. The wait holds the summary queue (at most the gap).

Rules:
- One summary at a time, gateway-wide. Per account only the newest message: a newer push replaces a queued job and aborts a running one.
- Mail that is read, junked or moved out of the Inbox is skipped, checked before the model call and again before the push (the same rules as the preview push).
- On timeout, an error or a doubtful answer, nothing more is sent and the preview stays.
- **Safety:** the email is untrusted. The system prompt and few-shot block are fixed and the email goes into the last user message between `<email>` delimiters it cannot forge; no URL reaches the model (`[link]`). If the model reports `ai_instructions: true`, the push carries a fixed, localised notice instead of anything the model wrote (fi: "Viestissä on tekoälylle piilotettuja ohjeita, mikä viittaa huijaukseen. Avaa se varoen.", en: "This email hides instructions aimed at an AI, which suggests phishing. Open it with care."). Otherwise URLs, e-mail addresses, common-TLD domains, `[link]` and markdown are stripped from the summary and it is cut to 200 characters; what remains is still dropped if it has links or host names, prompt-injection or role markers, or is a refusal. An answer that is neither JSON nor a truncated JSON summary is dropped.
- Results are cached per message in `push_summary` (migration 210, sealed under an HKDF purpose key, pruned after 7 days). Rejected answers are cached too; timeouts and errors are not.
- Counters `summary_*` appear in the `push stats` lines. Each replacement logs `push: summary pushed` with `modelMs` and `flagged`; rejections log `push: summary rejected` with the reason; flagged mail is counted in `summary_flagged`. Mail content is never logged.

## Container image

`docker build -t webmail-gateway .` gives a multi-stage image running as the non-root `node` user with a `HEALTHCHECK` on `/healthz`. CI pushes `ghcr.io/wnt/webmail-gateway` from `main`.

## Contract

The binding contract for layout, module signatures, migration ranges and routes is `COORDINATION.md` in the coordinator's checkout (`/home/wnt/webmail/COORDINATION.md`); change it only through the coordinator.
