import type { Config } from "../../config.js";
import { constantTimeEqual, sha256hex } from "./util.js";

/** The scope every Bulwark token gets (D7/A2). MCP later adds `mail.read`, `mail.organize`, `mail.send`. */
export const SCOPE_MAIL = "mail";
export const KNOWN_SCOPES: readonly string[] = [SCOPE_MAIL];
/** OIDC scopes Bulwark sends by default; accepted and dropped. */
export const IGNORED_SCOPES: readonly string[] = ["openid", "email", "profile", "offline_access"];

export interface OAuthClient {
  id: string;
  /** sha256 hex of the client secret; null for a disabled (unconfigured) confidential client, and for a public one. */
  secretHash: string | null;
  /**
   * A public client (RFC 6749 section 2.1, `token_endpoint_auth_method:
   * none`): a native app that cannot keep a secret. It identifies itself by
   * `client_id` alone and must never present a secret; PKCE (required for
   * every client) and the exact redirect URI bind its codes.
   */
  public?: boolean;
  /** The name the sign-in page shows for a client other than the webmail on this origin. */
  displayName?: { fi: string; en: string };
  /** Exact redirect URIs, where `*` stands for exactly one path segment. */
  redirectUris: readonly string[];
  postLogoutRedirectUris: readonly string[];
  allowedScopes: readonly string[];
  defaultScopes: readonly string[];
  /**
   * A first-party client on this origin may sign in through the passkey
   * challenge endpoints (`/auth/fp/*`, routes.ts) without leaving its page.
   * Only Bulwark, the webmail served from this very origin, is.
   */
  firstParty?: boolean;
}

/** The native iPhone app's client id (design/ios-native-app.md, "Sign-in"). */
export const IOS_CLIENT_ID = "madekivi-ios";

/**
 * Static registry (no DB until MCP's dynamic clients, §12 of the design).
 * Bulwark's callback is `<base>/<locale>/auth/callback` for each of its locales.
 * The iPhone app signs in in the system browser sheet and comes back on a
 * private-use URI scheme (RFC 8252 section 7.1): its bundle id, and the
 * free-team development build's.
 */
export function buildClients(config: Pick<Config, "publicBaseUrl" | "auth">): Map<string, OAuthClient> {
  const base = config.publicBaseUrl;
  const bulwark: OAuthClient = {
    id: "bulwark",
    secretHash: config.auth.bulwarkClientSecret ? sha256hex(config.auth.bulwarkClientSecret) : null,
    redirectUris: [`${base}/*/auth/callback`],
    postLogoutRedirectUris: [`${base}/`, `${base}/login`],
    allowedScopes: [SCOPE_MAIL],
    defaultScopes: [SCOPE_MAIL],
    firstParty: true,
  };
  const ios: OAuthClient = {
    id: IOS_CLIENT_ID,
    secretHash: null,
    public: true,
    redirectUris: ["fi.madekivi.mail:/oauth/callback", "fi.madekivi.mail.dev:/oauth/callback"],
    postLogoutRedirectUris: [],
    allowedScopes: [SCOPE_MAIL],
    defaultScopes: [SCOPE_MAIL],
    displayName: { fi: "Madekivi Mail iPhonelle", en: "Madekivi Mail for iPhone" },
  };
  return new Map([
    [bulwark.id, bulwark],
    [ios.id, ios],
  ]);
}

/** Bulwark locales are `xx` or `xx-YY` (`i18n/routing.ts`); the `*` segment accepts exactly that. */
const LOCALE_SEGMENT = String.raw`[a-z]{2}(?:-[A-Za-z]{2,4})?`;

/**
 * Exact match (legacy-proxy's `redirectAllowed`): the URI must be in the form a
 * browser sends (`new URL(uri).href === uri`), so dot segments, backslashes and
 * percent-encoded slashes cannot land the code elsewhere. No query, no fragment.
 * A private-use scheme URI (`fi.madekivi.mail:/oauth/callback`) matches only
 * itself: the scheme is lower-cased by the parser, a `//host` form, another
 * path or a trailing slash is a different string.
 */
export function redirectAllowed(client: OAuthClient, uri: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }
  if (parsed.href !== uri || parsed.search || parsed.hash || parsed.username || parsed.password) return false;
  return client.redirectUris.some((pattern) => {
    const re = pattern
      .split("*")
      .map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
      .join(LOCALE_SEGMENT);
    return new RegExp(`^${re}$`).test(uri);
  });
}

export function postLogoutAllowed(client: OAuthClient, uri: string): boolean {
  return client.postLogoutRedirectUris.includes(uri);
}

export function clientSecretMatches(client: OAuthClient, secret: string): boolean {
  if (client.public || !client.secretHash) return false;
  return constantTimeEqual(sha256hex(secret), client.secretHash);
}

export type ScopeResult = { ok: true; scopes: string[] } | { ok: false };

/** Drop the OIDC scopes, reject unknown ones, default when empty, and clamp to the client's allowed set. */
export function resolveScopes(client: OAuthClient, requested: readonly string[]): ScopeResult {
  const kept = requested.filter((s) => !IGNORED_SCOPES.includes(s));
  if (kept.some((s) => !KNOWN_SCOPES.includes(s) || !client.allowedScopes.includes(s))) return { ok: false };
  return { ok: true, scopes: kept.length ? [...new Set(kept)] : [...client.defaultScopes] };
}
