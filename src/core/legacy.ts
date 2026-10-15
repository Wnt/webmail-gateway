import { getGandiPassword, type Account } from "./accounts.js";
import { emitLegacyRelogin } from "./hooks.js";
import { mintToken } from "./token.js";
import type { CoreContext } from "../types.js";

type Ctx = Pick<CoreContext, "config" | "db" | "log" | "fetch">;
/** The fields of an `Account` that legacy calls need. */
export type LegacyAccount = Pick<Account, "id" | "email" | "legacySlug">;

export const LEGACY_TOKEN_TTL_SEC = 300;
const RELOGIN_TIMEOUT_MS = 30_000;
const JMAP_TIMEOUT_MS = 60_000;

export const JMAP_CORE = "urn:ietf:params:jmap:core";
export const JMAP_MAIL = "urn:ietf:params:jmap:mail";
export const JMAP_SUBMISSION = "urn:ietf:params:jmap:submission";

/** `[method, arguments, callId]` */
export type JmapMethodCall = [string, Record<string, unknown>, string];
export interface JmapResponse {
  methodResponses: [string, Record<string, unknown>, string][];
  sessionState?: string;
  [k: string]: unknown;
}

export class LegacyError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "LegacyError";
  }
}

function envKey(): Buffer {
  const k = Buffer.from(process.env.LEGACY_SESSION_HMAC_KEY ?? "", "base64");
  if (k.length !== 32) throw new LegacyError("LEGACY_SESSION_HMAC_KEY is not set (base64 of 32 bytes)");
  return k;
}

/**
 * A legacy-proxy Bearer token (5 minute TTL) for `slug`/`username`, signed with
 * `LEGACY_SESSION_HMAC_KEY`. `key` defaults to that env var; the gateway itself
 * always passes `config.legacyHmacKey`.
 */
export function mintLegacyToken(slug: string, username: string, key: Buffer = envKey(), nowSec?: number): string {
  return mintToken(key, { accountSlug: slug, username, ttlSec: LEGACY_TOKEN_TTL_SEC }, nowSec);
}

const joinUrl = (base: string, path: string): string => base + (path.startsWith("/") ? path : `/${path}`);

/** Request bodies that can be sent twice. A stream cannot, so it is never retried. */
function replayable(body: RequestInit["body"]): boolean {
  return body == null || typeof body === "string" || body instanceof URLSearchParams || ArrayBuffer.isView(body) || body instanceof ArrayBuffer;
}

async function discard(res: Response): Promise<void> {
  try {
    await res.body?.cancel();
  } catch {
    // already closed
  }
}

// One re-login per account at a time; concurrent 401s share it.
const relogins = new Map<string, Promise<boolean>>();

/**
 * Recreate the account inside legacy-proxy: a Basic-authenticated session
 * request makes it verify the Gandi credentials against IMAP and store them.
 * Returns false when we have no stored password or legacy-proxy rejects it.
 */
export function relogin(ctx: Ctx, account: LegacyAccount): Promise<boolean> {
  return reloginWithBasic(ctx, account);
}

// Shared by `relogin` and the 401 path of `legacyFetch`.
function reloginWithBasic(ctx: Ctx, account: LegacyAccount): Promise<boolean> {
  const inflight = relogins.get(account.id);
  if (inflight) return inflight;
  const p = (async () => {
    const password = await getGandiPassword(ctx, account.id);
    if (password === null) return false;
    const basic = Buffer.from(`${account.email}:${password}`, "utf8").toString("base64");
    const res = await (ctx.fetch ?? fetch)(joinUrl(ctx.config.legacyProxyUrl, "/jmap/session"), {
      headers: { authorization: `Basic ${basic}` },
      signal: AbortSignal.timeout(RELOGIN_TIMEOUT_MS),
    });
    await discard(res);
    if (!res.ok) {
      ctx.log?.warn({ accountId: account.id, status: res.status }, "legacy-proxy Basic re-login rejected");
    } else {
      // Not awaited: listeners (push) may call legacy-proxy themselves.
      void emitLegacyRelogin(account.id);
    }
    return res.ok;
  })().finally(() => relogins.delete(account.id));
  relogins.set(account.id, p);
  return p;
}

/**
 * `fetch` against legacy-proxy as `account`: `path` (with query) is appended to
 * `LEGACY_PROXY_URL` and a fresh Bearer token is minted per attempt. Any
 * `Authorization` header in `init` is replaced.
 *
 * On 401 (legacy-proxy lost its state) it logs in once with Basic and the
 * stored Gandi password, which recreates the account, then retries once.
 * If there is no stored password or the re-login fails, the original 401
 * response is returned. A streaming request body cannot be replayed: the
 * account is still re-logged-in, but the 401 is returned and the caller
 * decides whether to retry.
 */
export async function legacyFetch(
  ctx: Ctx,
  account: LegacyAccount,
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const doFetch = ctx.fetch ?? fetch;
  const url = joinUrl(ctx.config.legacyProxyUrl, path);
  const attempt = (): Promise<Response> => {
    const headers = new Headers(init.headers);
    headers.set("authorization", `Bearer ${mintLegacyToken(account.legacySlug, account.email, ctx.config.legacyHmacKey)}`);
    return doFetch(url, { ...init, headers });
  };

  const first = await attempt();
  if (first.status !== 401) return first;

  const ok = await reloginWithBasic(ctx, account);
  if (!ok || !replayable(init.body)) return first;
  await discard(first);
  return attempt();
}

/**
 * Call JMAP methods on legacy-proxy as `account` (POST `/jmap`) and return the
 * parsed response. Same 401 handling as `legacyFetch`. Throws `LegacyError` on
 * transport failure, non-2xx, or a non-JSON body.
 */
export async function legacyJmap(
  ctx: Ctx,
  account: LegacyAccount,
  methodCalls: JmapMethodCall[],
  using: string[] = [JMAP_CORE, JMAP_MAIL],
): Promise<JmapResponse> {
  let res: Response;
  try {
    res = await legacyFetch(ctx, account, "/jmap", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ using, methodCalls }),
      signal: AbortSignal.timeout(JMAP_TIMEOUT_MS),
    });
  } catch (err) {
    throw new LegacyError(`legacy-proxy request failed: ${(err as Error).message}`);
  }
  if (!res.ok) {
    await discard(res);
    throw new LegacyError(`legacy-proxy answered ${res.status}`, res.status);
  }
  try {
    return (await res.json()) as JmapResponse;
  } catch {
    throw new LegacyError("legacy-proxy returned a non-JSON body", res.status);
  }
}
