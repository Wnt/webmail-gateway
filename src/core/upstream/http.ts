// HTTP transport to the upstream: one undici Agent (a keep-alive pool per
// origin, so a separate download host such as Fastmail's gets its own), and
// error mapping. undici does not decompress, so gzip passes through untouched.
import { Agent, type Dispatcher } from "undici";
import type { UpstreamResponse } from "./types.js";

/** Transport failure talking to the upstream, mapped to the status the client gets. */
export class UpstreamError extends Error {
  constructor(
    message: string,
    readonly status: 502 | 504,
    readonly code?: string,
  ) {
    super(message);
    this.name = "UpstreamError";
  }
}

export function toUpstreamError(err: unknown): UpstreamError {
  if (err instanceof UpstreamError) return err;
  const code = (err as { code?: string } | null)?.code;
  const timeout = code === "UND_ERR_HEADERS_TIMEOUT" || code === "UND_ERR_CONNECT_TIMEOUT";
  return new UpstreamError(timeout ? "upstream timed out" : "upstream unreachable", timeout ? 504 : 502, code);
}

export function newAgent(): Agent {
  return new Agent({ connections: 256, keepAliveTimeout: 30_000 });
}

export interface SendOptions {
  method: Dispatcher.HttpMethod;
  headers?: Record<string, string>;
  body?: Dispatcher.DispatchOptions["body"];
  signal?: AbortSignal | undefined;
  headersTimeout?: number | undefined;
  bodyTimeout?: number | undefined;
  /** GET only: follow up to this many redirects. Credentials are dropped when the origin changes. */
  maxRedirects?: number;
  /** Each redirect target must pass this, or the request fails with 502 (instead of following it). */
  redirectAllowed?: (next: URL, from: URL) => boolean;
}

const REDIRECTS = new Set([301, 302, 303, 307, 308]);

/** One request to an absolute URL. Throws `UpstreamError` on transport failure. */
export async function send(agent: Dispatcher, url: string, o: SendOptions): Promise<UpstreamResponse> {
  let target = new URL(url);
  let headers = o.headers ?? {};
  for (let hop = 0; ; hop++) {
    let res: UpstreamResponse;
    try {
      res = await agent.request({
        origin: target.origin,
        path: target.pathname + target.search,
        method: o.method,
        headers,
        body: o.body ?? null,
        signal: o.signal ?? null,
        headersTimeout: o.headersTimeout ?? 60_000,
        bodyTimeout: o.bodyTimeout ?? 120_000,
      });
    } catch (err) {
      throw toUpstreamError(err);
    }
    const location = res.headers["location"];
    if (o.method !== "GET" || !REDIRECTS.has(res.statusCode) || typeof location !== "string" || hop >= (o.maxRedirects ?? 0)) {
      return res;
    }
    const next = new URL(location, target);
    if (next.protocol !== "https:" && next.protocol !== "http:") return res;
    await res.body.dump();
    if (o.redirectAllowed && !o.redirectAllowed(next, target)) {
      throw new UpstreamError(`upstream redirected to ${next.origin}, which is not an allowed upstream origin`, 502, "REDIRECT_REFUSED");
    }
    if (next.origin !== target.origin) {
      // Like fetch(): never carry credentials to another origin.
      headers = Object.fromEntries(Object.entries(headers).filter(([k]) => k.toLowerCase() !== "authorization"));
    }
    target = next;
  }
}
