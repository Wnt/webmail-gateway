// The upstream abstraction (COORDINATION.md D14): everything the features need
// from "the mail server behind the gateway", with two first-class
// implementations: `legacy` (legacy-proxy in front of Gandi) and `jmap` (any
// native JMAP server: Fastmail in production, Stalwart on test stacks).
import type { Dispatcher } from "undici";
import type { Account } from "../accounts.js";

export type UpstreamKind = "legacy" | "jmap";

/** The account fields an upstream needs. */
export type UpstreamAccount = Pick<Account, "id" | "email" | "legacySlug">;

/** `[method, arguments, callId]` */
export type JmapMethodCall = [string, Record<string, unknown>, string];
export interface JmapResponse {
  methodResponses: [string, Record<string, unknown>, string][];
  sessionState?: string;
  createdIds?: Record<string, string>;
  [k: string]: unknown;
}

/** A JMAP Session object (RFC 8620 section 2), as the upstream returned it. */
export type JmapSession = Record<string, unknown> & {
  capabilities: Record<string, unknown>;
  accounts: Record<string, unknown>;
  apiUrl: string;
};

/**
 * What a request is for. The upstream resolves it to a URL: legacy-proxy's
 * fixed paths, or the native server's session URL templates (RFC 6570 level 1).
 * Values are decoded; the upstream encodes them for its own template.
 */
export type Target =
  | { kind: "session" }
  | { kind: "api" }
  | { kind: "upload"; accountId: string }
  | { kind: "download"; accountId: string; blobId: string; type: string; name: string; /** extra raw query, no `?` */ query?: string }
  | { kind: "eventsource"; types?: string; closeafter?: string; ping?: string };

export type UpstreamResponse = Dispatcher.ResponseData;

export interface UpstreamRequest {
  target: Target;
  method: Dispatcher.HttpMethod;
  headers?: Record<string, string>;
  body?: Dispatcher.DispatchOptions["body"];
  /** Whether the body may be sent twice (it may not when it is a stream). */
  replayable: boolean;
  signal?: AbortSignal;
  headersTimeout?: number;
  bodyTimeout?: number;
}

export type UpstreamResult =
  | { kind: "response"; res: UpstreamResponse }
  /** The upstream no longer accepts the account's stored credential: the caller answers 401. */
  | { kind: "authLost" }
  /** A non-replayable request got 401, the credential was refreshed, and the client should retry. */
  | { kind: "retryLater" };

/** Result of checking a credential for the bootstrap CLI. */
export type VerifyResult =
  | { ok: true }
  | { ok: false; reason: "rejected" | "mismatch" | "unreachable" | "error"; detail?: string };

/** How the push feature learns about new mail from this upstream. */
export type PushMechanism =
  /** RFC 8620 PushSubscription to our /internal/push/jmap/:hookId (legacy-proxy; needs the upstream to reach us). */
  | "pushSubscription"
  /** One long-lived RFC 8620 EventSource per account (no inbound exposure). */
  | "eventSource";

export interface Upstream {
  readonly kind: UpstreamKind;
  readonly pushMechanism: PushMechanism;
  /** Whether JMAP_PASSWORD_MODE (Basic, verified by the upstream) can work. */
  readonly supportsPasswordMode: boolean;

  /** A request as `account`. Throws `UpstreamError` on transport failures. */
  request(account: UpstreamAccount, req: UpstreamRequest): Promise<UpstreamResult>;
  /** The upstream's (unrewritten) session for `account`; cached briefly unless `fresh`. Throws `UpstreamCallError`. */
  session(account: UpstreamAccount, opts?: { fresh?: boolean }): Promise<JmapSession>;
  /** POST JMAP method calls as `account` and parse the answer. Throws `UpstreamCallError` (`UpstreamTooLargeError` past `opts.maxResponseBytes`). */
  jmap(account: UpstreamAccount, methodCalls: JmapMethodCall[], using?: string[], opts?: JmapCallOptions): Promise<JmapResponse>;
  /** Capability URIs the upstream accepts in `using`. */
  knownCapabilities(account: UpstreamAccount): Promise<ReadonlySet<string>>;
  /** Before a non-replayable request: make sure the upstream still accepts the account. */
  ensureKnown(account: UpstreamAccount): Promise<"ok" | "authLost" | "error">;

  /** Whether the account has a stored credential this upstream can use. */
  hasCredential(accountId: string): Promise<boolean>;
  /** Bootstrap: check `secret` (a Gandi password, or an upstream API token/password) for `email`. Nothing is stored. */
  verifyCredential(email: string, secret: string): Promise<VerifyResult>;
  /** Bootstrap: store `secret` sealed for the account. */
  storeCredential(account: UpstreamAccount, secret: string): Promise<void>;
  /** What the bootstrap CLI asks for on the terminal. */
  readonly credentialPrompt: string;

  /** Subscribe to "the upstream rejected this account's credential". Returns an unsubscribe function. */
  onAuthLost(cb: (accountId: string) => void): () => void;
  /** Drop cached per-account state (tokens, sessions). */
  forget(accountId: string): void;
  close(): Promise<void>;
}

export const JMAP_CORE = "urn:ietf:params:jmap:core";
export const JMAP_MAIL = "urn:ietf:params:jmap:mail";
export const JMAP_SUBMISSION = "urn:ietf:params:jmap:submission";

/** The upstream answered a JMAP call with a non-2xx status, an unparseable body, or not at all. */
export class UpstreamCallError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "UpstreamCallError";
  }
}

/** The response body was larger than the caller's `maxResponseBytes`; no more of it was read. */
export class UpstreamTooLargeError extends UpstreamCallError {
  constructor(limit: number) {
    super(`upstream response over ${limit} bytes`);
    this.name = "UpstreamTooLargeError";
  }
}

/** Options for one `Upstream.jmap` call. */
export interface JmapCallOptions {
  /** Read at most this many bytes of the response body; past it the call fails with `UpstreamTooLargeError`. */
  maxResponseBytes?: number;
  /** Abort the call (e.g. the client that asked for it went away). */
  signal?: AbortSignal;
}
