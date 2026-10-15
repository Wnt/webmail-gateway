// JMAP API request handling: validation and the PushSubscription batch split
// (design/jmap.md section 6). Pure logic; transport is injected.
import { JmapMethodError } from "../../core/hooks.js";
import { LEGACY_CAPABILITIES } from "../../core/upstream/index.js";
import { harvestCreatedIds, RefError, resolveArgs, type Args, type CreatedIds, type MethodResponse, type Prior } from "./refs.js";

export interface Envelope {
  using: string[];
  methodCalls: [string, Args, string][];
  createdIds?: Record<string, string>;
}

export interface ResponseEnvelope {
  methodResponses: MethodResponse[];
  sessionState: string;
  createdIds?: Record<string, string>;
}

/** Capabilities legacy-proxy accepts in `using` (the legacy upstream's set). */
export const KNOWN_CAPABILITIES: ReadonlySet<string> = LEGACY_CAPABILITIES;

const CORE = "urn:ietf:params:jmap:core";

/** Calls that never reach legacy-proxy. Case-insensitive on purpose: a variant spelling must not slip through. */
export const isPushCall = (name: string): boolean => /^pushsubscription\//i.test(name);

export type Validation =
  | { ok: true; env: Envelope }
  | { ok: false; status: number; type: string; extra?: Record<string, unknown> };

const isObj = (v: unknown): v is Args => !!v && typeof v === "object" && !Array.isArray(v);

/**
 * RFC 8620 section 3.3 Request shape, call count, and known capabilities:
 * `known` is the upstream's set, `true` the legacy set, `false` no check.
 */
export function validateEnvelope(body: unknown, maxCalls: number, known: boolean | ReadonlySet<string>): Validation {
  const notRequest = { ok: false as const, status: 400, type: "urn:ietf:params:jmap:error:notRequest" };
  if (!isObj(body)) return notRequest;
  const { using, methodCalls, createdIds } = body;
  if (!Array.isArray(using) || !using.every((u) => typeof u === "string")) return notRequest;
  if (!Array.isArray(methodCalls)) return notRequest;
  for (const c of methodCalls) {
    if (!Array.isArray(c) || c.length !== 3 || typeof c[0] !== "string" || !isObj(c[1]) || typeof c[2] !== "string") {
      return notRequest;
    }
  }
  if (createdIds !== undefined && (!isObj(createdIds) || !Object.values(createdIds).every((v) => typeof v === "string"))) {
    return notRequest;
  }
  if (methodCalls.length > maxCalls) {
    return { ok: false, status: 400, type: "urn:ietf:params:jmap:error:limit", extra: { limit: "maxCallsInRequest" } };
  }
  if (known !== false) {
    const set = known === true ? KNOWN_CAPABILITIES : known;
    const bad = (using as string[]).find((u) => !set.has(u));
    if (bad !== undefined) {
      return { ok: false, status: 400, type: "urn:ietf:params:jmap:error:unknownCapability", extra: { detail: `Unknown capability: ${bad}` } };
    }
  }
  return { ok: true, env: body as unknown as Envelope };
}

/** A request-level failure of the first forwarded batch: relayed to the client as-is. */
export class ForwardRequestError extends Error {
  constructor(
    readonly status: number,
    readonly body: unknown,
  ) {
    super(`legacy-proxy answered ${status}`);
    this.name = "ForwardRequestError";
  }
}

export interface SplitDeps {
  /** POST a sub-request to legacy-proxy. Throws `ForwardRequestError` for a non-2xx answer. */
  forward(env: Envelope): Promise<ResponseEnvelope>;
  /** core/hooks.handlePushSubscription bound to the principal. */
  push(method: string, args: Args): Promise<Args>;
  /** sessionState to report when no call was forwarded. */
  sessionState(): Promise<string>;
}

export interface SplitResult {
  response: ResponseEnvelope;
  /** How many sub-requests went to legacy-proxy and how many calls went to the hook. */
  forwarded: number;
  intercepted: number;
}

const methodError = (type: string, description?: string): Args => (description ? { type, description } : { type });

/**
 * Run a batch that contains PushSubscription calls: maximal runs of forwarded
 * calls go to legacy-proxy as sub-requests, push calls go to the hook, one
 * after another in the client's order. Result references into earlier
 * sub-requests are resolved here; creation ids travel in `createdIds`.
 */
export async function runSplit(env: Envelope, deps: SplitDeps): Promise<SplitResult> {
  const responses: MethodResponse[] = [];
  const prior: Prior = new Map();
  const created: CreatedIds = new Map(Object.entries(env.createdIds ?? {}));
  let sessionState: string | undefined;
  let forwarded = 0;
  let intercepted = 0;
  let executedAny = false;

  const record = (r: MethodResponse) => {
    responses.push(r);
    const list = prior.get(r[2]);
    if (list) list.push(r);
    else prior.set(r[2], [r]);
    harvestCreatedIds(created, r[0], r[1]);
  };

  let batch: [string, Args, string][] = [];
  const flush = async () => {
    if (batch.length === 0) return;
    const calls = batch;
    batch = [];
    const sub: Envelope = { using: env.using, methodCalls: calls, createdIds: Object.fromEntries(created) };
    forwarded++;
    let out: ResponseEnvelope;
    try {
      out = await deps.forward(sub);
    } catch (err) {
      // Nothing has run yet: the whole request fails the way legacy-proxy failed it.
      if (!executedAny) throw err;
      for (const [, , id] of calls) record(["error", methodError("serverFail"), id]);
      executedAny = true;
      return;
    }
    executedAny = true;
    for (const r of out.methodResponses ?? []) record(r);
    for (const [k, v] of Object.entries(out.createdIds ?? {})) if (typeof v === "string") created.set(k, v);
    if (typeof out.sessionState === "string") sessionState = out.sessionState;
  };

  for (const [name, args, id] of env.methodCalls) {
    if (!isPushCall(name)) {
      // References into this pending batch stay for legacy-proxy; earlier ones are inlined.
      const keep = new Set(batch.map((c) => c[2]));
      try {
        batch.push([name, resolveArgs(args, prior, { keepResultOf: keep }), id]);
      } catch (err) {
        if (!(err instanceof RefError)) throw err;
        await flush();
        record(["error", methodError(err.type, err.message), id]);
        executedAny = true;
      }
      continue;
    }

    await flush();
    executedAny = true;
    intercepted++;
    if (!env.using.includes(CORE)) {
      record(["error", methodError("unknownMethod"), id]);
      continue;
    }
    let resolved: Args;
    try {
      resolved = resolveArgs(args, prior, { creation: created });
    } catch (err) {
      if (!(err instanceof RefError)) throw err;
      record(["error", methodError(err.type, err.message), id]);
      continue;
    }
    try {
      record([name, await deps.push(name, resolved), id]);
    } catch (err) {
      if (err instanceof JmapMethodError) record(["error", methodError(err.type, err.message === err.type ? undefined : err.message), id]);
      else record(["error", methodError("serverFail"), id]);
    }
  }
  await flush();

  const response: ResponseEnvelope = { methodResponses: responses, sessionState: sessionState ?? (await deps.sessionState()) };
  // RFC 8620 section 3.4: createdIds is in the response only when the request had it.
  if (env.createdIds !== undefined) response.createdIds = Object.fromEntries(created);
  return { response, forwarded, intercepted };
}
