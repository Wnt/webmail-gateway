import { pino } from "pino";
import type { Principal } from "./auth-context.js";

const log = pino({ name: "hooks", level: process.env.LOG_LEVEL === "silent" ? "silent" : "warn" });

export interface NewMailEvent {
  emailId: string;
  threadId: string;
  /** `Name <addr>` */
  from: string;
  subject: string;
  /** Plain text, already trimmed by the emitter. */
  preview: string;
}

export type NewMailListener = (accountId: string, event: NewMailEvent) => void | Promise<void>;

const newMailListeners: NewMailListener[] = [];

/** Subscribe to new-mail events. Returns an unsubscribe function. */
export function onNewMail(cb: NewMailListener): () => void {
  newMailListeners.push(cb);
  return () => {
    const i = newMailListeners.indexOf(cb);
    if (i >= 0) newMailListeners.splice(i, 1);
  };
}

/**
 * Deliver a new-mail event to every listener and wait for them. A listener that
 * throws is logged and does not affect the others or the emitter.
 */
export async function emitNewMail(accountId: string, event: NewMailEvent): Promise<void> {
  const results = await Promise.allSettled([...newMailListeners].map(async (cb) => cb(accountId, event)));
  for (const r of results) {
    if (r.status === "rejected") log.error({ err: r.reason, accountId }, "new-mail listener failed");
  }
}

/** A JMAP method-level error (RFC 8620 section 3.6.2): `["error", {type, description}, callId]`. */
export class JmapMethodError extends Error {
  constructor(
    readonly type: string,
    description?: string,
  ) {
    super(description ?? type);
    this.name = "JmapMethodError";
  }
}

/** Handles `PushSubscription/get|set|...`. Returns the method's response arguments. Throw `JmapMethodError` for JMAP errors. */
export type PushSubscriptionHandler = (
  principal: Principal,
  method: string,
  args: Record<string, unknown>,
) => Promise<Record<string, unknown>>;

let pushHandler: PushSubscriptionHandler | null = null;

/** The push feature registers itself here; the last registration wins. Returns an unregister function. */
export function registerPushSubscriptionHandler(fn: PushSubscriptionHandler): () => void {
  pushHandler = fn;
  return () => {
    if (pushHandler === fn) pushHandler = null;
  };
}

/**
 * Called by the JMAP proxy instead of forwarding `PushSubscription/*` to legacy-proxy.
 * Throws `JmapMethodError("forbidden")` when no push feature is registered (D6).
 */
export async function handlePushSubscription(
  principal: Principal,
  method: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (!pushHandler) throw new JmapMethodError("forbidden", `${method} is not available`);
  return pushHandler(principal, method, args);
}

/** Test helper: drop all listeners and the push handler. */
export function resetHooks(): void {
  newMailListeners.length = 0;
  pushHandler = null;
}
