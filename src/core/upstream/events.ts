// One long-lived RFC 8620 section 7.3 EventSource connection to the upstream
// for an account: parses StateChange events, watches for silence (ping), and
// reconnects with exponential backoff and jitter. Used by the push feature
// when the upstream's push mechanism is "eventSource" (P1: only for accounts
// with an active device).
import { randomInt } from "node:crypto";
import type { FastifyBaseLogger } from "fastify";
import type { Upstream, UpstreamAccount } from "./types.js";

export interface StateChange {
  /** accountId -> { TypeName: state } */
  changed: Record<string, Record<string, string>>;
}

export interface WatchOptions {
  /** Data types to subscribe to (the `types` template variable). */
  types: string[];
  /** Server ping interval asked for, in seconds (RFC 8620: the server may clamp it). */
  pingSec?: number;
  onChange(change: StateChange): void;
  /** Called each time a connection is established (a reconnect may have missed changes). */
  onOpen?(): void;
  log?: FastifyBaseLogger;
  /** Backoff after a failure: first delay and cap, in ms. */
  minBackoffMs?: number;
  maxBackoffMs?: number;
  /** After the credential was rejected. */
  authLostBackoffMs?: number;
}

export interface Watch {
  stop(): void;
  /** Whether a connection is currently open. */
  readonly connected: boolean;
}

const STABLE_MS = 60_000;

/** Parse complete SSE events out of `buf`; returns the unparsed rest. */
export function parseSse(buf: string, onEvent: (event: string, data: string) => void): string {
  for (;;) {
    const m = /\r?\n\r?\n/.exec(buf);
    if (!m) return buf;
    const block = buf.slice(0, m.index);
    buf = buf.slice(m.index + m[0].length);
    let event = "message";
    const data: string[] = [];
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith(":")) continue;
      const i = line.indexOf(":");
      const field = i < 0 ? line : line.slice(0, i);
      const value = i < 0 ? "" : line.slice(i + 1).replace(/^ /, "");
      if (field === "event") event = value;
      else if (field === "data") data.push(value);
    }
    if (data.length) onEvent(event, data.join("\n"));
  }
}

/** Start watching `account`'s upstream EventSource. Never throws; failures reconnect. */
export function watchStateChanges(upstream: Upstream, account: UpstreamAccount, o: WatchOptions): Watch {
  const pingSec = o.pingSec ?? 60;
  const minB = o.minBackoffMs ?? 1_000;
  const maxB = o.maxBackoffMs ?? 300_000;
  const authB = o.authLostBackoffMs ?? 900_000;
  let stopped = false;
  let connected = false;
  let failures = 0;
  let timer: NodeJS.Timeout | null = null;
  let ac: AbortController | null = null;

  const schedule = (ms: number) => {
    if (stopped) return;
    timer = setTimeout(() => {
      timer = null;
      void connect();
    }, ms);
    timer.unref();
  };
  const backoff = () => {
    const base = Math.min(maxB, minB * 2 ** Math.min(failures, 20));
    failures++;
    return Math.round(base / 2 + randomInt(Math.max(1, Math.round(base / 2))));
  };

  async function connect(): Promise<void> {
    if (stopped) return;
    ac = new AbortController();
    const started = Date.now();
    let retryAfterMs: number | null = null;
    let reason = "ended";
    try {
      const r = await upstream.request(account, {
        target: { kind: "eventsource", types: o.types.join(","), closeafter: "no", ping: String(pingSec) },
        method: "GET",
        headers: { accept: "text/event-stream", "accept-encoding": "identity", "cache-control": "no-cache" },
        replayable: true,
        signal: ac.signal,
        headersTimeout: 30_000,
        // Silence watchdog: no byte (not even a ping) for three intervals means a dead connection.
        bodyTimeout: pingSec * 3 * 1000,
      });
      if (r.kind !== "response") {
        o.log?.warn({ accountId: account.id }, "upstream eventsource: credential rejected");
        if (!stopped) schedule(authB);
        return;
      }
      const res = r.res;
      if (res.statusCode !== 200) {
        const ra = Number(res.headers["retry-after"]);
        if (res.statusCode === 429 && Number.isFinite(ra) && ra > 0) retryAfterMs = Math.min(ra * 1000, maxB);
        await res.body.dump();
        reason = `status ${res.statusCode}`;
      } else {
        connected = true;
        o.onOpen?.();
        let buf = "";
        res.body.setEncoding("utf8");
        for await (const chunk of res.body as AsyncIterable<string>) {
          buf = parseSse(buf + chunk, (event, data) => {
            if (event !== "state" && event !== "message") return;
            let msg: unknown;
            try {
              msg = JSON.parse(data);
            } catch {
              return;
            }
            const m = msg as { "@type"?: unknown; changed?: unknown };
            if (m["@type"] === "StateChange" && m.changed && typeof m.changed === "object") {
              o.onChange({ changed: m.changed as StateChange["changed"] });
            }
          });
          if (buf.length > 1_000_000) throw new Error("event too large");
        }
      }
    } catch (err) {
      reason = stopped ? "stopped" : (err as { code?: string }).code ?? (err as Error).message;
    } finally {
      connected = false;
      ac = null;
    }
    if (stopped) return;
    if (Date.now() - started > STABLE_MS) failures = 0;
    const delay = retryAfterMs ?? backoff();
    o.log?.info({ accountId: account.id, reason, retryInMs: delay }, "upstream eventsource closed");
    schedule(delay);
  }

  void connect();
  return {
    stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
      ac?.abort();
    },
    get connected() {
      return connected;
    },
  };
}
