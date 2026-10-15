import type { FastifyBaseLogger } from "fastify";

/**
 * In-process counters (P5: no metrics endpoint; structured logs instead).
 * `flush` logs the counts since the last flush as one `push stats` line;
 * `get` returns totals since start (or the last `reset`).
 */
export class PushStats {
  private window = new Map<string, number>();
  private totals = new Map<string, number>();

  inc(name: string, by = 1): void {
    if (by === 0) return;
    this.window.set(name, (this.window.get(name) ?? 0) + by);
    this.totals.set(name, (this.totals.get(name) ?? 0) + by);
  }

  get(name: string): number {
    return this.totals.get(name) ?? 0;
  }

  snapshot(): Record<string, number> {
    return Object.fromEntries([...this.totals].sort(([a], [b]) => a.localeCompare(b)));
  }

  reset(): void {
    this.window.clear();
    this.totals.clear();
  }

  flush(log: FastifyBaseLogger): void {
    if (this.window.size === 0) return;
    log.info({ counters: Object.fromEntries([...this.window].sort(([a], [b]) => a.localeCompare(b))) }, "push stats");
    this.window.clear();
  }
}
