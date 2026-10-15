/**
 * Fixed-window counters per (bucket, key), in process (D12: one replica).
 * `take` counts an attempt and says whether it is over the limit; `retryAfter`
 * is in whole seconds for the `Retry-After` header.
 */
export class RateLimiter {
  private readonly windows = new Map<string, { start: number; count: number }>();

  constructor(
    private readonly now: () => number = Date.now,
    private readonly maxKeys = 10_000,
  ) {}

  take(bucket: string, key: string, max: number, windowMs = 60_000): { ok: true } | { ok: false; retryAfter: number } {
    const t = this.now();
    const k = `${bucket}\0${key}`;
    let w = this.windows.get(k);
    if (!w || t - w.start >= windowMs) {
      if (!w && this.windows.size >= this.maxKeys) this.evict(t, windowMs);
      w = { start: t, count: 0 };
      this.windows.set(k, w);
    }
    w.count += 1;
    if (w.count <= max) return { ok: true };
    return { ok: false, retryAfter: Math.max(1, Math.ceil((w.start + windowMs - t) / 1000)) };
  }

  /** Give back one attempt (a successful login should not count against its address). */
  refund(bucket: string, key: string): void {
    const w = this.windows.get(`${bucket}\0${key}`);
    if (w && w.count > 0) w.count -= 1;
  }

  private evict(t: number, windowMs: number): void {
    for (const [k, w] of this.windows) if (t - w.start >= windowMs) this.windows.delete(k);
    if (this.windows.size >= this.maxKeys) this.windows.delete(this.windows.keys().next().value!);
  }
}
