// In-memory fixed-window counters (design/jmap.md section 7). One gateway
// replica (D12), so no shared store; a restart resets the windows.

export type Clock = () => number;

interface Window {
  count: number;
  resetAt: number;
}

export interface Bucket {
  key: string;
  limit: number;
}

export class FixedWindowLimiter {
  private readonly windows = new Map<string, Window>();
  private lastSweep = 0;

  constructor(
    private readonly windowMs: number,
    private readonly now: Clock = Date.now,
  ) {}

  private current(key: string): Window | undefined {
    const w = this.windows.get(key);
    if (w && w.resetAt <= this.now()) {
      this.windows.delete(key);
      return undefined;
    }
    return w;
  }

  private sweep(): void {
    const t = this.now();
    if (t - this.lastSweep < 60_000) return;
    this.lastSweep = t;
    for (const [k, w] of this.windows) if (w.resetAt <= t) this.windows.delete(k);
  }

  /** Seconds until every given bucket has room again, or 0 when all of them have room now. */
  blockedFor(buckets: Bucket[]): number {
    let wait = 0;
    for (const b of buckets) {
      const w = this.current(b.key);
      if (w && w.count >= b.limit) wait = Math.max(wait, Math.ceil((w.resetAt - this.now()) / 1000));
    }
    return wait;
  }

  /**
   * Atomically count one hit in every bucket if all of them have room.
   * Returns 0 on success, else the seconds to wait (and nothing is counted).
   */
  tryReserve(buckets: Bucket[]): number {
    this.sweep();
    const wait = this.blockedFor(buckets);
    if (wait > 0) return wait;
    for (const b of buckets) this.hit(b.key);
    return 0;
  }

  /** Count one hit, ignoring the limit. */
  hit(key: string): void {
    const w = this.current(key);
    if (w) w.count++;
    else this.windows.set(key, { count: 1, resetAt: this.now() + this.windowMs });
  }

  /** Undo one hit (a reserved attempt that did not fail). */
  refund(keys: string[]): void {
    for (const k of keys) {
      const w = this.current(k);
      if (w && w.count > 0) w.count--;
    }
  }

  get size(): number {
    return this.windows.size;
  }
}

/** A counting semaphore with a bounded wait. */
export class Semaphore {
  private active = 0;
  private readonly waiters: (() => void)[] = [];

  constructor(private readonly max: number) {}

  /** Resolves to a release function, or null if no slot frees up within `timeoutMs`. */
  acquire(timeoutMs: number): Promise<(() => void) | null> {
    const release = () => {
      this.active--;
      const next = this.waiters.shift();
      if (next) next();
    };
    if (this.active < this.max) {
      this.active++;
      return Promise.resolve(once(release));
    }
    return new Promise((resolve) => {
      const grant = () => {
        clearTimeout(timer);
        this.active++;
        resolve(once(release));
      };
      const timer = setTimeout(() => {
        const i = this.waiters.indexOf(grant);
        if (i >= 0) this.waiters.splice(i, 1);
        resolve(null);
      }, timeoutMs);
      this.waiters.push(grant);
    });
  }
}

function once(fn: () => void): () => void {
  let done = false;
  return () => {
    if (done) return;
    done = true;
    fn();
  };
}
