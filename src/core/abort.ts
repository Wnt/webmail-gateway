/**
 * `work`, or a rejection with the signal's reason as soon as `signal` aborts.
 * The caller stops waiting; the work itself goes on, because it may be shared
 * with other callers (a re-login, a session discovery). Its outcome stays
 * handled either way, so a late rejection is never an unhandled one.
 */
export function untilAborted<T>(work: Promise<T>, signal: AbortSignal | null | undefined): Promise<T> {
  if (!signal) return work;
  if (signal.aborted) {
    work.catch(() => undefined);
    return Promise.reject(signal.reason);
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    work.then(
      (v) => {
        signal.removeEventListener("abort", onAbort);
        resolve(v);
      },
      (e) => {
        signal.removeEventListener("abort", onAbort);
        reject(e);
      },
    );
  });
}
