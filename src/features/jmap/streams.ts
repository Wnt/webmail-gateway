// Byte limits for streamed bodies and the registry of open EventSource streams
// (design/jmap.md section 5).
import { Transform, type TransformCallback } from "node:stream";

export class SizeLimitError extends Error {
  constructor(readonly limit: number) {
    super(`body exceeds ${limit} bytes`);
    this.name = "SizeLimitError";
  }
}

/** Passes bytes through and fails once more than `limit` went by. `bytes` is the running count. */
export class ByteCounter extends Transform {
  bytes = 0;
  constructor(private readonly limit: number) {
    super();
  }
  override _transform(chunk: Buffer, _enc: BufferEncoding, cb: TransformCallback): void {
    this.bytes += chunk.length;
    if (this.bytes > this.limit) cb(new SizeLimitError(this.limit));
    else cb(null, chunk);
  }
}

export interface SseHandle {
  accountId: string;
  /** sha256 hex of the client's bearer token, when it used one (matches hooks' TokenRevokedEvent.tokenIds). */
  tokenId?: string;
  /** The OAuth grant behind the token: revoking the grant ends the stream. */
  grantId?: string;
  /** End the stream cleanly (max age, shutdown, revocation). */
  end(reason: string): void;
  /** Check the stream's access again (the revocation feed was down) and end it if it is gone. */
  recheck?(): Promise<void>;
}

export class SseRegistry {
  private readonly byAccount = new Map<string, Set<SseHandle>>();
  private total = 0;

  constructor(
    private readonly maxPerAccount: number,
    private readonly maxTotal: number,
  ) {}

  /** Reserve a slot; false when a cap is reached. */
  add(h: SseHandle): boolean {
    const set = this.byAccount.get(h.accountId) ?? new Set<SseHandle>();
    if (set.size >= this.maxPerAccount || this.total >= this.maxTotal) return false;
    set.add(h);
    this.byAccount.set(h.accountId, set);
    this.total++;
    return true;
  }

  remove(h: SseHandle): void {
    const set = this.byAccount.get(h.accountId);
    if (!set?.delete(h)) return;
    this.total--;
    if (set.size === 0) this.byAccount.delete(h.accountId);
  }

  /** End every stream of one account (for revocation, D8). */
  endAccount(accountId: string, reason: string): void {
    for (const h of [...(this.byAccount.get(accountId) ?? [])]) h.end(reason);
  }

  /** End the streams opened with one of these tokens (an OAuth grant was revoked, D8). */
  endTokens(accountId: string, tokenIds: ReadonlySet<string>, reason: string): void {
    for (const h of [...(this.byAccount.get(accountId) ?? [])]) {
      if (h.tokenId !== undefined && tokenIds.has(h.tokenId)) h.end(reason);
    }
  }

  /** End the streams of a revoked grant (any of its tokens), or with `tokensOnly` those of the listed tokens. */
  endRevoked(e: { accountId: string; grantId: string; tokenIds: readonly string[]; tokensOnly?: boolean }, reason: string): void {
    const tokens = new Set(e.tokenIds);
    for (const h of [...(this.byAccount.get(e.accountId) ?? [])]) {
      const byToken = h.tokenId !== undefined && tokens.has(h.tokenId);
      if (byToken || (!e.tokensOnly && h.grantId === e.grantId)) h.end(reason);
    }
  }

  /** Every stream rechecks its access (the revocation feed changed state, so notices may have been missed). */
  recheckAll(): void {
    for (const set of [...this.byAccount.values()]) for (const h of [...set]) void h.recheck?.();
  }

  endAll(reason: string): void {
    for (const set of [...this.byAccount.values()]) for (const h of [...set]) h.end(reason);
  }

  count(accountId?: string): number {
    return accountId === undefined ? this.total : (this.byAccount.get(accountId)?.size ?? 0);
  }
}
