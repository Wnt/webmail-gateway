// core/upstream: the mail server behind the gateway (COORDINATION.md D14).
// `getUpstream(ctx)` returns the one instance for the context's config:
// `UPSTREAM_KIND=legacy` (legacy-proxy) or `jmap` (a native JMAP server).
import type { Config } from "../../config.js";
import type { CoreContext } from "../../types.js";
import { JmapUpstream } from "./jmap.js";
import { LegacyUpstream } from "./legacy.js";
import type { Upstream } from "./types.js";

export * from "./types.js";
export { UpstreamError, toUpstreamError } from "./http.js";
export { LegacyUpstream, LEGACY_CAPABILITIES, LEGACY_TEMPLATES } from "./legacy.js";
export { JmapUpstream } from "./jmap.js";
export { watchStateChanges, type StateChange, type Watch, type WatchOptions } from "./events.js";

type Ctx = Pick<CoreContext, "config" | "db" | "log" | "fetch">;

const instances = new WeakMap<Config, Upstream>();

/** The upstream for `ctx.config`, created on first use and shared by every feature. */
export function getUpstream(ctx: Ctx): Upstream {
  let u = instances.get(ctx.config);
  if (!u) {
    u = ctx.config.upstream.kind === "jmap" ? new JmapUpstream(ctx) : new LegacyUpstream(ctx);
    instances.set(ctx.config, u);
  }
  return u;
}

/** Close the upstream's connections (app shutdown). The next `getUpstream` creates a fresh one. */
export async function closeUpstream(ctx: Pick<CoreContext, "config">): Promise<void> {
  const u = instances.get(ctx.config);
  if (!u) return;
  instances.delete(ctx.config);
  await u.close();
}
