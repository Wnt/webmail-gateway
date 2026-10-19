import webpush from "web-push";
import { onLegacyRelogin, registerPushSubscriptionHandler } from "../../core/hooks.js";
import type { AppContext, CliCommand, FeaturePlugin } from "../../types.js";
import { ApnsSender, type ApnsOptions } from "./apns.js";
import { registerApnsRoutes } from "./apns-routes.js";
import { createPushSubscriptionHandler } from "./jmap-emulation.js";
import { Pipeline, type PipelineOptions } from "./pipeline.js";
import { registerRelayRoutes } from "./relay-routes.js";
import { Sender, type SenderOptions } from "./sender.js";
import { PushStats } from "./stats.js";
import type { SummarizerOptions } from "./summarizer.js";
import { garbageCollect } from "./store.js";
import { UpstreamManager, type ReconcileReason, type UpstreamOptions } from "./upstream.js";

/**
 * Push feature (design/push.md): relay-compatible browser registration under
 * /relay/api/push, emulated JMAP PushSubscription/*, one upstream
 * subscription per account in legacy-proxy, and encrypted Web Push with a
 * from/subject/preview summary for every new INBOX message, optionally
 * followed by a quiet replacement push carrying an AI summary (Phase 5).
 * The native iPhone app's devices register under /relay/api/push/apns and
 * get the same new-mail pushes through APNs, end-to-end encrypted to the
 * device, with the one-time code when the message has one.
 */

export interface PushRuntime {
  stats: PushStats;
  sender: Sender;
  apns: ApnsSender;
  pipeline: Pipeline;
  upstream: UpstreamManager;
  /** Fire-and-forget reconcile of one account (logs its own errors). */
  kick(accountId: string, reason: ReconcileReason): void;
  /** One reconciler pass over every account (what the timer runs). */
  tick(): Promise<void>;
  /** Wait for queued reconciles and pipeline runs (tests). */
  idle(): Promise<void>;
}

export interface PushTestOptions {
  sender?: SenderOptions;
  apns?: ApnsOptions;
  pipeline?: PipelineOptions;
  upstream?: UpstreamOptions;
  summarizer?: SummarizerOptions;
  /** Receives the runtime once the plugin is registered. */
  onRuntime?: (rt: PushRuntime) => void;
}

const GC_EVERY_TICKS = 12;

export function createPushRuntime(ctx: AppContext, opts: PushTestOptions = {}): PushRuntime {
  const stats = new PushStats();
  const sender = new Sender(ctx, stats, opts.sender);
  const apns = new ApnsSender(ctx, stats, opts.apns);
  const pipeline = new Pipeline(ctx, stats, sender, { ...opts.pipeline, summarizer: opts.summarizer ?? opts.pipeline?.summarizer }, apns);
  const upstream = new UpstreamManager(ctx, stats, pipeline, opts.upstream);
  const pending = new Set<Promise<void>>();
  let ticks = 0;

  const kick = (accountId: string, reason: ReconcileReason): void => {
    const p = upstream.reconcile(accountId, reason).finally(() => pending.delete(p));
    pending.add(p);
  };

  const tick = async (): Promise<void> => {
    await upstream.reconcileAll("timer");
    if (++ticks % GC_EVERY_TICKS === 0) {
      await garbageCollect(ctx.db).catch((err) => ctx.log.error({ err }, "push: garbage collection failed"));
    }
    stats.flush(ctx.log);
  };

  const idle = async (): Promise<void> => {
    while (pending.size) await Promise.all([...pending]);
    await pipeline.idle();
  };

  return { stats, sender, apns, pipeline, upstream, kick, tick, idle };
}

/** Build the plugin; tests pass options (fast retries, a runtime callback). */
export function makePushPlugin(opts: PushTestOptions = {}): FeaturePlugin {
  return async (app, ctx) => {
    const rt = createPushRuntime(ctx, opts);
    const cfg = ctx.config.push;
    if (!cfg.vapid) ctx.log.warn("push: VAPID keys not configured - web push disabled");
    if (!cfg.apns.key) ctx.log.warn("push: APNs key not configured (APNS_PRIVATE_KEY, APNS_KEY_ID, APNS_TEAM_ID) - native app devices register, nothing is sent");

    const offHandler = registerPushSubscriptionHandler(
      createPushSubscriptionHandler({ ctx, stats: rt.stats, onChange: (id) => rt.kick(id, "subs-changed") }),
    );
    const offRelogin = onLegacyRelogin((accountId) => {
      rt.pipeline.invalidate(accountId);
      rt.kick(accountId, "relogin");
    });

    await registerRelayRoutes(app, ctx, rt.stats);
    await registerApnsRoutes(app, ctx, { stats: rt.stats, apns: rt.apns, onChange: (id) => rt.kick(id, "subs-changed") });
    rt.upstream.registerInternalRoute(app);

    let timer: NodeJS.Timeout | null = null;
    if (cfg.workerEnabled) {
      // Only a listening server runs the reconciler; `app.inject` tests never start it.
      app.addHook("onListen", async () => {
        void rt.upstream.reconcileAll("startup").catch((err) => ctx.log.error({ err }, "push: startup reconcile failed"));
        timer = setInterval(() => {
          void rt.tick().catch((err) => ctx.log.error({ err }, "push: reconcile tick failed"));
        }, cfg.reconcileIntervalMs);
        timer.unref();
      });
    }

    app.addHook("onClose", async () => {
      if (timer) clearInterval(timer);
      offHandler();
      offRelogin();
      rt.pipeline.stop();
      rt.upstream.stop();
      rt.apns.close();
      rt.stats.flush(ctx.log);
    });

    opts.onRuntime?.(rt);
  };
}

export const pushPlugin: FeaturePlugin = makePushPlugin();

/** CLI commands contributed by this feature (merged into `src/cli.ts`). */
export const pushCliCommands: Record<string, CliCommand> = {
  /** Print a fresh VAPID key pair as env lines, for the gateway Secret. */
  "push:vapid-keys": async (_args: string[], _ctx: AppContext) => {
    const keys = webpush.generateVAPIDKeys();
    process.stdout.write(`PUSH_VAPID_PUBLIC_KEY=${keys.publicKey}\nPUSH_VAPID_PRIVATE_KEY=${keys.privateKey}\n`);
  },
};
