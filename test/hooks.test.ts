import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Principal } from "../src/core/auth-context.js";
import {
  emitNewMail,
  handlePushSubscription,
  JmapMethodError,
  onNewMail,
  registerPushSubscriptionHandler,
  resetHooks,
  type NewMailEvent,
} from "../src/core/hooks.js";

const event: NewMailEvent = { emailId: "e1", threadId: "t1", from: "A <a@x.fi>", subject: "Hi", preview: "hello" };
const principal: Principal = { accountId: "acc", email: "a@x.fi", scopes: [], via: "basic" };

beforeEach(() => resetHooks());

describe("new-mail bus", () => {
  it("delivers to every listener with the account id", async () => {
    const a = vi.fn();
    const b = vi.fn(async () => {});
    onNewMail(a);
    onNewMail(b);
    await emitNewMail("acc-1", event);
    expect(a).toHaveBeenCalledWith("acc-1", event);
    expect(b).toHaveBeenCalledWith("acc-1", event);
  });

  it("unsubscribes", async () => {
    const a = vi.fn();
    const off = onNewMail(a);
    off();
    await emitNewMail("acc", event);
    expect(a).not.toHaveBeenCalled();
  });

  it("a failing listener (sync or async) does not stop the others or reject the emit", async () => {
    const ok = vi.fn();
    onNewMail(() => {
      throw new Error("sync boom");
    });
    onNewMail(async () => {
      throw new Error("async boom");
    });
    onNewMail(ok);
    await expect(emitNewMail("acc", event)).resolves.toBeUndefined();
    expect(ok).toHaveBeenCalledOnce();
  });

  it("emit with no listeners is fine", async () => {
    await expect(emitNewMail("acc", event)).resolves.toBeUndefined();
  });
});

describe("PushSubscription handler", () => {
  it("answers forbidden when nothing is registered", async () => {
    await expect(handlePushSubscription(principal, "PushSubscription/get", {})).rejects.toMatchObject({
      type: "forbidden",
    });
    await expect(handlePushSubscription(principal, "PushSubscription/get", {})).rejects.toBeInstanceOf(JmapMethodError);
  });

  it("routes to the registered handler with principal, method and args", async () => {
    const h = vi.fn(async () => ({ list: [] }));
    registerPushSubscriptionHandler(h);
    const out = await handlePushSubscription(principal, "PushSubscription/get", { ids: null });
    expect(out).toEqual({ list: [] });
    expect(h).toHaveBeenCalledWith(principal, "PushSubscription/get", { ids: null });
  });

  it("propagates handler JMAP errors; unregister restores forbidden", async () => {
    const off = registerPushSubscriptionHandler(async () => {
      throw new JmapMethodError("invalidArguments", "bad");
    });
    await expect(handlePushSubscription(principal, "PushSubscription/set", {})).rejects.toMatchObject({
      type: "invalidArguments",
      message: "bad",
    });
    off();
    await expect(handlePushSubscription(principal, "PushSubscription/set", {})).rejects.toMatchObject({
      type: "forbidden",
    });
  });
});
