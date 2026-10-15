import { describe, expect, it, vi } from "vitest";
import { JmapMethodError } from "../../src/core/hooks.js";
import {
  ForwardRequestError,
  isPushCall,
  runSplit,
  validateEnvelope,
  type Envelope,
  type ResponseEnvelope,
  type SplitDeps,
} from "../../src/features/jmap/api.js";
import { jsonPointer, resolveArgs, RefError, type Args, type MethodResponse } from "../../src/features/jmap/refs.js";

const CORE = "urn:ietf:params:jmap:core";
const MAIL = "urn:ietf:params:jmap:mail";

/** A fake legacy dispatcher: answers each call with `{ from: name, args }` (args as received). */
function deps(over: Partial<SplitDeps> = {}) {
  const forwarded: Envelope[] = [];
  const pushed: [string, Args][] = [];
  const d: SplitDeps = {
    forward: async (env) => {
      forwarded.push(structuredClone(env));
      const out: MethodResponse[] = env.methodCalls.map(([n, a, id]) => {
        if (n === "Mailbox/get") return [n, { list: [{ id: "inbox-1" }, { id: "junk-1" }] }, id];
        if (n === "Email/query") return [n, { ids: ["e1", "e2"], got: a }, id];
        if (n === "Email/set") return [n, { created: { k1: { id: "E1" } } }, id];
        return [n, { got: a }, id];
      });
      return { methodResponses: out, sessionState: "s7" } satisfies ResponseEnvelope;
    },
    push: async (method, args) => {
      pushed.push([method, args]);
      if (method === "PushSubscription/get") return { list: [{ id: "p1" }, { id: "p2" }] };
      if (method === "PushSubscription/set" && args["create"]) return { created: { new: { id: "P9" } } };
      return { ok: true, args };
    },
    sessionState: async () => "cached",
    ...over,
  };
  return { d, forwarded, pushed };
}

describe("isPushCall", () => {
  it("matches every spelling of PushSubscription/*", () => {
    for (const n of ["PushSubscription/get", "PushSubscription/set", "pushsubscription/set", "PUSHSUBSCRIPTION/changes"]) {
      expect(isPushCall(n)).toBe(true);
    }
    for (const n of ["Email/get", "XPushSubscription/set", "PushSubscriptionX/get", "Push/set"]) expect(isPushCall(n)).toBe(false);
  });
});

describe("validateEnvelope", () => {
  const ok = { using: [CORE], methodCalls: [["Core/echo", {}, "0"]] };
  it("accepts a Request", () => expect(validateEnvelope(ok, 64, true).ok).toBe(true));
  it.each([
    ["not an object", []],
    ["using missing", { methodCalls: [] }],
    ["bad call", { using: [], methodCalls: [["x", [], "0"]] }],
    ["short call", { using: [], methodCalls: [["x", {}]] }],
    ["bad createdIds", { using: [], methodCalls: [], createdIds: { a: 1 } }],
  ])("rejects %s as notRequest", (_n, body) => {
    expect(validateEnvelope(body, 64, false)).toMatchObject({ ok: false, type: "urn:ietf:params:jmap:error:notRequest" });
  });
  it("enforces maxCallsInRequest", () => {
    const body = { using: [], methodCalls: Array.from({ length: 3 }, (_, i) => ["Core/echo", {}, String(i)]) };
    expect(validateEnvelope(body, 2, false)).toMatchObject({ ok: false, extra: { limit: "maxCallsInRequest" } });
  });
  it("checks capabilities only when asked", () => {
    const body = { using: [CORE, "urn:x"], methodCalls: [] };
    expect(validateEnvelope(body, 64, false).ok).toBe(true);
    expect(validateEnvelope(body, 64, true)).toMatchObject({ ok: false, type: "urn:ietf:params:jmap:error:unknownCapability" });
  });
});

describe("refs", () => {
  it("jsonPointer supports * over arrays and escapes", () => {
    const doc = { list: [{ id: "a", t: ["x"] }, { id: "b", t: ["y", "z"] }], "a/b": { "~": 1 } };
    expect(jsonPointer(doc, "/list/*/id")).toEqual(["a", "b"]);
    expect(jsonPointer(doc, "/list/*/t")).toEqual(["x", "y", "z"]);
    expect(jsonPointer(doc, "/a~1b/~0")).toBe(1);
    expect(jsonPointer(doc, "/list/1/id")).toBe("b");
    expect(jsonPointer(doc, "/nope")).toBeUndefined();
    expect(jsonPointer(doc, "/list/__proto__")).toBeUndefined();
  });

  it("resolves result references, keeps the ones it is told to keep", () => {
    const prior = new Map([["a", [["Email/query", { ids: ["1"] }, "a"] as MethodResponse]]]);
    const args = { "#ids": { resultOf: "a", name: "Email/query", path: "/ids" }, "#x": { resultOf: "b", name: "Q", path: "/" } };
    expect(resolveArgs(args, prior, { keepResultOf: new Set(["b"]) })).toEqual({ ids: ["1"], "#x": args["#x"] });
    expect(() => resolveArgs(args, prior)).toThrow(RefError);
    expect(() => resolveArgs({ "#ids": { resultOf: "a", name: "Email/get", path: "/ids" } }, prior)).toThrow(/did not produce/);
  });

  it("resolves creation references in strings and nested keys, not top-level keys", () => {
    const created = new Map([["k", "REAL"]]);
    const out = resolveArgs({ emailId: "#k", update: { "#k": { a: "#k" } }, keep: "#other" }, new Map(), { creation: created });
    expect(out).toEqual({ emailId: "REAL", update: { REAL: { a: "REAL" } }, keep: "#other" });
  });
});

describe("runSplit", () => {
  it("handles Bulwark's push-only batches without forwarding anything", async () => {
    const { d, forwarded, pushed } = deps();
    const out = await runSplit({ using: [CORE], methodCalls: [["PushSubscription/get", { ids: null }, "0"]] }, d);
    expect(forwarded).toHaveLength(0);
    expect(pushed).toEqual([["PushSubscription/get", { ids: null }]]);
    expect(out.response).toEqual({
      methodResponses: [["PushSubscription/get", { list: [{ id: "p1" }, { id: "p2" }] }, "0"]],
      sessionState: "cached",
    });
  });

  it("runs the design example: order, ids and references across segments", async () => {
    const { d, forwarded, pushed } = deps();
    const env: Envelope = {
      using: [CORE, MAIL],
      methodCalls: [
        ["Mailbox/get", { accountId: "7", ids: null }, "a"],
        ["PushSubscription/get", { ids: null }, "b"],
        ["PushSubscription/set", { "#destroy": { resultOf: "b", name: "PushSubscription/get", path: "/list/*/id" } }, "c"],
        ["Email/query", { accountId: "7", "#inMailbox": { resultOf: "a", name: "Mailbox/get", path: "/list/0/id" } }, "d"],
        ["Email/get", { accountId: "7", "#ids": { resultOf: "d", name: "Email/query", path: "/ids" } }, "e"],
      ],
    };
    const out = await runSplit(env, d);
    expect(out.response.methodResponses.map((r) => [r[0], r[2]])).toEqual([
      ["Mailbox/get", "a"],
      ["PushSubscription/get", "b"],
      ["PushSubscription/set", "c"],
      ["Email/query", "d"],
      ["Email/get", "e"],
    ]);
    expect(forwarded.map((f) => f.methodCalls.map((c) => c[2]))).toEqual([["a"], ["d", "e"]]);
    // d's reference into the first sub-request was inlined; e's reference within the batch was kept
    expect(forwarded[1]!.methodCalls[0]![1]).toEqual({ accountId: "7", inMailbox: "inbox-1" });
    expect(forwarded[1]!.methodCalls[1]![1]).toHaveProperty("#ids");
    expect(pushed[1]).toEqual(["PushSubscription/set", { destroy: ["p1", "p2"] }]);
    expect(out.response.sessionState).toBe("s7");
    expect(out.forwarded).toBe(2);
    expect(out.intercepted).toBe(2);
  });

  it("carries creation ids across sub-requests and into the hook", async () => {
    const { d, forwarded, pushed } = deps();
    const out = await runSplit(
      {
        using: [CORE, MAIL],
        methodCalls: [
          ["Email/set", { create: { k1: {} } }, "1"],
          ["PushSubscription/set", { create: { new: { url: "x", emailId: "#k1" } } }, "2"],
          ["Email/get", { ids: ["#k1", "#new"] }, "3"],
        ],
        createdIds: { pre: "PRE" },
      },
      d,
    );
    expect(forwarded[0]!.createdIds).toEqual({ pre: "PRE" });
    expect(pushed[0]![1]).toEqual({ create: { new: { url: "x", emailId: "E1" } } });
    expect(forwarded[1]!.createdIds).toEqual({ pre: "PRE", k1: "E1", new: "P9" });
    expect(out.response.createdIds).toEqual({ pre: "PRE", k1: "E1", new: "P9" });
  });

  it("answers invalidResultReference locally and keeps going", async () => {
    const { d, forwarded } = deps();
    const out = await runSplit(
      {
        using: [CORE],
        methodCalls: [
          ["PushSubscription/get", {}, "a"],
          ["Email/get", { "#ids": { resultOf: "zz", name: "Email/query", path: "/ids" } }, "b"],
          ["Core/echo", { x: 1 }, "c"],
          ["PushSubscription/set", { "#destroy": { resultOf: "a", name: "Nope/get", path: "/x" } }, "d"],
        ],
      },
      d,
    );
    expect(out.response.methodResponses).toEqual([
      ["PushSubscription/get", expect.any(Object), "a"],
      ["error", { type: "invalidResultReference", description: expect.any(String) }, "b"],
      ["Core/echo", { got: { x: 1 } }, "c"],
      ["error", { type: "invalidResultReference", description: expect.any(String) }, "d"],
    ]);
    expect(forwarded.map((f) => f.methodCalls.map((c) => c[2]))).toEqual([["c"]]);
  });

  it("keeps side responses that share a call id", async () => {
    const { d } = deps({
      forward: async (env) => ({
        methodResponses: [
          [env.methodCalls[0]![0], { created: { s: { id: "S" } } }, env.methodCalls[0]![2]],
          ["Email/set", { updated: { e1: null } }, env.methodCalls[0]![2]],
        ],
        sessionState: "s7",
      }),
    });
    const out = await runSplit(
      {
        using: [CORE],
        methodCalls: [
          ["EmailSubmission/set", {}, "x"],
          ["PushSubscription/get", { "#ids": { resultOf: "x", name: "Email/set", path: "/updated" } }, "y"],
        ],
      },
      d,
    );
    expect(out.response.methodResponses.map((r) => r[0])).toEqual(["EmailSubmission/set", "Email/set", "PushSubscription/get"]);
  });

  it("maps hook errors to method errors (forbidden before push lands, serverFail on crashes)", async () => {
    const { d } = deps({
      push: async (m) => {
        if (m.endsWith("get")) throw new JmapMethodError("forbidden", "PushSubscription/get is not available");
        throw new Error("boom with secret detail");
      },
    });
    const out = await runSplit(
      { using: [CORE], methodCalls: [["PushSubscription/get", {}, "a"], ["PushSubscription/set", {}, "b"]] },
      d,
    );
    expect(out.response.methodResponses).toEqual([
      ["error", { type: "forbidden", description: "PushSubscription/get is not available" }, "a"],
      ["error", { type: "serverFail" }, "b"],
    ]);
  });

  it("needs the core capability for push calls", async () => {
    const { d, pushed } = deps();
    const out = await runSplit({ using: [MAIL], methodCalls: [["PushSubscription/get", {}, "a"]] }, d);
    expect(out.response.methodResponses[0]).toEqual(["error", { type: "unknownMethod" }, "a"]);
    expect(pushed).toHaveLength(0);
  });

  it("relays a request-level error of the first sub-request, but not of a later one", async () => {
    const fail = vi.fn(async () => {
      throw new ForwardRequestError(400, { type: "urn:ietf:params:jmap:error:unknownCapability" });
    });
    const { d } = deps({ forward: fail });
    await expect(
      runSplit({ using: [CORE], methodCalls: [["Core/echo", {}, "a"], ["PushSubscription/get", {}, "b"]] }, d),
    ).rejects.toBeInstanceOf(ForwardRequestError);

    const out = await runSplit({ using: [CORE], methodCalls: [["PushSubscription/get", {}, "a"], ["Core/echo", {}, "b"], ["Email/get", {}, "c"]] }, d);
    expect(out.response.methodResponses.slice(1)).toEqual([
      ["error", { type: "serverFail" }, "b"],
      ["error", { type: "serverFail" }, "c"],
    ]);
  });

  it("property: no push-like call is ever forwarded, and response ids follow request order", async () => {
    const names = ["Core/echo", "Email/get", "PushSubscription/get", "pushSubscription/set", "Mailbox/get", "PUSHSUBSCRIPTION/x"];
    let seed = 42;
    const rnd = (n: number) => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    for (let round = 0; round < 200; round++) {
      const calls: [string, Args, string][] = Array.from({ length: 1 + rnd(8) }, (_, i) => [names[rnd(names.length)]!, {}, `c${i}`]);
      const { d, forwarded } = deps();
      const out = await runSplit({ using: [CORE], methodCalls: calls }, d);
      for (const f of forwarded) for (const c of f.methodCalls) expect(isPushCall(c[0])).toBe(false);
      expect(out.response.methodResponses.map((r) => r[2])).toEqual(calls.map((c) => c[2]));
    }
  });
});
