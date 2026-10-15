import { describe, expect, it } from "vitest";
import { parsePushConfig } from "../../src/features/push/config.js";
import { relayIdFromUrl } from "../../src/features/push/jmap-emulation.js";
import {
  cleanPreview,
  cleanSubject,
  cleanText,
  fitPayload,
  formatFrom,
  minimalPayload,
  payloadBytes,
  truncate,
  type PushPayload,
} from "../../src/features/push/payload.js";
import { topicFor } from "../../src/features/push/sender.js";
import { endpointAllowed, hostAllowed, isValidSubscriptionId, isValidWebPushSubscription } from "../../src/features/push/validation.js";

describe("cleaning", () => {
  it("drops control and format characters, keeps ZWJ, collapses whitespace", () => {
    expect(cleanText("  a\tb\r\n\u0000c\u200bd\u00ade  ")).toBe("a b cde");
    expect(cleanText("x\u2028y")).toBe("x y");
    const family = "\u{1F468}\u200d\u{1F469}\u200d\u{1F467}";
    expect(cleanText(`hi ${family}`)).toBe(`hi ${family}`);
    expect(cleanText(null)).toBe("");
  });

  it("strips a leading style sheet and preheader padding like Bulwark", () => {
    expect(cleanPreview("@media screen{.a{color:red}} Hello there")).toBe("Hello there");
    expect(cleanPreview(".x{display:none} Real text")).toBe("Real text");
    expect(cleanPreview("\u034f\u200c \u00a0 Sale starts now")).toBe("Sale starts now");
    expect(cleanPreview("...")).toBe("");
    expect(cleanPreview("Meet at {time} tomorrow")).toBe("Meet at {time} tomorrow");
  });

  it("truncates to the UTF-16 limit on a grapheme boundary with an ellipsis", () => {
    expect(truncate("short", 200)).toBe("short");
    const words = "word ".repeat(100).trim();
    const t = truncate(words, 200);
    expect(t.length).toBeLessThanOrEqual(200);
    expect(t.endsWith("word\u2026")).toBe(true);
    const emoji = "\u{1F600}".repeat(150); // 300 code units
    const e = truncate(emoji, 200);
    expect(e.length).toBeLessThanOrEqual(200);
    expect(e.endsWith("\u2026")).toBe(true);
    // never splits a surrogate pair
    expect([...e.slice(0, -1)].every((c) => c === "\u{1F600}")).toBe(true);
    const flags = "\u{1F1EB}\u{1F1EE}".repeat(60); // regional-indicator pairs
    const f = truncate(flags, 50);
    expect((f.length - 1) % 4).toBe(0);
  });

  it("formats the sender", () => {
    expect(formatFrom([{ name: "Alice", email: "alice@x.fi" }])).toBe("Alice <alice@x.fi>");
    expect(formatFrom([{ name: null, email: "bob@x.fi" }])).toBe("bob@x.fi");
    expect(formatFrom([{ name: "bob@x.fi", email: "bob@x.fi" }])).toBe("bob@x.fi");
    expect(formatFrom([{ name: '"Quoted\r\nName"', email: "q@x.fi" }])).toBe("Quoted Name <q@x.fi>");
    expect(formatFrom([{ name: "Only name", email: null }])).toBe("Only name");
    expect(formatFrom(null)).toBe("");
    expect(formatFrom([{ name: "N".repeat(300), email: "n@x.fi" }]).length).toBeLessThanOrEqual(120);
  });

  it("cleans subjects", () => {
    expect(cleanSubject("  Re:\tHello\n world ")).toBe("Re: Hello world");
    expect(cleanSubject("s".repeat(500)).length).toBe(200);
    expect(cleanSubject(null)).toBe("");
  });
});

describe("payload size", () => {
  const base = (over: Partial<PushPayload> = {}): PushPayload => ({
    kind: "email",
    accountLabel: "a@x.fi",
    accountId: "1",
    emailIds: ["e1"],
    changed: { "1": { EmailDelivery: "s" } },
    email: { from: "A <a@x.fi>", subject: "Hi", preview: "Hello" },
    ...over,
  });

  it("leaves a small payload alone and caps ids at 10", () => {
    expect(fitPayload(base())).toEqual(base());
    const many = fitPayload(base({ emailIds: Array.from({ length: 15 }, (_, i) => `e${i}`) }));
    expect(many.emailIds).toEqual(Array.from({ length: 10 }, (_, i) => `e${i + 5}`));
  });

  it("shrinks step by step until it fits", () => {
    const big = base({
      emailIds: Array.from({ length: 10 }, (_, i) => `${"x".repeat(250)}${i}`),
      email: { from: "A <a@x.fi>", subject: "\u{1F600}".repeat(100), preview: "\u{1F600}".repeat(100) },
    });
    const fitted = fitPayload(big, 1000);
    expect(payloadBytes(fitted)).toBeLessThanOrEqual(1000);
    expect(fitted.emailIds).toHaveLength(1);
    expect(fitted.emailIds[0]).toMatch(/9$/);
    expect(fitPayload(big, 200).email).toBeUndefined();
  });

  it("builds the minimal payload for a 413", () => {
    const m = minimalPayload(base({ emailIds: ["a", "b"] }));
    expect(m).toEqual({ kind: "email", accountLabel: "a@x.fi", accountId: "1", emailIds: ["b"], changed: { "1": { EmailDelivery: "s" } } });
  });

  it("derives a short base64url topic per account", () => {
    const t = topicFor("acc", "1");
    expect(t).toMatch(/^[A-Za-z0-9_-]{32}$/);
    expect(topicFor("acc", "2")).not.toBe(t);
  });
});

describe("validation", () => {
  it("matches the relay's id and subscription rules", () => {
    expect(isValidSubscriptionId("abcdefgh")).toBe(true);
    expect(isValidSubscriptionId("short")).toBe(false);
    expect(isValidSubscriptionId("has space!")).toBe(false);
    expect(isValidSubscriptionId("x".repeat(129))).toBe(false);
    const keys = { p256dh: "B".repeat(87), auth: "A".repeat(22) };
    expect(isValidWebPushSubscription({ endpoint: "https://fcm.googleapis.com/fcm/send/x", keys })).toBe(true);
    expect(isValidWebPushSubscription({ endpoint: "http://fcm.googleapis.com/x", keys })).toBe(false);
    expect(isValidWebPushSubscription({ endpoint: "https://a.b/c", keys: { ...keys, auth: "short" } })).toBe(false);
    expect(isValidWebPushSubscription({ endpoint: "https://a.b/c", keys: { ...keys, p256dh: "x" } })).toBe(false);
    expect(isValidWebPushSubscription(null)).toBe(false);
  });

  it("allows only listed push-service hosts", () => {
    const hosts = ["fcm.googleapis.com", "*.push.services.mozilla.com"];
    expect(hostAllowed("fcm.googleapis.com", hosts)).toBe(true);
    expect(hostAllowed("updates.push.services.mozilla.com", hosts)).toBe(true);
    expect(hostAllowed("push.services.mozilla.com", hosts)).toBe(false);
    expect(hostAllowed("evil-push.services.mozilla.com.attacker.test", hosts)).toBe(false);
    expect(endpointAllowed("https://fcm.googleapis.com/fcm/send/x", hosts)).toBe(true);
    expect(endpointAllowed("https://user:pw@fcm.googleapis.com/x", hosts)).toBe(false);
    expect(endpointAllowed("https://10.0.0.1/x", hosts)).toBe(false);
  });

  it("accepts only our own relay JMAP URLs", () => {
    const pub = "https://mail.example.test";
    expect(relayIdFromUrl(`${pub}/relay/api/push/jmap/abcdef0123456789`, pub)).toBe("abcdef0123456789");
    expect(relayIdFromUrl(`https://MAIL.example.test/relay/api/push/jmap/abcdef0123456789`, pub)).toBe("abcdef0123456789");
    expect(relayIdFromUrl(`https://notifications.relay.bulwarkmail.org/api/push/jmap/abcdef0123456789`, pub)).toBeNull();
    expect(relayIdFromUrl(`${pub}/relay/api/push/jmap/abcdef0123456789?x=1`, pub)).toBeNull();
    expect(relayIdFromUrl(`${pub}/relay/api/push/jmap/short`, pub)).toBeNull();
    expect(relayIdFromUrl("not a url", pub)).toBeNull();
  });
});

describe("config", () => {
  it("defaults to disabled web push and sane intervals", () => {
    const c = parsePushConfig({});
    expect(c).toMatchObject({ vapid: null, upstreamAlways: false, reconcileIntervalMs: 300_000, ttlSec: 21_600, workerEnabled: true });
    expect(c.endpointHosts).toContain("fcm.googleapis.com");
  });

  it("needs both keys and a subject, and checks key lengths", () => {
    const pub = Buffer.alloc(65, 4).toString("base64url");
    const priv = Buffer.alloc(32, 1).toString("base64url");
    expect(() => parsePushConfig({ PUSH_VAPID_PUBLIC_KEY: pub })).toThrow(/VAPID/);
    expect(() => parsePushConfig({ PUSH_VAPID_PUBLIC_KEY: pub, PUSH_VAPID_PRIVATE_KEY: priv })).toThrow(/PUSH_VAPID_SUBJECT/);
    expect(() =>
      parsePushConfig({ PUSH_VAPID_PUBLIC_KEY: priv, PUSH_VAPID_PRIVATE_KEY: priv, PUSH_VAPID_SUBJECT: "mailto:a@b.c" }),
    ).toThrow(/65 bytes/);
    const c = parsePushConfig({ PUSH_VAPID_PUBLIC_KEY: pub, PUSH_VAPID_PRIVATE_KEY: priv, PUSH_VAPID_SUBJECT: "mailto:a@b.c" });
    expect(c.vapid).toEqual({ publicKey: pub, privateKey: priv, subject: "mailto:a@b.c" });
  });
});
