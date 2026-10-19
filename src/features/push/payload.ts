/**
 * The push payload (COORDINATION.md "Push payload"; design/push.md section 6):
 * Bulwark relay's ForwardPayload plus an optional `email` summary that our
 * Bulwark `sw.js` patch shows when its preview API answers 401.
 */

export interface PayloadEmail {
  from: string;
  subject: string;
  preview: string;
  /** AI summary (Phase 5), only in the quiet replacement push: <= 200 chars, plain text. */
  summary?: string;
}

export interface PushPayload {
  kind: "email";
  accountLabel: string;
  accountId: string;
  emailIds: string[];
  changed: Record<string, Record<string, string>>;
  email?: PayloadEmail;
  /** `false` on the quiet replacement push: update the notification (same tag) without alerting again. */
  renotify?: false;
  /** When this push was handed to the push service (ms since the epoch; set per device by the sender). Diagnostics only. */
  sentAt?: number;
  /** On the quiet replacement push: when the preview push it replaces went out (ms since the epoch). Diagnostics only. */
  firstSentAt?: number;
  /** Per device: a ticket that lets the service worker fetch the newest message once its session has expired (preview-ticket.ts). */
  previewTicket?: string;
}

/**
 * A Declarative Web Push message (WebKit, Safari 18.4 / iOS 18.4; the Push
 * API's "declarative push message"): `web_push: 8030` plus a `notification`
 * the browser shows by itself. On an iPhone Home Screen app, webpushd shows
 * an immutable one at once, without launching the app or running its
 * service worker; a classic push instead launches the app in the background
 * and waits for the worker, which on a cold launch iOS may not run until the
 * next push arrives (seen 2026-10-19: the preview notification appeared only
 * with the summary push, 35 s later). Our own members stay at the top level,
 * where the parser ignores them, so a browser without declarative support
 * hands the same JSON to the service worker as before.
 */
export interface DeclarativePushPayload extends PushPayload {
  web_push: 8030;
  notification: {
    title: string;
    body: string;
    navigate: string;
    tag: string;
    silent: boolean;
    data: { kind: "email"; emailId: string; accountId: string; headlineEmailId: string };
  };
}

/** The notification text the service worker builds from `email` when its preview lookup fails (sw.js buildPayloadEmailContent). */
export function payloadNotificationText(email: PayloadEmail | undefined): { title: string; body: string } {
  const from = email?.from.trim() ?? "";
  const subject = email?.subject.trim() ?? "";
  const preview = ((email?.summary ?? "").trim() || (email?.preview ?? "").trim()).slice(0, PREVIEW_MAX);
  if (!from && !subject && !preview) return { title: "New mail", body: "" };
  return { title: from || "New mail", body: [subject, preview].filter(Boolean).join("\n") || "(no subject)" };
}

/**
 * `p` as a Declarative Web Push message that opens its newest message
 * (the same URL the service worker gives the notification it shows). iOS
 * keeps no `data` for such a notification, so the link's fragment carries
 * when the push went out (`#sent=<ms>`): the worker orders it against a
 * quiet push by that (sw.js), and the app ignores the fragment.
 */
export function declarativePayload(p: PushPayload, publicBaseUrl: string): DeclarativePushPayload {
  const emailId = p.emailIds[p.emailIds.length - 1] ?? "";
  const base = publicBaseUrl.replace(/\/+$/, "");
  const { title, body } = payloadNotificationText(p.email);
  const sent = typeof p.sentAt === "number" && Number.isFinite(p.sentAt) ? `#sent=${Math.round(p.sentAt)}` : "";
  return {
    web_push: 8030,
    notification: {
      title,
      body,
      navigate: emailId ? `${base}/mail/message/${encodeURIComponent(emailId)}${sent}` : `${base}/`,
      tag: `bulwark-mail:${p.accountId || "default"}`,
      silent: false,
      data: { kind: "email", emailId, accountId: p.accountId, headlineEmailId: emailId },
    },
    ...p,
  };
}

export const PREVIEW_MAX = 200;
export const SUBJECT_MAX = 200;
export const FROM_MAX = 120;
export const MAX_EMAIL_IDS = 10;
/** RFC 8291 single record: 4096 - 86 (header) - 16 (tag) - 1 (delimiter) = 3993 plaintext bytes. Keep a margin. */
export const PAYLOAD_BUDGET_BYTES = 3000;

// --- Bulwark's preview cleaning, ported from lib/utils.ts (cleanPreview) of
// --- bulwarkmail/webmail v1.14.2 (AGPL-3.0), so the toast matches the app.

const LEADING_INVISIBLE_RE = /^[\s\p{Cf}\p{Mn}]+/u;
const ONLY_PUNCTUATION_RE = /^[.…\s]+$/;
const DECLARATIONS_RE = /^\s*(?:[-\w]+\s*:|[.#@a-z*][^{}]*\{)/i;
const AT_RULE_RE = /^@(?:media|font-face|import|supports|keyframes|charset|page)\b/;
const SELECTOR_RE = /^[.#]?[a-z*](?:[\w\-.#,>~+*\s[\]="']|:(?!\s))*\{/i;

function stripInvisibleLeading(text: string): string {
  const stripped = text.replace(LEADING_INVISIBLE_RE, "");
  return ONLY_PUNCTUATION_RE.test(stripped) ? "" : stripped;
}

function stripLeadingCss(text: string): string {
  let rest = text.trimStart();
  for (let guard = 0; guard < 100 && (AT_RULE_RE.test(rest) || SELECTOR_RE.test(rest)); guard++) {
    const brace = rest.indexOf("{");
    const semicolon = rest.indexOf(";");
    if (semicolon >= 0 && (brace < 0 || semicolon < brace) && /^@(?:import|charset)\b/.test(rest)) {
      rest = rest.slice(semicolon + 1).trimStart();
      continue;
    }
    if (brace < 0) return rest;
    let depth = 0;
    let end = -1;
    for (let i = brace; i < rest.length; i++) {
      if (rest[i] === "{") depth++;
      else if (rest[i] === "}" && --depth === 0) {
        end = i;
        break;
      }
    }
    if (end < 0) return rest.startsWith("@") || DECLARATIONS_RE.test(rest.slice(brace + 1)) ? "" : rest;
    if (!rest.startsWith("@") && !DECLARATIONS_RE.test(rest.slice(brace + 1, end))) return rest;
    rest = rest.slice(end + 1).trimStart();
  }
  return rest;
}

export function cleanPreviewLikeBulwark(text: string): string {
  return stripInvisibleLeading(stripLeadingCss(stripInvisibleLeading(text)));
}

// --- our own cleaning and truncation

const ZWJ = "\u200d";
/** Control (Cc) and format (Cf) characters except ZWJ (emoji sequences), plus line/paragraph separators. */
const JUNK_RE = /[\p{Cc}\p{Cf}\u2028\u2029]/gu;

/** NFC, drop control/format characters, collapse whitespace, trim. */
export function cleanText(text: string | null | undefined): string {
  if (!text) return "";
  return text
    .normalize("NFC")
    .replace(JUNK_RE, (ch) => (ch === ZWJ ? ch : /\s/.test(ch) ? " " : ""))
    .replace(/\s+/g, " ")
    .trim();
}

const segmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" });

/**
 * Cut `text` to at most `max` UTF-16 code units (sw.js slices that way), on a
 * grapheme boundary, preferring a word boundary within the last 30 units, and
 * append "…" (counted in `max`) when anything was cut.
 */
export function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  const limit = max - 1; // room for the ellipsis
  let out = "";
  for (const { segment } of segmenter.segment(text)) {
    if (out.length + segment.length > limit) break;
    out += segment;
  }
  const space = out.lastIndexOf(" ");
  if (space > 0 && out.length - space <= 30) out = out.slice(0, space);
  return out.trimEnd() + "…";
}

export interface JmapAddress {
  name?: string | null;
  email?: string | null;
}

/** `Name <addr>`, `addr`, or "" for the first address. */
export function formatFrom(from: JmapAddress[] | null | undefined): string {
  const a = from?.[0];
  if (!a) return "";
  const email = cleanText(a.email).replace(/[<>]/g, "");
  const name = cleanText(a.name).replace(/^"(.*)"$/, "$1");
  let out: string;
  if (name && email && name.toLowerCase() !== email.toLowerCase()) out = `${name} <${email}>`;
  else out = email || name;
  return truncate(out, FROM_MAX);
}

export function cleanSubject(subject: string | null | undefined, max = SUBJECT_MAX): string {
  return truncate(cleanText(subject), max);
}

export function cleanPreview(preview: string | null | undefined, max = PREVIEW_MAX): string {
  return truncate(cleanText(cleanPreviewLikeBulwark(preview ?? "")), max);
}

export function payloadBytes(p: PushPayload): number {
  return Buffer.byteLength(JSON.stringify(p), "utf8");
}

/**
 * Shrink a payload until it fits `budget` bytes: newest id only, then a
 * 100-char preview, then a 100-char subject, then no `email` at all.
 * `wrap` measures what is really sent (a declarative message repeats the text).
 */
export function fitPayload(p: PushPayload, budget = PAYLOAD_BUDGET_BYTES, wrap: (q: PushPayload) => PushPayload = (q) => q): PushPayload {
  const size = (q: PushPayload) => Buffer.byteLength(JSON.stringify(wrap(q)), "utf8");
  let cur: PushPayload = { ...p, emailIds: p.emailIds.slice(-MAX_EMAIL_IDS) };
  const steps: ((q: PushPayload) => PushPayload)[] = [
    (q) => ({ ...q, emailIds: q.emailIds.slice(-1) }),
    (q) => (q.email ? { ...q, email: { ...q.email, preview: truncate(q.email.preview, 100) } } : q),
    (q) => (q.email ? { ...q, email: { ...q.email, subject: truncate(q.email.subject, 100) } } : q),
    (q) => (q.email ? { ...q, email: { ...q.email, from: truncate(q.email.from, 60) } } : q),
    (q) => {
      const { email: _drop, ...rest } = q;
      return rest;
    },
  ];
  for (const step of steps) {
    if (size(cur) <= budget) return cur;
    cur = step(cur);
  }
  return cur;
}

/** The minimal payload (no `email`), used after a 413. */
export function minimalPayload(p: PushPayload): PushPayload {
  const { email: _drop, ...rest } = p;
  return { ...rest, emailIds: p.emailIds.slice(-1) };
}
