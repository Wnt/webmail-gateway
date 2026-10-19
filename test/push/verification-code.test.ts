import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { EmailBody } from "../../src/features/push/summary-text.js";
import { htmlToText } from "../../src/features/push/summary-text.js";
import {
  CUT_MARK,
  detectorWork,
  findVerificationCode,
  findVerificationCodeInBody,
  markCut,
  MAX_BODY_CHARS,
  MAX_PREVIEW_CHARS,
  MAX_SUBJECT_CHARS,
  mentionsVerificationCode,
  verificationCodeBodyTexts,
} from "../../src/features/push/verification-code.js";

// Shared, synthetic cases (invented senders, codes and data only): the inline
// cases of Bulwark's lib/__tests__/verification-code.test.ts, the one-time-code
// mails of the test stacks (tools/e2e/fixtures/otp, except 05, which names no
// code word), and our own. Kept free of anything gateway-specific so the same
// file can run in Bulwark's tests unchanged.
interface Case {
  name: string;
  subject: string;
  text: string;
  code: string | null;
}
const cases = JSON.parse(readFileSync(new URL("../fixtures/verification-code-cases.json", import.meta.url), "utf8")) as Case[];

describe("findVerificationCode on the shared cases", () => {
  it("has the cases", () => {
    expect(cases.length).toBeGreaterThan(50);
    for (const c of cases) {
      expect(Object.keys(c).sort()).toEqual(["code", "name", "subject", "text"]);
      expect(new Set(cases.map((x) => x.name)).size).toBe(cases.length);
    }
  });

  it.each(cases.map((c) => [c.name, c] as const))("%s", (_, c) => {
    expect(findVerificationCode(c.subject, c.text)).toBe(c.code);
  });
});

describe("what the push pipeline does with a preview", () => {
  // legacy-proxy and JMAP servers give a whitespace-collapsed preview of up to 256 characters.
  const previewOf = (text: string) => text.replace(/\s+/g, " ").trim().slice(0, 256);
  const pipeline = (c: Case) =>
    findVerificationCode(c.subject, previewOf(c.text)) ??
    (mentionsVerificationCode(c.subject) || mentionsVerificationCode(previewOf(c.text)) ? findVerificationCode(c.subject, c.text) : null);

  it.each(cases.map((c) => [c.name, c] as const))("%s", (_, c) => {
    expect(pipeline(c)).toBe(c.code);
  });

  it("reads the body only when a code word was seen", () => {
    expect(mentionsVerificationCode("Your sign-in code")).toBe(true);
    expect(mentionsVerificationCode("Vahvistuskoodi")).toBe(true);
    expect(mentionsVerificationCode("Ihr Bestätigungscode")).toBe(true);
    expect(mentionsVerificationCode("OTP for your login")).toBe(true);
    expect(mentionsVerificationCode("Your one-time password")).toBe(true);
    expect(mentionsVerificationCode("您的验证码")).toBe(true);
    expect(mentionsVerificationCode("Lunch on Friday?")).toBe(false);
    expect(mentionsVerificationCode("Use promo code AUTUMN25")).toBe(false);
    expect(mentionsVerificationCode("Updates to our Code of Conduct")).toBe(false);
    expect(mentionsVerificationCode("")).toBe(false);
    expect(mentionsVerificationCode(null)).toBe(false);
  });
});

describe("the body as the gateway reads it", () => {
  const part = (type: string, value: string, extra: Partial<EmailBody["text"][number]> = {}) => ({ type, value, ...extra });

  it("reads an HTML table without its stylesheet", () => {
    const body: EmailBody = {
      text: [part("text/plain", "This email is only available as HTML.")],
      html: [
        part(
          "text/html",
          "<html><head><style>.x{width:600px;color:#123456}</style></head><body><table><tr><td>Verification code:</td></tr>" +
            "<tr><td style=\"font-size:32px\"><b>261765</b></td></tr><tr><td>Asiakasnumero 10023</td></tr></table></body></html>",
        ),
      ],
    };
    const [html] = verificationCodeBodyTexts(body);
    expect(html).not.toContain("600px");
    expect(findVerificationCodeInBody("Verification Code", body)).toBe("261765");
  });

  it("finds the code of an HTML-only mail with other numbers nearby (otp fixture 07)", () => {
    const html =
      '<!doctype html><html><body style="font-family:sans-serif"><table role="presentation" width="100%"><tr><td>' +
      "<p>Vahvista s&auml;hk&ouml;postiosoitteesi sy&ouml;tt&auml;m&auml;ll&auml; alla oleva koodi.</p></td></tr>" +
      '<tr><td style="font-size:32px;letter-spacing:8px;font-weight:bold">914602</td></tr><tr>' +
      '<td><p style="color:#777">Asiakasnumero 10023, viite 2026-10-19</p></td></tr></table></body></html>';
    expect(findVerificationCodeInBody("Laskutin: vahvista sähköpostiosoitteesi", { text: [], html: [part("text/html", html)] })).toBe("914602");
  });

  it("leaves quoted text out and falls back to the plain-text part", () => {
    const quoted: EmailBody = { text: [], html: [part("text/html", "<blockquote>Your code is 482913</blockquote>")] };
    expect(findVerificationCodeInBody("", quoted)).toBeNull();
    const plain: EmailBody = {
      text: [part("text/plain", "Hi Alice,\n\nUse this code to finish signing in: 482913\n")],
      html: [part("text/html", "<p>Open the app to sign in.</p>")],
    };
    expect(verificationCodeBodyTexts(plain)).toHaveLength(2);
    expect(findVerificationCodeInBody("Sign in", plain)).toBe("482913");
  });

  it("skips parts with an encoding problem, and finds nothing in an empty body", () => {
    expect(findVerificationCodeInBody("", { text: [part("text/plain", "Your code is 482913", { isEncodingProblem: true })], html: [] })).toBeNull();
    expect(verificationCodeBodyTexts({ text: [], html: [] })).toEqual([]);
  });
});

describe("hostile mail stays cheap (linear, capped)", () => {
  /** The fastest of five runs, in ms (the least disturbed by other load on the host). */
  const timeMs = (f: () => unknown) => {
    let best = Infinity;
    for (let i = 0; i < 5; i++) {
      const t0 = performance.now();
      f();
      best = Math.min(best, performance.now() - t0);
    }
    return best;
  };
  /**
   * Nine rounds at 5,000 and at 20,000 characters, taken in turn so both see
   * the same load: the fastest large run, and whether any round was linear
   * (4x the input in at most 8x the time, plus 10 ms of timer and scheduling
   * noise). A quadratic shape fails every round; a busy host only some.
   */
  const scaling = (shape: (n: number) => () => unknown) => {
    const [runSmall, runLarge] = [shape(5_000), shape(20_000)];
    let large = Infinity;
    let linear = false;
    for (let i = 0; i < 9; i++) {
      let t0 = performance.now();
      runSmall();
      const s = performance.now() - t0;
      t0 = performance.now();
      runLarge();
      const l = performance.now() - t0;
      large = Math.min(large, l);
      if (l < 8 * s + 10) linear = true;
    }
    return { large, linear };
  };
  const body = (value: string): EmailBody => ({ text: [{ type: "text/plain", value }], html: [] });
  const pad = (n: number) => "Lorem ipsum ".repeat(Math.ceil(n / 12)).slice(0, n);
  const html = (value: string): EmailBody => ({ text: [], html: [{ type: "text/html", value }] });
  const shapes: [string, (n: number) => () => unknown][] = [
    ["one long word under a code subject", (n) => () => findVerificationCodeInBody("Your verification code", body("x".repeat(n)))],
    ["one long word as the subject", (n) => () => findVerificationCode("x".repeat(n / 20), "")],
    ["a long word ending in @", (n) => () => findVerificationCode("code", `${"x".repeat(n)}@`)],
    ["dense code candidates", (n) => () => findVerificationCode("", "code 1234 ".repeat(n / 10))],
    ["digits glued into one long word", (n) => () => findVerificationCode("Your code", "a1234".repeat(n / 5))],
    ["one long code word", (n) => () => findVerificationCode("", `${"code".repeat(n / 4)} 123456`)],
    ["hyphenated groups", (n) => () => findVerificationCode("code", "ab-".repeat(n / 3))],
    ["dots before a long run of spaces", (n) => () => findVerificationCode("code", `${".".repeat(n / 2)}${" ".repeat(n / 2)}x`)],
    ["a run of < before one >", (n) => () => findVerificationCodeInBody("Your code", html(`${"<".repeat(n)}>x`))],
    ["unclosed tags", (n) => () => findVerificationCodeInBody("Your code", html("<p ".repeat(n / 3)))],
    ["unclosed style elements", (n) => () => findVerificationCodeInBody("Your code", html("<style>".repeat(n / 7)))],
    ["unclosed title and blockquote elements", (n) => () => htmlToText("<title><blockquote>".repeat(n / 19))],
    ["unclosed quote-start divs", (n) => () => htmlToText("<div class='x ".repeat(n / 14))],
    ["unclosed comments", (n) => () => findVerificationCodeInBody("Your code", html("<!--".repeat(n / 4)))],
    ["deep nesting", (n) => () => findVerificationCodeInBody("Your code", html(`${"<div><td>".repeat(n / 18)}code 123456${"</td></div>".repeat(n / 18)}`))],
    ["unclosed hidden spans", (n) => () => findVerificationCodeInBody("Your code", html('<span style="display:none">'.repeat(n / 27)))],
    ["many closed hidden elements", (n) => () => findVerificationCodeInBody("Your code", html("<div hidden>x</div>".repeat(n / 19)))],
    ["deeply nested inside a hidden element", (n) => () => findVerificationCodeInBody("Your code", html(`<div style="display:none">${"<div>".repeat(n / 5)}code 1${"</div>".repeat(n / 6)}`))],
    ["a long inline style", (n) => () => findVerificationCodeInBody("Your code", html(`<p style="${"a:b;".repeat(n / 4)}">code 123456</p>`))],
    ["many attributes", (n) => () => findVerificationCodeInBody("Your code", html(`<p ${'a="b" '.repeat(n / 6)}>code 123456</p>`))],
    ["quoted lines", (n) => () => findVerificationCodeInBody("Your code", body("> code 1234\n".repeat(n / 12)))],
    ["a long attribution-like line", (n) => () => findVerificationCodeInBody("Your code", body(`On ${"x".repeat(n)} wrote:\ncode 123456`))],
    ["long separator-like lines", (n) => () => findVerificationCodeInBody("Your code", body(`${"-".repeat(n / 2)}\n${"_".repeat(n / 2)}\ncode 123456`))],
  ];

  it.each(shapes)("%s: well under the bound, and 4x the input takes at most about 8x the time", (_, shape) => {
    const { large, linear } = scaling(shape);
    expect(large).toBeLessThan(250);
    expect(linear).toBe(true);
  });

  it("dense candidates and code words: the keyword lookups grow linearly (counted, not timed)", () => {
    const steps = (n: number) => {
      detectorWork.keywordSteps = 0;
      findVerificationCode("", "code 1234 ".repeat(n));
      return detectorWork.keywordSteps;
    };
    const [s100, s400, s2000] = [steps(100), steps(400), steps(2_000)];
    // At most a window's worth of code words per candidate (the spans of a list do not overlap), and no log factor.
    expect(s2000 / 2_000).toBeLessThan(60);
    expect(s2000 / s400).toBeLessThan(5 * 1.05);
    expect(s400 / s100).toBeLessThan(4 * 1.1);
  });

  it("a 40,000-character word, 20,000 characters of 'code 1234 ' and huge inputs finish quickly", () => {
    expect(timeMs(() => findVerificationCodeInBody("Your verification code", body("x".repeat(40_000))))).toBeLessThan(250);
    expect(timeMs(() => findVerificationCode("", "code 1234 ".repeat(2_000)))).toBeLessThan(250);
    expect(timeMs(() => findVerificationCode("x".repeat(1_000_000), "y".repeat(1_000_000), "preview"))).toBeLessThan(250);
    expect(timeMs(() => findVerificationCodeInBody("Your code", html("<".repeat(1_000_000))))).toBeLessThan(250);
    expect(timeMs(() => mentionsVerificationCode("code".repeat(250_000)))).toBeLessThan(250);
  });

  it("reads the subject, a preview and a body only up to their caps, never half a code", () => {
    expect([MAX_SUBJECT_CHARS, MAX_PREVIEW_CHARS, MAX_BODY_CHARS]).toEqual([1_000, 1_000, 20_000]);
    expect(findVerificationCode(`${pad(900)} Your code is 482913`, "")).toBe("482913");
    expect(findVerificationCode(`${pad(1_000)} Your code is 482913`, "")).toBeNull();
    expect(findVerificationCode("", `${pad(800)} Your code is 482913 ${pad(100)}`, "preview")).toBe("482913");
    expect(findVerificationCode("", `${pad(1_000)} Your code is 482913`, "preview")).toBeNull();
    expect(findVerificationCode("", `${pad(19_000)} Your code is 482913`)).toBe("482913");
    expect(findVerificationCode("", `${pad(20_000)} Your code is 482913`)).toBeNull();
    // Near the cut, nothing is offered: never "4829" for 482913 cut after its fourth digit.
    const ending = (n: number) => `${pad(MAX_BODY_CHARS - n - 9)} code is `;
    expect(findVerificationCode("", `${ending(120)}482913 ${pad(200)}`)).toBe("482913");
    expect(findVerificationCode("", `${ending(40)}482913 ${pad(200)}`)).toBeNull();
    expect(findVerificationCode("", `${ending(4)}482913 and more`)).toBeNull();
    expect(mentionsVerificationCode(`${pad(1_000)} code`)).toBe(false);
    expect(findVerificationCodeInBody("Your code", body(`${pad(21_000)} 482913`))).toBeNull();
  });

  it("a spaced or grouped code cut at a cap never comes back as its first group (subject, preview, body)", () => {
    const at = (max: number, lead: string) => `${" ".repeat(max - lead.length)}${lead}`;
    for (const lead of ["Your code is 1234 ", "Your code is 1234-", "Your code is 1 2 3 4 "]) {
      expect(findVerificationCode(`${at(MAX_SUBJECT_CHARS, lead)}5678`, "")).toBeNull();
      expect(findVerificationCode("", `${at(MAX_PREVIEW_CHARS, lead)}5678`, "preview")).toBeNull();
      expect(findVerificationCode("", `${at(MAX_BODY_CHARS, lead)}5678`)).toBeNull();
      expect(findVerificationCodeInBody("", body(`${at(MAX_BODY_CHARS, lead)}5678`))).toBeNull();
    }
    // Uncut, the whole code.
    expect(findVerificationCode("", "Your code is 1234 5678", "preview")).toBe("12345678");
  });

  it("keeps the cut through HTML extraction: a large removed <style> before the cut leaves a short text that is still cut", () => {
    const tail = "</style>Your code is 1234";
    const markup = `<style>${"x".repeat(200_000 - "<style>".length - tail.length)}${tail}56`;
    expect(markup.slice(0, 200_000).endsWith("1234")).toBe(true);
    const [text] = verificationCodeBodyTexts(html(markup));
    expect(text!.endsWith(CUT_MARK)).toBe(true);
    expect(findVerificationCodeInBody("", html(markup))).toBeNull();
    // A body value the server cut is cut too.
    const truncated: EmailBody = { text: [{ type: "text/plain", value: "Your code is 1234", isTruncated: true }], html: [] };
    expect(findVerificationCodeInBody("", truncated)).toBeNull();
    const early: EmailBody = { text: [{ type: "text/plain", value: `Your code is 482913. ${pad(200)}`, isTruncated: true }], html: [] };
    expect(findVerificationCodeInBody("", early)).toBe("482913");
    // The guard counts from where the cut was: a code far before a long cut word still counts.
    expect(findVerificationCode("", markCut(`Your code is 482913 ${"x".repeat(5_000)}`, true))).toBe("482913");
    expect(findVerificationCode("", `Your code is 482913 ${"x".repeat(30_000)}`)).toBe("482913");
    expect(findVerificationCodeInBody("", html(`<p>Your code is 482913</p>${"x".repeat(400_000)}`))).toBe("482913");
    expect(findVerificationCode("", markCut("Your code is 1234 5678", true))).toBeNull();
    expect(findVerificationCode("", markCut("Your code is 1234 5678", false))).toBe("12345678");
  });

  it("a preview the upstream may have cut (JMAP: up to 256 characters, no mark) offers no code near its end", () => {
    const at256 = (lead: string, rest: string) => {
      const full = `${pad(256 - lead.length)}${lead}${rest}`;
      return { preview: full.slice(0, 256), full };
    };
    // Cut inside the code, with nothing to say so.
    const inside = at256(" Your code is 1234", "56. Use it to sign in.");
    expect(inside.preview).toHaveLength(256);
    expect(findVerificationCode("Your verification code", inside.preview, "preview")).toBeNull();
    expect(findVerificationCode("Your verification code", inside.full)).toBe("123456");
    // Cut after a group and the space trimmed, and cut inside a grouped or hyphenated code.
    expect(findVerificationCode("", at256(" Your code is 1234 ", "5678").preview.trimEnd(), "preview")).toBeNull();
    expect(findVerificationCode("", at256(" Your code is 123 4", "56").preview, "preview")).toBeNull();
    expect(findVerificationCode("", at256(" Your code is 1234-", "5678").preview, "preview")).toBeNull();
    // An explicit "..." or "…" is a cut in any source, grouped codes included.
    for (const source of ["preview", "body"] as const) {
      expect(findVerificationCode("", "Your code is 1234 ...", source)).toBeNull();
      expect(findVerificationCode("", "Your code is 1234 5678…", source)).toBeNull();
      expect(findVerificationCode("", "Your code is 1234...", source)).toBeNull();
    }
    expect(findVerificationCode("Your code is 1234 ...", "")).toBeNull();
    // No over-correction: a short preview is complete, and a long one still gives a code far from its end.
    expect(findVerificationCode("", "Your code is 482913. It expires in 10 minutes.", "preview")).toBe("482913");
    expect(findVerificationCode("", `Your code is 482913. ${pad(230)}`, "preview")).toBe("482913");
    expect(findVerificationCode("", `Your code is 482913. ${pad(150)}...`, "preview")).toBe("482913");
    expect(findVerificationCode("", `${pad(170)} Your code is 482913`, "preview")).toBe("482913"); // 190 characters: complete
  });
});

// Shared, synthetic body cases (Bulwark runs the same file through its reader):
// what a reader of the body sees, without hidden elements or prior correspondence.
interface BodyCase {
  name: string;
  subject: string;
  html: string | null;
  text: string | null;
  code: string | null;
}
const bodyCases = JSON.parse(readFileSync(new URL("../fixtures/verification-code-body-cases.json", import.meta.url), "utf8")) as BodyCase[];

describe("the body as its reader sees it (shared body cases)", () => {
  it.each(bodyCases.map((c) => [c.name, c] as const))("%s", (_, c) => {
    const body: EmailBody = {
      html: c.html === null ? [] : [{ type: "text/html", value: c.html }],
      text: c.text === null ? [] : [{ type: "text/plain", value: c.text }],
    };
    expect(findVerificationCodeInBody(c.subject, body)).toBe(c.code);
  });
});

describe("a preview's ellipsis or an unmarked server cut never leaves a fragment (review bulwark-n1 r2 R5, the same core)", () => {
  it("gives no code for the review's examples, and the whole code for a complete preview or from the body", () => {
    expect(findVerificationCode("", "Your code is 1234 56...", "preview")).toBeNull();
    expect(findVerificationCode("", "Your code is 1234 ...", "preview")).toBeNull();
    expect(findVerificationCode("", "Your code is 1 2 3 4 5...", "preview")).toBeNull();
    expect(findVerificationCode("", "Your code is 1234 5678", "preview")).toBe("12345678");
    const body = `${"x".repeat(238)} Your code is 12345678`;
    expect(findVerificationCode("", body.slice(0, 256), "preview")).toBeNull();
    expect(findVerificationCodeInBody("", { text: [{ type: "text/plain", value: body }], html: [] })).toBe("12345678");
  });
});
