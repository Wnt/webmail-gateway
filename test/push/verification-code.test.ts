import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { EmailBody } from "../../src/features/push/summary-text.js";
import {
  findVerificationCode,
  findVerificationCodeInBody,
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

  it("keeps quoted text and falls back to the plain-text part", () => {
    const quoted: EmailBody = { text: [], html: [part("text/html", "<blockquote>Your code is 482913</blockquote>")] };
    expect(findVerificationCodeInBody("", quoted)).toBe("482913");
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
