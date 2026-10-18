import { describe, expect, it } from "vitest";
import { parseSse } from "../../src/core/upstream/events.js";
import { absolutizeSession, jmapUrl, sessionIdentities } from "../../src/core/upstream/jmap.js";
import { legacyPath } from "../../src/core/upstream/legacy.js";
import { expandTemplate } from "../../src/core/upstream/templates.js";
import type { JmapSession } from "../../src/core/upstream/types.js";

const dl = { kind: "download" as const, accountId: "u1", blobId: "B/1", type: "text/plain", name: "a b&c.txt" };

describe("template expansion (RFC 6570 level 1)", () => {
  it("encodes values like Bulwark (encodeURIComponent) and keeps legacy paths byte-identical", () => {
    expect(legacyPath(dl)).toBe("/jmap/download/u1/B%2F1/text%2Fplain/a%20b%26c.txt");
    expect(legacyPath({ ...dl, query: "accept=x" })).toBe("/jmap/download/u1/B%2F1/text%2Fplain/a%20b%26c.txt?accept=x");
    expect(legacyPath({ kind: "eventsource", types: "*", closeafter: "no", ping: "30" })).toBe(
      "/jmap/eventsource?types=*&closeafter=no&ping=30",
    );
  });

  it("drops query pairs whose variable is missing, never the path", () => {
    expect(expandTemplate("/e?types={types}&closeafter={closeafter}&ping={ping}", { types: "Email" })).toBe("/e?types=Email");
    expect(expandTemplate("/e?types={types}", {})).toBe("/e");
    expect(expandTemplate("/d/{accountId}/{blobId}", { accountId: "a" })).toBe("/d/a/");
    expect(expandTemplate("/e/?fixed=1&ping={ping}", {})).toBe("/e/?fixed=1");
  });

  it("maps targets onto a Fastmail-shaped session (separate download host, other variable order)", () => {
    const s = {
      capabilities: {},
      accounts: {},
      apiUrl: "https://api.fastmail.com/jmap/api/",
      downloadUrl: "https://www.fastmailusercontent.com/jmap/download/{accountId}/{blobId}/{name}?type={type}",
      uploadUrl: "https://api.fastmail.com/jmap/upload/{accountId}/",
      eventSourceUrl: "https://api.fastmail.com/jmap/event/",
    } as JmapSession;
    const su = "https://api.fastmail.com/jmap/session";
    expect(jmapUrl(s, su, dl)).toBe("https://www.fastmailusercontent.com/jmap/download/u1/B%2F1/a%20b%26c.txt?type=text%2Fplain");
    expect(jmapUrl(s, su, { kind: "upload", accountId: "u1" })).toBe("https://api.fastmail.com/jmap/upload/u1/");
    expect(jmapUrl(s, su, { kind: "eventsource", types: "*", ping: "30" })).toBe("https://api.fastmail.com/jmap/event/");
    expect(jmapUrl(s, su, { kind: "api" })).toBe("https://api.fastmail.com/jmap/api/");
    expect(jmapUrl(s, su, { kind: "session" })).toBe(su);
  });

  it("resolves relative URLs and refuses a downgrade to http", () => {
    const base = { capabilities: {}, accounts: {}, apiUrl: "/jmap/api/", downloadUrl: "/dl/{accountId}/{blobId}/{name}?accept={type}" } as JmapSession;
    const s = absolutizeSession(base, "https://mail.example.test/.well-known/jmap");
    expect(s.apiUrl).toBe("https://mail.example.test/jmap/api/");
    expect(s["downloadUrl"]).toBe("https://mail.example.test/dl/{accountId}/{blobId}/{name}?accept={type}");
    expect(() => absolutizeSession({ ...base, apiUrl: "http://evil.test/jmap" }, "https://mail.example.test/s")).toThrow(/https/);
    expect(absolutizeSession({ ...base, apiUrl: "http://stalwart:8080/jmap" }, "http://stalwart:8080/s").apiUrl).toBe("http://stalwart:8080/jmap");
  });

  it("finds the session's identities (username, primary mail account name)", () => {
    const s = {
      capabilities: {},
      apiUrl: "x",
      username: "Owner@Example.test",
      accounts: { u1: { name: "user@fastmail.example" }, u2: { name: "other" } },
      primaryAccounts: { "urn:ietf:params:jmap:mail": "u1" },
    } as unknown as JmapSession;
    expect(sessionIdentities(s)).toEqual(["owner@example.test", "user@fastmail.example"]);
  });
});

describe("SSE parsing", () => {
  it("splits events, joins data lines, ignores comments, keeps partial input", () => {
    const got: [string, string][] = [];
    const rest = parseSse(": ping\n\nevent: state\ndata: {\"a\":\ndata: 1}\n\nevent: ping\r\ndata: {}\r\n\r\ndata: x", (e, d) => got.push([e, d]));
    expect(got).toEqual([
      ["state", '{"a":\n1}'],
      ["ping", "{}"],
    ]);
    expect(rest).toBe("data: x");
  });
});
