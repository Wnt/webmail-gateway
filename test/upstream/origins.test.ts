// gateway-data-5: the native JMAP upstream sends the stored credential only to
// the session URL's origin and the configured UPSTREAM_ALLOWED_ORIGINS, never to
// whatever origin the upstream's session object names.
import { pino } from "pino";
import { MockAgent } from "undici";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { setUpstreamCredential, upsertAccount } from "../../src/core/accounts.js";
import { UpstreamError } from "../../src/core/upstream/http.js";
import { absolutizeSession, JmapUpstream } from "../../src/core/upstream/jmap.js";
import type { JmapSession, UpstreamRequest } from "../../src/core/upstream/types.js";
import type { Db } from "../../src/db/pool.js";
import type { AppContext } from "../../src/types.js";
import { makeTestConfig, makeTestDb } from "../helpers.js";

const SESSION_URL = "https://provider.example/jmap/session";
const session = (over: Record<string, string>) => ({ capabilities: {}, accounts: {}, apiUrl: "https://provider.example/jmap/api/", ...over });

let db: Db;
beforeAll(async () => {
  db = await makeTestDb();
});
afterAll(async () => db.close());
let cleanup: (() => Promise<void>)[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  for (const c of cleanup.reverse()) await c();
  cleanup = [];
});

/** A JmapUpstream whose only transport is a MockAgent with the network disabled: these reserved names are never resolved. */
async function setup(env: Record<string, string> = {}) {
  const config = makeTestConfig({ UPSTREAM_KIND: "jmap", UPSTREAM_SESSION_URL: SESSION_URL, ...env });
  const ctx: AppContext = { config, db, log: pino({ level: "silent" }), fetch };
  const mock = new MockAgent();
  mock.disableNetConnect();
  const upstream = new JmapUpstream(ctx);
  vi.spyOn(upstream.agent, "request").mockImplementation(((opts: Parameters<typeof mock.request>[0]) => mock.request(opts)) as typeof upstream.agent.request);
  const account = await upsertAccount(ctx, { email: "alice@example.test" });
  await setUpstreamCredential(ctx, account.id, { auth: "bearer", username: account.email, secret: "audit-test-credential" });
  cleanup.push(async () => {
    await upstream.close();
    await mock.close();
  });
  const seen: { origin: string; path: string; authorization: string | undefined }[] = [];
  const record = (opts: { origin?: string | URL; path: string; headers?: unknown }) =>
    seen.push({ origin: String(opts.origin), path: opts.path, authorization: (opts.headers as Record<string, string> | undefined)?.["authorization"] });
  const call = async (req: UpstreamRequest) => {
    const res = await upstream.request(account, req);
    if (res.kind === "response") await res.res.body.dump();
    return res;
  };
  return { ctx, mock, upstream, account, seen, record, call };
}

const api: UpstreamRequest = { target: { kind: "api" }, method: "POST", body: "{}", replayable: true };
const download: UpstreamRequest = {
  target: { kind: "download", accountId: "u1", blobId: "b1", type: "text/plain", name: "a.txt" },
  method: "GET",
  replayable: true,
};

describe("native JMAP credential destinations (gateway-data-5)", () => {
  it("does not send the stored credential to an unconfigured session-selected origin", async () => {
    const { mock, seen, record, call } = await setup();
    mock.get("https://provider.example").intercept({ path: "/jmap/session", method: "GET" }).reply(200, session({ apiUrl: "https://unconfigured.example/collect" }));
    mock.get("https://unconfigured.example").intercept({ path: "/collect", method: "POST" }).reply((opts) => {
      record(opts);
      return { statusCode: 200, data: JSON.stringify({ methodResponses: [], sessionState: "0" }) };
    });
    await expect(call(api)).rejects.toThrow(/unconfigured\.example.*UPSTREAM_ALLOWED_ORIGINS/);
    expect(seen, "session metadata must not expand the configured credential destination trust boundary").toEqual([]);
  });

  it("uses a separate download origin once it is configured (Fastmail's blob host)", async () => {
    const { mock, seen, record, call } = await setup({ UPSTREAM_ALLOWED_ORIGINS: "https://blobs.provider-content.example" });
    mock.get("https://provider.example").intercept({ path: "/jmap/session", method: "GET" }).reply(200, session({
      downloadUrl: "https://blobs.provider-content.example/jmap/download/{accountId}/{blobId}/{name}?type={type}",
    }));
    mock.get("https://blobs.provider-content.example").intercept({ path: /^\/jmap\/download\//, method: "GET" }).reply((opts) => {
      record(opts);
      return { statusCode: 200, data: "blob" };
    });
    const res = await call(download);
    expect(res.kind).toBe("response");
    expect(seen).toEqual([{
      origin: "https://blobs.provider-content.example",
      path: "/jmap/download/u1/b1/a.txt?type=text%2Fplain",
      authorization: "Bearer audit-test-credential",
    }]);
  });

  it("refuses a redirect to an origin that is not allowed, without following it", async () => {
    const { mock, seen, record, call } = await setup();
    mock.get("https://provider.example").intercept({ path: "/jmap/session", method: "GET" }).reply(200, session({
      downloadUrl: "https://provider.example/dl/{accountId}/{blobId}/{name}",
    }));
    mock.get("https://provider.example").intercept({ path: "/dl/u1/b1/a.txt", method: "GET" }).reply(302, "", {
      headers: { location: "https://elsewhere.example/blob" },
    });
    mock.get("https://elsewhere.example").intercept({ path: "/blob", method: "GET" }).reply((opts) => {
      record(opts);
      return { statusCode: 200, data: "x" };
    });
    const err = await call(download).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(UpstreamError);
    expect((err as UpstreamError).status).toBe(502);
    expect((err as Error).message).toMatch(/elsewhere\.example/);
    expect(seen).toEqual([]);
  });

  it("follows a redirect within the allowed origins, dropping the credential across origins", async () => {
    const { mock, seen, record, call } = await setup({ UPSTREAM_ALLOWED_ORIGINS: "https://blobs.provider-content.example" });
    mock.get("https://provider.example").intercept({ path: "/jmap/session", method: "GET" }).reply(200, session({
      downloadUrl: "https://provider.example/dl/{accountId}/{blobId}/{name}",
    }));
    mock.get("https://provider.example").intercept({ path: "/dl/u1/b1/a.txt", method: "GET" }).reply(302, "", {
      headers: { location: "https://blobs.provider-content.example/signed/blob" },
    });
    mock.get("https://blobs.provider-content.example").intercept({ path: "/signed/blob", method: "GET" }).reply((opts) => {
      record(opts);
      return { statusCode: 200, data: "x" };
    });
    expect((await call(download)).kind).toBe("response");
    expect(seen).toEqual([{ origin: "https://blobs.provider-content.example", path: "/signed/blob", authorization: undefined }]);
  });

  it("refuses user info, another port, a template variable in the origin and a downgrade", () => {
    const allowed = ["https://provider.example"];
    const check = (over: Record<string, string>) => () => absolutizeSession(session(over) as JmapSession, SESSION_URL, allowed);
    expect(check({ apiUrl: "https://user:pw@provider.example/jmap/api/" })).toThrow(/not an allowed upstream origin/);
    expect(check({ apiUrl: "https://provider.example:8443/jmap/api/" })).toThrow(/provider\.example:8443.*UPSTREAM_ALLOWED_ORIGINS/);
    expect(check({ downloadUrl: "https://{accountId}.provider.example/dl/{blobId}" })).toThrow(/template variable in its origin/);
    expect(check({ downloadUrl: "https://provider.example{blobId}/dl" })).toThrow(/template variable in its origin/);
    expect(check({ eventSourceUrl: "http://provider.example/jmap/event/" })).toThrow(/https/);
    expect(check({ uploadUrl: "/jmap/upload/{accountId}/", eventSourceUrl: "https://provider.example:443/jmap/event/" })()).toMatchObject({
      uploadUrl: "https://provider.example/jmap/upload/{accountId}/",
    });
  });

  it("validates UPSTREAM_ALLOWED_ORIGINS and leaves the legacy upstream alone", () => {
    const jmap = { UPSTREAM_KIND: "jmap", UPSTREAM_SESSION_URL: SESSION_URL };
    expect(makeTestConfig({ ...jmap, UPSTREAM_ALLOWED_ORIGINS: " https://a.example , https://b.example:8443/ " }).upstream).toEqual({
      kind: "jmap", sessionUrl: SESSION_URL, auth: "bearer",
      allowedOrigins: ["https://provider.example", "https://a.example", "https://b.example:8443"],
    });
    expect(() => makeTestConfig({ ...jmap, UPSTREAM_ALLOWED_ORIGINS: "http://a.example" })).toThrow(/must be https/);
    expect(() => makeTestConfig({ ...jmap, UPSTREAM_ALLOWED_ORIGINS: "https://a.example/path" })).toThrow(/bare origin/);
    expect(() => makeTestConfig({ ...jmap, UPSTREAM_ALLOWED_ORIGINS: "https://u@a.example" })).toThrow(/bare origin/);
    expect(() => makeTestConfig({ ...jmap, UPSTREAM_SESSION_URL: "https://u:p@provider.example/s" })).toThrow(/user info/);
    // A plain-http test stack (Stalwart) may list plain-http origins.
    expect(makeTestConfig({ UPSTREAM_KIND: "jmap", UPSTREAM_SESSION_URL: "http://stalwart:8080/s", UPSTREAM_ALLOWED_ORIGINS: "http://dl:8080" }).upstream)
      .toMatchObject({ allowedOrigins: ["http://stalwart:8080", "http://dl:8080"] });
    expect(makeTestConfig({ UPSTREAM_ALLOWED_ORIGINS: "not checked" }).upstream).toEqual({ kind: "legacy" });
  });
});
