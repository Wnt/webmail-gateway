import { execFileSync } from "node:child_process";
import { createDecipheriv, createECDH, generateKeyPairSync, hkdfSync, randomBytes, verify, type KeyObject } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import http2 from "node:http2";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Test stand-ins for the native app's push path: a fake APNs provider API
 * (HTTP/2 over TLS with a self-signed certificate, checking the provider
 * token, the headers and the size like Apple), a device with its own P-256
 * key, and an independent envelope decryption (what the app's notification
 * service extension does).
 */

// ------------------------------------------------------------------ envelope

/** Decrypt an envelope v1 with the device's private scalar; throws on any mismatch. */
export function openEnvelope(envelope: string, devicePrivateKey: Buffer): string {
  const raw = Buffer.from(envelope, "base64url");
  if (raw.length < 1 + 65 + 16 + 12 + 16 || raw[0] !== 0x01) throw new Error("not an envelope v1");
  const ePub = raw.subarray(1, 66);
  const salt = raw.subarray(66, 82);
  const nonce = raw.subarray(82, 94);
  const ct = raw.subarray(94, raw.length - 16);
  const tag = raw.subarray(raw.length - 16);
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(devicePrivateKey);
  const dPub = ecdh.getPublicKey();
  const shared = ecdh.computeSecret(ePub);
  const info = Buffer.concat([Buffer.from("madekivi-mail apns v1\0", "latin1"), dPub, ePub]);
  const key = Buffer.from(hkdfSync("sha256", shared, salt, info, 32));
  const d = createDecipheriv("aes-256-gcm", key, nonce);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
}

// -------------------------------------------------------------------- device

export interface FakeDevice {
  /** The APNs device token, lower-case hex. */
  token: string;
  /** base64url of the 65-byte point, as the app registers it. */
  publicKey: string;
  privateKey: Buffer;
  open(envelope: string): Record<string, unknown>;
}

export function makeDevice(tokenBytes = 32): FakeDevice {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  const privateKey = ecdh.getPrivateKey();
  return {
    token: randomBytes(tokenBytes).toString("hex"),
    publicKey: ecdh.getPublicKey().toString("base64url"),
    privateKey,
    open: (envelope) => JSON.parse(openEnvelope(envelope, privateKey)) as Record<string, unknown>,
  };
}

// --------------------------------------------------------------- provider key

export interface ProviderKey {
  /** PKCS#8 PEM, like the .p8 Apple hands out. */
  pem: string;
  keyId: string;
  teamId: string;
  publicKey: KeyObject;
}

export function makeProviderKey(keyId = "KEYID12345", teamId = "TEAM123456"): ProviderKey {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return { pem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(), keyId, teamId, publicKey };
}

/** The env keys that make the gateway send to `fake` with `key`. */
export function apnsEnv(fake: { url: string }, key: ProviderKey, topics = "fi.madekivi.mail"): Record<string, string> {
  return { APNS_URL: fake.url, APNS_TOPIC: topics, APNS_PRIVATE_KEY: key.pem, APNS_KEY_ID: key.keyId, APNS_TEAM_ID: key.teamId };
}

// ----------------------------------------------------------------- fake APNs

export interface ApnsRequest {
  token: string;
  headers: http2.IncomingHttpHeaders;
  body: string;
  bytes: number;
  /** The parsed APNs JSON (null when it was not JSON). */
  json: { aps?: Record<string, unknown>; m?: string; [k: string]: unknown } | null;
  jwt: { header: Record<string, unknown>; claims: Record<string, unknown>; raw: string } | null;
  status: number;
  reason?: string;
  /** Which connection (1-based) carried it. */
  session: number;
}

export interface FakeApns {
  url: string;
  /** The certificate to trust. */
  ca: string;
  requests: ApnsRequest[];
  /** Scripted answers, consumed in order, for requests that pass the checks (default 200), optionally late. */
  script: { status: number; reason?: string; delayMs?: number }[];
  /** Connections accepted so far. */
  sessions: number;
  /** Send GOAWAY on the connection after answering the next request. */
  goawayAfterNext: boolean;
  /** Provider tokens the fake treats as expired (403 ExpiredProviderToken). */
  expiredTokens: Set<string>;
  close(): Promise<void>;
}

let cert: { key: string; cert: string } | null = null;

/** A throwaway self-signed certificate for 127.0.0.1 (openssl; once per test process). */
function testCertificate(): { key: string; cert: string } {
  if (cert) return cert;
  const dir = mkdtempSync(join(tmpdir(), "apns-fake-"));
  try {
    execFileSync(
      "openssl",
      [
        "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem"), "-days", "2",
        "-subj", "/CN=apns-fake.test", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
      ],
      { stdio: "ignore" },
    );
    cert = { key: readFileSync(join(dir, "k.pem"), "utf8"), cert: readFileSync(join(dir, "c.pem"), "utf8") };
    return cert;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function decodeJwt(raw: string): ApnsRequest["jwt"] {
  const [h, c] = raw.split(".");
  try {
    return {
      header: JSON.parse(Buffer.from(h ?? "", "base64url").toString("utf8")) as Record<string, unknown>,
      claims: JSON.parse(Buffer.from(c ?? "", "base64url").toString("utf8")) as Record<string, unknown>,
      raw,
    };
  } catch {
    return null;
  }
}

export async function startFakeApns(key: ProviderKey, topics: string[] = ["fi.madekivi.mail"]): Promise<FakeApns> {
  const { key: tlsKey, cert: tlsCert } = testCertificate();
  const server = http2.createSecureServer({ key: tlsKey, cert: tlsCert, allowHTTP1: false });
  const fake: FakeApns = {
    url: "",
    ca: tlsCert,
    requests: [],
    script: [],
    sessions: 0,
    goawayAfterNext: false,
    expiredTokens: new Set(),
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of live) s.destroy();
        server.close(() => resolve());
      }),
  };
  const live = new Set<http2.ServerHttp2Session>();
  const sessionNo = new WeakMap<http2.ServerHttp2Session, number>();
  server.on("session", (s) => {
    live.add(s);
    sessionNo.set(s, ++fake.sessions);
    s.on("close", () => live.delete(s));
  });

  /** Apple's checks, in Apple's order. */
  function check(headers: http2.IncomingHttpHeaders, jwt: ApnsRequest["jwt"], bytes: number): { status: number; reason?: string } {
    const auth = String(headers.authorization ?? "");
    if (!/^bearer /i.test(auth) || !jwt) return { status: 403, reason: "MissingProviderToken" };
    const [h, c, sig] = jwt.raw.split(".");
    const signed = verify("sha256", Buffer.from(`${h}.${c}`), { key: key.publicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(sig ?? "", "base64url"));
    if (!signed || jwt.header.alg !== "ES256" || jwt.header.kid !== key.keyId || jwt.claims.iss !== key.teamId) {
      return { status: 403, reason: "InvalidProviderToken" };
    }
    const iat = jwt.claims.iat;
    if (typeof iat !== "number" || Date.now() / 1000 - iat > 3600 || fake.expiredTokens.has(jwt.raw)) return { status: 403, reason: "ExpiredProviderToken" };
    const topic = headers["apns-topic"];
    if (!topic) return { status: 400, reason: "MissingTopic" };
    if (!topics.includes(String(topic))) return { status: 400, reason: "TopicDisallowed" };
    if (headers["apns-push-type"] !== "alert") return { status: 400, reason: "InvalidPushType" };
    if (headers["apns-priority"] !== "10") return { status: 400, reason: "BadPriority" };
    if (!/^\d+$/.test(String(headers["apns-expiration"] ?? ""))) return { status: 400, reason: "BadExpirationDate" };
    if (bytes > 4096) return { status: 413, reason: "PayloadTooLarge" };
    return { status: 200 };
  }

  server.on("stream", (stream, headers) => {
    const chunks: Buffer[] = [];
    stream.on("data", (c: Buffer) => chunks.push(c));
    stream.on("end", () => {
      const body = Buffer.concat(chunks);
      const path = String(headers[":path"] ?? "");
      const m = /^\/3\/device\/([0-9a-f]+)$/.exec(path);
      if (headers[":method"] !== "POST" || !m) {
        stream.respond({ ":status": 404 });
        stream.end(JSON.stringify({ reason: "BadPath" }));
        return;
      }
      const auth = String(headers.authorization ?? "");
      const jwt = /^bearer /i.test(auth) ? decodeJwt(auth.slice(7).trim()) : null;
      let answer: { status: number; reason?: string; delayMs?: number } = check(headers, jwt, body.length);
      if (answer.status === 200 && fake.script.length) answer = fake.script.shift()!;
      let json: ApnsRequest["json"] = null;
      try {
        json = JSON.parse(body.toString("utf8")) as ApnsRequest["json"];
      } catch {
        json = null;
      }
      fake.requests.push({
        token: m[1]!,
        headers,
        body: body.toString("utf8"),
        bytes: body.length,
        json,
        jwt,
        status: answer.status,
        ...(answer.reason ? { reason: answer.reason } : {}),
        session: sessionNo.get(stream.session as http2.ServerHttp2Session) ?? 0,
      });
      const apnsId = "00000000-0000-4000-8000-" + randomBytes(6).toString("hex").toUpperCase();
      if (answer.delayMs) {
        const { delayMs, ...later } = answer;
        setTimeout(() => respond(stream, later, apnsId), delayMs);
      } else respond(stream, answer, apnsId);
      if (fake.goawayAfterNext) {
        fake.goawayAfterNext = false;
        const s = stream.session;
        setTimeout(() => s?.goaway(http2.constants.NGHTTP2_NO_ERROR), 5);
      }
    });
  });

  function respond(stream: http2.ServerHttp2Stream, answer: { status: number; reason?: string }, apnsId: string): void {
    if (stream.destroyed || stream.closed) return;
    if (answer.status === 200) {
      stream.respond({ ":status": 200, "apns-id": apnsId });
      stream.end();
    } else {
      stream.respond({ ":status": answer.status, "apns-id": apnsId, "content-type": "application/json" });
      stream.end(JSON.stringify(answer.status === 410 ? { reason: answer.reason ?? "Unregistered", timestamp: Date.now() } : { reason: answer.reason ?? "InternalServerError" }));
    }
  }

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  fake.url = `https://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
  return fake;
}

// ------------------------------------------------------------ signed-in app

/** The native app signed in: a passkey, a grant of the madekivi-ios client from a real code exchange, and its principal. */
export async function signInApp(
  ctx: Pick<import("../../src/types.js").AppContext, "config" | "db" | "log">,
  accountId: string,
  passkeyId?: Buffer,
): Promise<{ grantId: string; accessToken: string; refreshToken: string; principal: import("../../src/core/auth-context.js").Principal; passkeyId: Buffer }> {
  const { TokenStore } = await import("../../src/features/auth/tokens.js");
  const { addTestPasskey } = await import("../helpers.js");
  const { createHash } = await import("node:crypto");
  const pk = passkeyId ?? (await addTestPasskey(ctx, accountId));
  const store = new TokenStore(ctx);
  const verifier = randomBytes(32).toString("base64url");
  const redirectUri = "fi.madekivi.mail:/oauth/callback";
  const code = await store.issueCode({
    clientId: "madekivi-ios",
    accountId,
    passkeyId: pk,
    redirectUri,
    codeChallenge: createHash("sha256").update(verifier).digest("base64url"),
    scopes: ["mail"],
  });
  const t = await store.redeemCode({ code, clientId: "madekivi-ios", redirectUri, codeVerifier: verifier });
  if (!t) throw new Error("code exchange failed");
  const principal = await store.authenticate(t.accessToken);
  if (!principal) throw new Error("no principal");
  return { grantId: t.grantId, accessToken: t.accessToken, refreshToken: t.refreshToken, principal, passkeyId: pk };
}
