import "reflect-metadata";
import { createHash, createPublicKey, sign, webcrypto } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { BasicConstraintsExtension, CRLDistributionPointsExtension, Extension, X509CertificateGenerator } from "@peculiar/x509";
import { verifyRegistrationResponse, type RegistrationResponseJSON } from "@simplewebauthn/server";
import { decodeAttestationObject, isoBase64URL, isoCBOR } from "@simplewebauthn/server/helpers";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { upsertAccount } from "../src/core/accounts.js";
import { resetAuthenticators } from "../src/core/auth-context.js";
import { createEnrollToken } from "../src/features/auth/enroll.js";
import { makeAuthPlugin } from "../src/features/auth/index.js";
import { createAuthState } from "../src/features/auth/state.js";
import { CeremonyError, listPasskeys, registrationOptions, verifyRegistration } from "../src/features/auth/webauthn.js";
import type { AppContext } from "../src/types.js";
import { SoftAuthenticator } from "./fake-authenticator.js";
import { makeTestContext } from "./helpers.js";

// Registration asks for attestation "none" and never acts on an attestation
// statement, whatever format a client sends: its certificates are not used,
// and no address named in them is contacted. The fixture is a well-formed
// android-key attestation of the credential, issued by a made-up root, whose
// leaf certificate names a CRL address on a loopback server that counts
// requests.

const BASE = "https://mail.example.test";
const RP_ID = "mail.example.test";
const ctx: AppContext = await makeTestContext({ OAUTH_CLIENT_SECRET_BULWARK: "s".repeat(40), PUBLIC_BASE_URL: BASE });
let now = Date.parse("2026-10-20T12:00:00Z");
const state = createAuthState(ctx, () => now);
const app: FastifyInstance = Fastify();
await app.register(makeAuthPlugin({ now: () => now }), ctx);
await app.ready();
let accountId: string;

/** The loopback server a certificate's CRL address points at; counts every request. */
let crlServer: Server;
let crlHits: string[] = [];
let crlUrl: string;

const authr = () => new SoftAuthenticator({ origin: BASE, rpId: RP_ID });
const sha256 = (b: Uint8Array): Buffer => createHash("sha256").update(b).digest();
const day = 86_400_000;

/** Android Key Attestation's KeyDescription (DER), with `challenge` as its attestationChallenge. */
function keyDescription(challenge: Buffer): Buffer {
  const tlv = (tag: number, body: Buffer) => Buffer.concat([Buffer.from([tag, body.length]), body]);
  return tlv(
    0x30,
    Buffer.concat([
      tlv(0x02, Buffer.from([3])), // attestationVersion
      tlv(0x0a, Buffer.from([1])), // attestationSecurityLevel: trusted environment
      tlv(0x02, Buffer.from([4])), // keymasterVersion
      tlv(0x0a, Buffer.from([1])), // keymasterSecurityLevel
      tlv(0x04, challenge), // attestationChallenge
      tlv(0x04, Buffer.alloc(0)), // uniqueId
      tlv(0x30, Buffer.alloc(0)), // softwareEnforced
      tlv(0x30, Buffer.alloc(0)), // teeEnforced
    ]),
  );
}

/**
 * `res` (a "none" registration from `a`) re-signed as an android-key
 * attestation of the same credential: a leaf certificate with the credential's
 * public key, the key description and a CRL address, issued by a made-up root,
 * and `sig` over authenticatorData || clientDataHash by the credential key.
 * Everything the library checks before path validation holds, so only the
 * root is wrong. `fmt` relabels the statement as another format.
 */
async function withCertificateChain(res: RegistrationResponseJSON, a: SoftAuthenticator, fmt = "android-key"): Promise<RegistrationResponseJSON> {
  const authData = decodeAttestationObject(isoBase64URL.toBuffer(res.response.attestationObject)).get("authData");
  const clientDataHash = sha256(isoBase64URL.toBuffer(res.response.clientDataJSON));
  const priv = a.credentials.get(res.id)!.priv;
  const credentialKey = await webcrypto.subtle.importKey("jwk", createPublicKey(priv).export({ format: "jwk" }), { name: "ECDSA", namedCurve: "P-256" }, true, [
    "verify",
  ]);
  const rootKeys = (await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
  const validity = { notBefore: new Date(Date.now() - day), notAfter: new Date(Date.now() + day) };
  const root = await X509CertificateGenerator.createSelfSigned({
    name: "CN=Examplepaja Test Attestation Root",
    keys: rootKeys,
    ...validity,
    extensions: [new BasicConstraintsExtension(true, undefined, true)],
  });
  const leaf = await X509CertificateGenerator.create({
    subject: "CN=Examplepaja Test Attestation Key",
    issuer: root.subject,
    publicKey: credentialKey,
    signingKey: rootKeys.privateKey,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    ...validity,
    extensions: [new CRLDistributionPointsExtension([crlUrl]), new Extension("1.3.6.1.4.1.11129.2.1.17", false, keyDescription(clientDataHash))],
  });
  const attStmt = new Map<string, unknown>([
    ["alg", -7],
    ["sig", sign("sha256", Buffer.concat([authData, clientDataHash]), priv)],
    ["x5c", [new Uint8Array(leaf.rawData), new Uint8Array(root.rawData)]],
  ]);
  const attestationObject = isoCBOR.encode(
    new Map<string, Parameters<typeof isoCBOR.encode>[0]>([
      ["fmt", fmt],
      ["attStmt", attStmt as Parameters<typeof isoCBOR.encode>[0]],
      ["authData", authData],
    ]),
  );
  return { ...res, response: { ...res.response, attestationObject: isoBase64URL.fromBuffer(attestationObject) } };
}

beforeAll(async () => {
  crlServer = createServer((req, res) => {
    crlHits.push(req.url ?? "");
    res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => crlServer.listen(0, "127.0.0.1", resolve));
  crlUrl = `http://127.0.0.1:${(crlServer.address() as AddressInfo).port}/attestation.crl`;
});
beforeEach(async () => {
  now += 61_000; // a fresh rate-limit window per test
  crlHits = [];
  await ctx.db.exec("DELETE FROM auth_session; DELETE FROM auth_challenge; DELETE FROM auth_enroll_token; DELETE FROM passkey; DELETE FROM auth_audit; DELETE FROM account");
  accountId = (await upsertAccount(ctx, { email: "alice@example.test" })).id;
});
afterEach(() => {
  vi.restoreAllMocks();
});
afterAll(async () => {
  await new Promise((resolve) => crlServer.close(resolve));
  await app.close();
  resetAuthenticators();
  await ctx.db.close();
});

describe("attestation statements", () => {
  // Fixture check: verified as android-key, the response passes everything
  // up to the trust decision on its made-up root.
  it("the fixture is an android-key attestation that only its root keeps from verifying", async () => {
    const a = authr();
    const options = await registrationOptions(state, { id: accountId, email: "alice@example.test" });
    const response = await withCertificateChain(a.register(options), a);
    await expect(
      verifyRegistrationResponse({ response, expectedChallenge: options.challenge, expectedOrigin: BASE, expectedRPID: RP_ID, requireUserVerification: true }),
    ).rejects.toThrow(/root certificate was not a known root certificate/);
  });

  it("an enrollment carrying a certificate chain sends no request and registers an ordinary passkey", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const log = vi.spyOn(ctx.log, "info");
    const a = authr();
    const cookies = new Map<string, string>();
    const go = async (method: "GET" | "POST", url: string, json?: unknown) => {
      const res = await app.inject({
        method,
        url,
        remoteAddress: "10.0.0.1",
        headers: {
          cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join("; "),
          "sec-fetch-site": "same-origin",
          ...(json !== undefined ? { "content-type": "application/json" } : {}),
        },
        ...(json !== undefined ? { payload: JSON.stringify(json) } : {}),
      });
      const set = res.headers["set-cookie"];
      for (const c of set === undefined ? [] : Array.isArray(set) ? set : [set]) {
        const [name, value] = c.split(";")[0]!.split("=");
        if (value) cookies.set(name!, value);
        else cookies.delete(name!);
      }
      return res;
    };
    const { token } = await createEnrollToken(ctx, accountId, now);
    expect((await go("GET", `/auth/enroll/${token}`)).statusCode).toBe(303);
    const options = (await go("POST", "/auth/enroll/options", {})).json();
    const response = await withCertificateChain(a.register(options), a);

    const res = await go("POST", "/auth/enroll/verify", { response, name: "Phone" });
    expect(crlHits).toEqual([]);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ next: "/auth/passkeys" });
    expect(log).toHaveBeenCalledWith({ fmt: "android-key" }, "registration: attestation statement ignored");
    const [passkey] = await listPasskeys(state, accountId);
    expect(passkey).toMatchObject({ name: "Phone", expiresAt: null });
    expect(b64(passkey!.id)).toBe(response.id);

    // The passkey is the credential's own key: it signs in.
    cookies.clear();
    const login = (await go("POST", "/auth/login/options", {})).json();
    expect((await go("POST", "/auth/login/verify", a.authenticate(login))).statusCode).toBe(200);
    expect(crlHits).toEqual([]);
  });

  it("every format is verified as none: nothing from the statement is used, nothing is fetched", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    for (const fmt of ["android-key", "packed", "tpm", "apple", "fido-u2f", "android-safetynet", "none", "made-up"]) {
      const a = authr();
      const options = await registrationOptions(state, { id: accountId, email: "alice@example.test" });
      const plain = a.register(options);
      const info = await verifyRegistration(state, { response: await withCertificateChain(plain, a, fmt), challenge: options.challenge });
      expect(info.fmt, fmt).toBe("none");
      expect(info.credential.id, fmt).toBe(plain.id);
    }
    expect(crlHits).toEqual([]);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("a plain none registration verifies as before, and the response's other checks still apply", async () => {
    const a = authr();
    const options = await registrationOptions(state, { id: accountId, email: "alice@example.test" });
    const plain = a.register(options);
    await expect(verifyRegistration(state, { response: plain, challenge: options.challenge })).resolves.toMatchObject({
      fmt: "none",
      credential: { id: plain.id },
      userVerified: true,
    });
    // Challenge, origin and user verification come from the client and
    // authenticator data, which the statement's removal leaves as sent.
    const chained = (over: Parameters<SoftAuthenticator["register"]>[1]) => withCertificateChain(a.register(options, over), a);
    await expect(verifyRegistration(state, { response: await chained({}), challenge: "another-challenge" })).rejects.toThrow(/challenge/);
    await expect(verifyRegistration(state, { response: await chained({ origin: "https://evil.example.test" }), challenge: options.challenge })).rejects.toThrow(
      /origin/,
    );
    await expect(verifyRegistration(state, { response: await chained({ userVerified: false }), challenge: options.challenge })).rejects.toThrow(
      /User verification/,
    );
    expect(crlHits).toEqual([]);
  });

  it("refuses an attestation object that is not one", async () => {
    const a = authr();
    const options = await registrationOptions(state, { id: accountId, email: "alice@example.test" });
    const plain = a.register(options);
    const authData = decodeAttestationObject(isoBase64URL.toBuffer(plain.response.attestationObject)).get("authData");
    const as = (attestationObject: unknown) => ({ ...plain, response: { ...plain.response, attestationObject } }) as RegistrationResponseJSON;
    const cbor = (m: Map<string, Parameters<typeof isoCBOR.encode>[0]>) => isoBase64URL.fromBuffer(isoCBOR.encode(m));
    for (const bad of [
      undefined,
      42,
      "",
      isoBase64URL.fromBuffer(Buffer.from("not cbor")),
      cbor(new Map([["fmt", "none"]])),
      cbor(new Map<string, Parameters<typeof isoCBOR.encode>[0]>([["authData", authData]])),
      cbor(new Map<string, Parameters<typeof isoCBOR.encode>[0]>([["fmt", 1], ["authData", authData]])),
      cbor(new Map<string, Parameters<typeof isoCBOR.encode>[0]>([["fmt", "none"], ["authData", "text"]])),
    ]) {
      await expect(verifyRegistration(state, { response: as(bad), challenge: options.challenge }), String(bad)).rejects.toBeInstanceOf(CeremonyError);
    }
    await expect(verifyRegistration(state, { response: null as unknown as RegistrationResponseJSON, challenge: options.challenge })).rejects.toBeInstanceOf(
      CeremonyError,
    );
  });
});

const b64 = (b: Uint8Array): string => Buffer.from(b).toString("base64url");
