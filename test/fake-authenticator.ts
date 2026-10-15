import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";

/**
 * A software WebAuthn authenticator for tests: real P-256 keys, real
 * `none`-attestation registration responses and real ES256 assertions, so the
 * server's verification code paths run for real. Every knob that a verifier
 * must check (origin, RP ID, flags, challenge, user handle, counter) can be
 * overridden to produce a bad response.
 */
export interface SoftAuthenticatorOptions {
  origin: string;
  rpId: string;
  userVerified?: boolean;
  backedUp?: boolean;
}

export interface Overrides {
  origin?: string;
  rpId?: string;
  challenge?: string;
  userVerified?: boolean;
  userHandle?: Buffer | null;
  counter?: number;
  type?: string;
}

interface Credential {
  id: Buffer;
  priv: KeyObject;
  cose: Buffer;
  userHandle: Buffer;
  counter: number;
}

const b64u = (b: Uint8Array | string): string => Buffer.from(b).toString("base64url");
const sha256 = (b: Uint8Array | string): Buffer => createHash("sha256").update(b).digest();

// --- a minimal CBOR encoder (what attestation objects and COSE keys need) ---
function cbor(v: unknown): Buffer {
  const head = (major: number, n: number): Buffer => {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 0x100) return Buffer.from([(major << 5) | 24, n]);
    if (n < 0x10000) return Buffer.from([(major << 5) | 25, n >> 8, n & 0xff]);
    const b = Buffer.alloc(5);
    b[0] = (major << 5) | 26;
    b.writeUInt32BE(n, 1);
    return b;
  };
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") return Buffer.concat([head(3, Buffer.byteLength(v)), Buffer.from(v, "utf8")]);
  if (v instanceof Uint8Array) return Buffer.concat([head(2, v.length), Buffer.from(v)]);
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(cbor)]);
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
  if (typeof v === "object" && v !== null) {
    const e = Object.entries(v);
    return Buffer.concat([head(5, e.length), ...e.flatMap(([k, x]) => [cbor(k), cbor(x)])]);
  }
  throw new Error(`cbor: unsupported ${typeof v}`);
}

export class SoftAuthenticator {
  readonly credentials = new Map<string, Credential>();

  constructor(private readonly o: SoftAuthenticatorOptions) {}

  private flags(over: Overrides, attested: boolean): number {
    const uv = over.userVerified ?? this.o.userVerified ?? true;
    return 0x01 | (uv ? 0x04 : 0) | (this.o.backedUp ? 0x08 | 0x10 : 0) | (attested ? 0x40 : 0);
  }

  private authData(over: Overrides, counter: number, attested?: Buffer): Buffer {
    const c = Buffer.alloc(4);
    c.writeUInt32BE(counter);
    return Buffer.concat([sha256(over.rpId ?? this.o.rpId), Buffer.from([this.flags(over, !!attested)]), c, attested ?? Buffer.alloc(0)]);
  }

  private clientData(type: string, challenge: string, over: Overrides): Buffer {
    return Buffer.from(
      JSON.stringify({ type: over.type ?? type, challenge: over.challenge ?? challenge, origin: over.origin ?? this.o.origin, crossOrigin: false }),
    );
  }

  /** Create a credential for `options.user` and answer as a browser would. */
  register(options: PublicKeyCredentialCreationOptionsJSON, over: Overrides = {}): RegistrationResponseJSON {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" });
    const cose = cbor(
      new Map<number, unknown>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, Buffer.from(jwk.x!, "base64url")],
        [-3, Buffer.from(jwk.y!, "base64url")],
      ]),
    );
    const id = sha256(cose).subarray(0, 16);
    const userHandle = over.userHandle === undefined ? Buffer.from(options.user.id, "base64url") : (over.userHandle ?? Buffer.alloc(0));
    const cred: Credential = { id, priv: privateKey, cose, userHandle, counter: over.counter ?? 0 };
    this.credentials.set(b64u(id), cred);
    const len = Buffer.alloc(2);
    len.writeUInt16BE(id.length);
    const attested = Buffer.concat([Buffer.alloc(16), len, id, cose]);
    const authData = this.authData(over, cred.counter, attested);
    const attestationObject = cbor({ fmt: "none", attStmt: {}, authData });
    return {
      id: b64u(id),
      rawId: b64u(id),
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64u(this.clientData("webauthn.create", options.challenge, over)),
        attestationObject: b64u(attestationObject),
        transports: ["internal"],
      },
    };
  }

  /** Sign a challenge with the credential (the only one, unless `credentialId` picks). */
  authenticate(options: PublicKeyCredentialRequestOptionsJSON, over: Overrides = {}, credentialId?: string): AuthenticationResponseJSON {
    const key = credentialId ?? this.credentials.keys().next().value;
    const cred = key ? this.credentials.get(key) : undefined;
    if (!cred) throw new Error("no credential");
    cred.counter = over.counter ?? cred.counter + 1;
    const clientDataJSON = this.clientData("webauthn.get", options.challenge, over);
    const authData = this.authData(over, cred.counter);
    const signature = sign("sha256", Buffer.concat([authData, sha256(clientDataJSON)]), cred.priv);
    const userHandle = over.userHandle === undefined ? cred.userHandle : over.userHandle;
    return {
      id: b64u(cred.id),
      rawId: b64u(cred.id),
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64u(clientDataJSON),
        authenticatorData: b64u(authData),
        signature: b64u(signature),
        ...(userHandle && userHandle.length ? { userHandle: b64u(userHandle) } : {}),
      },
    };
  }
}
