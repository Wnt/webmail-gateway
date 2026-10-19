import { createCipheriv, createECDH, hkdfSync, randomBytes } from "node:crypto";

/**
 * Envelope v1 of the native app's push payload (design/ios-native-app.md,
 * "What Apple sees, and the encrypted part"): everything about the message
 * travels encrypted to the device's own P-256 key, so Apple sees only a
 * generic alert and this opaque string.
 *
 *   base64url(0x01 | E_pub (65) | salt (16) | nonce (12) | ciphertext | tag (16))
 *
 * E is a fresh P-256 key pair per push; shared = ECDH x-coordinate of E_priv
 * and the device key D_pub; key = HKDF-SHA256(shared, salt,
 * "madekivi-mail apns v1\0" | D_pub | E_pub, 32); AES-256-GCM with that key
 * and the random nonce, no additional data. The app's test vectors
 * (Tests/Vectors/envelope-v1.json) are copied to
 * test/fixtures/apns-envelope-v1.json and checked byte for byte.
 */

export const ENVELOPE_VERSION = 0x01;
/** The HKDF info prefix, 22 bytes including the trailing NUL. */
export const ENVELOPE_INFO = Buffer.from("madekivi-mail apns v1\0", "latin1");
const POINT_BYTES = 65;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
/** Envelope bytes besides the ciphertext: version, E_pub, salt, nonce, tag. */
export const ENVELOPE_OVERHEAD = 1 + POINT_BYTES + SALT_BYTES + NONCE_BYTES + TAG_BYTES;

/** For tests only: fixed randomness, so the shared vectors can be reproduced. */
export interface EnvelopeRandomness {
  /** The ephemeral private scalar (32 bytes). */
  ephemeralPrivateKey?: Buffer;
  salt?: Buffer;
  nonce?: Buffer;
}

// P-256: y^2 = x^3 - 3x + b (mod p)
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

const toBig = (b: Buffer): bigint => BigInt(`0x${b.toString("hex") || "0"}`);
const mod = (a: bigint): bigint => ((a % P) + P) % P;

/**
 * The device key from its registration: base64url (no padding) of the
 * 65-byte uncompressed point, which must lie on P-256. Returns the point, or
 * null for anything else (compressed points, padding, other curves, junk).
 */
export function parseDevicePublicKey(v: unknown): Buffer | null {
  if (typeof v !== "string" || !/^[A-Za-z0-9_-]{87}$/.test(v)) return null;
  const raw = Buffer.from(v, "base64url");
  if (raw.length !== POINT_BYTES || raw[0] !== 0x04 || raw.toString("base64url") !== v) return null;
  const x = toBig(raw.subarray(1, 33));
  const y = toBig(raw.subarray(33, 65));
  if (x >= P || y >= P) return null;
  if (mod(y * y) !== mod(x * x * x - 3n * x + B)) return null;
  return raw;
}

/** The base64url length of an envelope around `plaintextBytes` bytes (no padding). */
export function envelopeLength(plaintextBytes: number): number {
  return Math.ceil(((ENVELOPE_OVERHEAD + plaintextBytes) * 4) / 3);
}

/** Encrypt `plaintext` to the device key `devicePublicKey` (the 65-byte point). */
export function sealEnvelope(plaintext: Buffer | string, devicePublicKey: Buffer, rand: EnvelopeRandomness = {}): string {
  const ecdh = createECDH("prime256v1");
  if (rand.ephemeralPrivateKey) ecdh.setPrivateKey(rand.ephemeralPrivateKey);
  else ecdh.generateKeys();
  const ePub = ecdh.getPublicKey(); // uncompressed, 65 bytes
  const shared = ecdh.computeSecret(devicePublicKey); // the x-coordinate, 32 bytes
  const salt = rand.salt ?? randomBytes(SALT_BYTES);
  const nonce = rand.nonce ?? randomBytes(NONCE_BYTES);
  if (salt.length !== SALT_BYTES || nonce.length !== NONCE_BYTES) throw new Error("bad envelope randomness");
  const key = Buffer.from(hkdfSync("sha256", shared, salt, Buffer.concat([ENVELOPE_INFO, devicePublicKey, ePub]), 32));
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const body = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : plaintext;
  const ct = Buffer.concat([cipher.update(body), cipher.final()]);
  return Buffer.concat([Buffer.from([ENVELOPE_VERSION]), ePub, salt, nonce, ct, cipher.getAuthTag()]).toString("base64url");
}
