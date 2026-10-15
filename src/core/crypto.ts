import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * AES-256-GCM sealing of secrets at rest (key: `GATEWAY_ENC_KEY`, `config.encKey`).
 * Sealed layout: version(1) | iv(12) | tag(16) | ciphertext.
 */
const VERSION = 1;
const IV_LEN = 12;
const TAG_LEN = 16;

export class CryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CryptoError";
  }
}

const asBuffer = (v: string | Uint8Array): Buffer => (typeof v === "string" ? Buffer.from(v, "utf8") : Buffer.from(v));

function checkKey(key: Buffer): void {
  if (key.length !== 32) throw new CryptoError("encryption key must be 32 bytes");
}

/** Encrypt `plaintext`. `aad` (optional) is authenticated but not stored; pass the same to `open`. */
export function seal(plaintext: string | Uint8Array, key: Buffer, aad?: string | Uint8Array): Buffer {
  checkKey(key);
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_LEN });
  if (aad !== undefined) cipher.setAAD(asBuffer(aad));
  const ct = Buffer.concat([cipher.update(asBuffer(plaintext)), cipher.final()]);
  return Buffer.concat([Buffer.of(VERSION), iv, cipher.getAuthTag(), ct]);
}

/** Decrypt the output of `seal`. Throws `CryptoError` on a wrong key, wrong `aad` or tampering. */
export function open(sealed: Uint8Array, key: Buffer, aad?: string | Uint8Array): Buffer {
  checkKey(key);
  const buf = Buffer.from(sealed);
  if (buf.length < 1 + IV_LEN + TAG_LEN || buf[0] !== VERSION) throw new CryptoError("malformed sealed value");
  const iv = buf.subarray(1, 1 + IV_LEN);
  const tag = buf.subarray(1 + IV_LEN, 1 + IV_LEN + TAG_LEN);
  const ct = buf.subarray(1 + IV_LEN + TAG_LEN);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_LEN });
    if (aad !== undefined) decipher.setAAD(asBuffer(aad));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new CryptoError("cannot open sealed value");
  }
}
