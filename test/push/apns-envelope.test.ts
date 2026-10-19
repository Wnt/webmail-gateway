import { createECDH, generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { envelopeLength, parseDevicePublicKey, sealEnvelope } from "../../src/features/push/apns-envelope.js";
import { openEnvelope } from "./apns-fake.js";

// The shared vectors of the app repo (Tests/Vectors/envelope-v1.json), copied
// unchanged: invented keys and data.
const vectors = JSON.parse(readFileSync(new URL("../fixtures/apns-envelope-v1.json", import.meta.url), "utf8")) as {
  devicePrivateKeyHex: string;
  devicePublicKey: string;
  ephemeralPrivateKeyHex: string;
  saltHex: string;
  nonceHex: string;
  vectors: { name: string; plaintext: string; envelope: string }[];
  wrongKeyEnvelope: string;
};

const hex = (h: string) => Buffer.from(h, "hex");

describe("envelope v1", () => {
  const device = parseDevicePublicKey(vectors.devicePublicKey)!;

  it("the vectors' device key is the public half of their private key", () => {
    const ecdh = createECDH("prime256v1");
    ecdh.setPrivateKey(hex(vectors.devicePrivateKeyHex));
    expect(ecdh.getPublicKey().toString("base64url")).toBe(vectors.devicePublicKey);
    expect(device).not.toBeNull();
  });

  it.each(vectors.vectors.map((v) => [v.name, v] as const))("seal reproduces %s byte for byte", (_, v) => {
    const sealed = sealEnvelope(v.plaintext, device, {
      ephemeralPrivateKey: hex(vectors.ephemeralPrivateKeyHex),
      salt: hex(vectors.saltHex),
      nonce: hex(vectors.nonceHex),
    });
    expect(sealed).toBe(v.envelope);
    expect(sealed.length).toBe(envelopeLength(Buffer.byteLength(v.plaintext)));
  });

  it.each(vectors.vectors.map((v) => [v.name, v] as const))("open decrypts %s", (_, v) => {
    expect(openEnvelope(v.envelope, hex(vectors.devicePrivateKeyHex))).toBe(v.plaintext);
  });

  it("open refuses the wrong-key envelope", () => {
    expect(() => openEnvelope(vectors.wrongKeyEnvelope, hex(vectors.devicePrivateKeyHex))).toThrow();
  });

  it("uses a fresh ephemeral key, salt and nonce per push", () => {
    const a = sealEnvelope("{}", device);
    const b = sealEnvelope("{}", device);
    expect(a).not.toBe(b);
    const ra = Buffer.from(a, "base64url");
    const rb = Buffer.from(b, "base64url");
    expect(ra[0]).toBe(1);
    expect(ra.subarray(1, 66).equals(rb.subarray(1, 66))).toBe(false); // E_pub
    expect(ra.subarray(66, 82).equals(rb.subarray(66, 82))).toBe(false); // salt
    expect(ra.subarray(82, 94).equals(rb.subarray(82, 94))).toBe(false); // nonce
    expect(openEnvelope(a, hex(vectors.devicePrivateKeyHex))).toBe("{}");
  });
});

describe("the device public key", () => {
  it("accepts an uncompressed P-256 point in base64url without padding", () => {
    const ecdh = createECDH("prime256v1");
    ecdh.generateKeys();
    const pub = ecdh.getPublicKey().toString("base64url");
    expect(parseDevicePublicKey(pub)?.length).toBe(65);
  });

  it("refuses anything else", () => {
    const ecdh = createECDH("prime256v1");
    ecdh.generateKeys();
    const raw = ecdh.getPublicKey();
    const offCurve = Buffer.from(raw);
    offCurve[64] = offCurve[64]! ^ 1;
    const p384 = generateKeyPairSync("ec", { namedCurve: "secp384r1" }).publicKey.export({ format: "jwk" });
    const xTooBig = Buffer.concat([Buffer.from([4]), Buffer.alloc(32, 0xff), raw.subarray(33)]);
    for (const bad of [
      raw.toString("base64"), // padding / standard alphabet
      `${raw.toString("base64url")}=`,
      ecdh.getPublicKey(undefined, "compressed").toString("base64url"),
      offCurve.toString("base64url"),
      xTooBig.toString("base64url"),
      Buffer.concat([Buffer.from([4]), Buffer.alloc(64)]).toString("base64url"),
      Buffer.concat([Buffer.from([5]), raw.subarray(1)]).toString("base64url"),
      `${p384.x}${p384.y}`,
      "",
      "x".repeat(87),
      42,
      null,
    ]) {
      expect(parseDevicePublicKey(bad), String(bad)).toBeNull();
    }
  });
});
