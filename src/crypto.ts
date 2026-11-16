/**
 * The server's half of the household key scheme, using `node:crypto` only.
 *
 * The server never holds the household key. What it does with cryptography is
 * narrow: it keeps its own X25519 key pair, works out each phone's link key from
 * that phone's public key, checks the proof on every request, signs every
 * reply, and opens the one secret a phone ever sends it (an invite's join
 * verifier), which arrives sealed under that phone's link key.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";

/** HKDF labels. Each must match the phone's, byte for byte. */
export const LABEL = {
  link: "hc link v1",
  claim: "hc claim v1",
  transport: "hc transport v1",
} as const;

/** The fixed DER prefix of an X25519 SubjectPublicKeyInfo, before the 32 raw bytes. */
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

export interface ServerKeyPair {
  privateKey: KeyObject;
  /** The 32 raw bytes every phone pins. */
  publicKey: Buffer;
}

export function generateServerKeyPair(): ServerKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  return { privateKey, publicKey: rawPublicKey(publicKey) };
}

export function exportPrivateKey(key: KeyObject): Buffer {
  return key.export({ type: "pkcs8", format: "der" });
}

export function importServerKeyPair(pkcs8: Buffer): ServerKeyPair {
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return { privateKey, publicKey: rawPublicKey(createPublicKey(privateKey)) };
}

function rawPublicKey(key: KeyObject): Buffer {
  const der = key.export({ type: "spki", format: "der" });
  return der.subarray(der.length - 32);
}

/** Throws if `raw` is not a usable X25519 public key. */
export function importPhoneKey(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new Error("A phone key is 32 bytes.");
  return createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

export function hkdf(secret: Buffer, salt: string, info: string): Buffer {
  return Buffer.from(hkdfSync("sha256", secret, Buffer.from(salt, "utf8"), info, 32));
}

/**
 * The link key one phone shares with this server: neither side ever sends it.
 * X25519 refuses a small-order public key by throwing, so a hostile key fails
 * here rather than producing a predictable secret.
 */
export function linkKey(server: ServerKeyPair, phoneKey: Buffer, householdId: string): Buffer {
  const shared = diffieHellman({ privateKey: server.privateKey, publicKey: importPhoneKey(phoneKey) });
  return hkdf(shared, householdId, LABEL.link);
}

export function hmac(key: Buffer, message: string): Buffer {
  return createHmac("sha256", key).update(message, "utf8").digest();
}

export function sha256Hex(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function sameBytes(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

/** AES-256-GCM, laid out as nonce (12) · ciphertext · tag (16). */
export function seal(key: Buffer, plaintext: Buffer, associatedData: string): Buffer {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(associatedData, "utf8"));
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([nonce, body, cipher.getAuthTag()]);
}

/** Throws if the sealed bytes were altered, or sealed under another key or label. */
export function open(key: Buffer, sealed: Buffer, associatedData: string): Buffer {
  if (sealed.length < 28) throw new Error("Too short to be sealed.");
  const decipher = createDecipheriv("aes-256-gcm", key, sealed.subarray(0, 12));
  decipher.setAAD(Buffer.from(associatedData, "utf8"));
  decipher.setAuthTag(sealed.subarray(sealed.length - 16));
  return Buffer.concat([decipher.update(sealed.subarray(12, sealed.length - 16)), decipher.final()]);
}

/** The key a phone seals secrets under when it sends them to this server. */
export function transportKey(link: Buffer): Buffer {
  return hkdf(link, "", LABEL.transport);
}

const BASE32 = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/**
 * A setup code: 10 random bytes as 16 characters, from an alphabet with no 0/O
 * or 1/I to misread. It only has to stand up to guessing at the door, which
 * `MAX_CLAIM_FAILURES` limits; nothing is ever encrypted under it.
 */
export function newSetupCode(): string {
  const bytes = randomBytes(10);
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return out;
}

/** Spaces and dashes are for reading aloud; case doesn't matter. */
export function normaliseSetupCode(typed: string): string {
  return typed.toUpperCase().replace(/[\s-]/g, "");
}

export function claimKey(setupCode: string): Buffer {
  return hkdf(Buffer.from(normaliseSetupCode(setupCode), "utf8"), "", LABEL.claim);
}

/**
 * What a claim's reply is proven with: the link key and the setup code
 * together. The link key alone would let whoever answered `/api/hello` on the
 * way, with a key of their own, prove the reply too; only the real server also
 * knows the code. The app builds the same key (`household-crypto.ts`).
 */
export function claimReplyKey(claim: Buffer, link: Buffer): Buffer {
  return hmac(claim, `hc claim reply v1\n${link.toString("base64url")}`);
}

export function fromBase64Url(text: unknown, bytes?: number): Buffer {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new Error("Not base64url.");
  }
  const buffer = Buffer.from(text, "base64url");
  if (bytes !== undefined && buffer.length !== bytes) throw new Error(`Expected ${bytes} bytes.`);
  return buffer;
}

export function toBase64Url(bytes: Buffer): string {
  return bytes.toString("base64url");
}
