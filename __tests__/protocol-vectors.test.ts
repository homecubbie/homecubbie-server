/**
 * Fixed inputs, run through the protocol as `node:crypto` implements it, with
 * the outputs written to `protocol-vectors.json`.
 *
 * The app implements the same protocol with `@noble` (`src/domain/sync/household-crypto.ts`)
 * and its own test reads this file and must produce every output byte for
 * byte. That is what proves a phone and this server agree, without either
 * importing the other.
 *
 * This test fails if the outputs drift from the committed file. After a
 * deliberate protocol change, regenerate with:
 *
 *     WRITE_VECTORS=1 npm test
 */
import assert from "node:assert/strict";
import { createCipheriv, createPrivateKey, createPublicKey, diffieHellman, type KeyObject } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { it } from "node:test";
import { claimKey, claimReplyKey, hkdf, hmac, linkKey } from "../src/crypto.ts";
import { replyProofInput, requestProofInput } from "../src/http-server.ts";
import { doorPair, signingPairFrom, signText, vouchText } from "./phone.ts";

const FILE = join(import.meta.dirname, "protocol-vectors.json");
const PKCS8_X25519 = Buffer.from("302e020100300506032b656e04220420", "hex");

function bytes(start: number, length: number): Buffer {
  return Buffer.from(Array.from({ length }, (_, index) => (start + index) & 0xff));
}

function privateKey(raw: Buffer): KeyObject {
  return createPrivateKey({ key: Buffer.concat([PKCS8_X25519, raw]), format: "der", type: "pkcs8" });
}

function publicOf(key: KeyObject): Buffer {
  const der = createPublicKey(key).export({ type: "spki", format: "der" });
  return der.subarray(der.length - 32);
}

function sealWith(key: Buffer, plaintext: Buffer, associatedData: string, nonce: Buffer): Buffer {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(associatedData, "utf8"));
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([nonce, body, cipher.getAuthTag()]);
}

const b64 = (value: Buffer) => value.toString("base64url");

function compute() {
  const phoneRaw = bytes(0x01, 32);
  const serverRaw = bytes(0x21, 32);
  const ephemeralRaw = bytes(0x41, 32);
  const phone = privateKey(phoneRaw);
  const server = privateKey(serverRaw);
  const ephemeral = privateKey(ephemeralRaw);
  const householdId = "hh-vector-0001";
  const householdKey = Buffer.alloc(32, 0xa5);
  const setupCode = "abcd-efgh-jklm-npqr";
  const inviteSecret = bytes(0x10, 16);
  const inviteId = "inv-vector-000001";
  const phoneId = "phone-vector-01";
  const request = {
    method: "POST",
    path: "/api/sync",
    time: 1789000000000,
    nonce: b64(Buffer.alloc(16)),
    body: '{"since":0,"batches":[]}',
  };
  const reply = { status: 200, body: '{"ok":true}' };
  const batch = { epoch: 1, batch: 1, schemaVersion: 44, plaintext: '[{"table":"note","column":"value","value":"4417"}]' };

  const serverKeys = { privateKey: server, publicKey: publicOf(server) };
  const link = linkKey(serverKeys, publicOf(phone), householdId);
  const dataKey = hkdf(householdKey, householdId, "hc data v1");
  const packetKey = hkdf(inviteSecret, "", "hc invite v1");
  const verifier = hkdf(inviteSecret, "", "hc join v1");
  const transport = hkdf(link, "", "hc transport v1");
  const batchLabel = `change ${householdId} ${batch.epoch} ${phoneId} ${batch.batch} ${batch.schemaVersion}`;
  const wrapShared = diffieHellman({ privateKey: ephemeral, publicKey: createPublicKey(phone) });
  const wrapKey = hkdf(wrapShared, householdId, "hc wrap v1");
  const recoveryCode = Buffer.alloc(20, 0x33);
  // Ed25519 is deterministic, so a signature is a vector too.
  const signingSeed = bytes(0x61, 32);
  const signing = signingPairFrom(signingSeed);
  const inviteDoor = doorPair("invite", inviteSecret);

  return {
    inputs: {
      phonePrivateKey: b64(phoneRaw),
      serverPrivateKey: b64(serverRaw),
      ephemeralPrivateKey: b64(ephemeralRaw),
      householdId,
      householdKey: b64(householdKey),
      setupCode,
      inviteSecret: b64(inviteSecret),
      inviteId,
      phoneId,
      request,
      reply,
      batch,
      batchNonce: b64(Buffer.alloc(12, 0x07)),
      wrapEpoch: 2,
      wrapNonce: b64(Buffer.alloc(12, 0x08)),
      recoveryCode: b64(recoveryCode),
      signingSeed: b64(signingSeed),
    },
    outputs: {
      phonePublicKey: b64(publicOf(phone)),
      serverPublicKey: b64(publicOf(server)),
      ephemeralPublicKey: b64(publicOf(ephemeral)),
      linkKey: b64(link),
      dataKey: b64(dataKey),
      claimKey: b64(claimKey(setupCode)),
      claimReplyKey: b64(claimReplyKey(claimKey(setupCode), link)),
      copyReplyProof: b64(hmac(link, replyProofInput(request.nonce, reply.status, Buffer.from(reply.body), '{"copyId":"c","epoch":2,"throughSeq":7}'))),
      invitePacketKey: b64(packetKey),
      inviteVerifier: b64(verifier),
      transportKey: b64(transport),
      requestProof: b64(
        hmac(link, requestProofInput(request.method, request.path, request.time, request.nonce, Buffer.from(request.body))),
      ),
      replyProof: b64(hmac(link, replyProofInput(request.nonce, reply.status, Buffer.from(reply.body)))),
      sealedBatch: b64(sealWith(dataKey, Buffer.from(batch.plaintext), batchLabel, Buffer.alloc(12, 0x07))),
      wrapBlob: b64(sealWith(wrapKey, householdKey, `wrap ${householdId} 2 ${phoneId}`, Buffer.alloc(12, 0x08))),
      // The recovery code is an invite with no time
      // limit. Its id, the packet key and the join verifier, all from the code.
      recoveryId: b64(hkdf(recoveryCode, "", "hc recovery id v1").subarray(0, 16)),
      recoveryPacketKey: b64(hkdf(recoveryCode, "", "hc recovery packet v1")),
      recoveryVerifier: b64(hkdf(recoveryCode, "", "hc recovery join v1")),
      // A member's signing key, the doors' keys from their codes,
      // and a vouch for the invite's door, signed.
      signingPublicKey: b64(signing.publicKey),
      inviteDoorKey: b64(inviteDoor.publicKey),
      recoveryDoorKey: b64(doorPair("recovery", recoveryCode).publicKey),
      vouchSignature: b64(signText(signing.privateKey, vouchText(householdId, publicOf(server), 1, inviteId, inviteDoor.publicKey))),
    },
  };
}

it("the protocol's outputs match the committed vectors the app is held to", () => {
  const computed = compute();
  if (process.env.WRITE_VECTORS === "1") writeFileSync(FILE, `${JSON.stringify(computed, null, 2)}\n`);
  assert.deepEqual(JSON.parse(readFileSync(FILE, "utf8")), computed);
});
