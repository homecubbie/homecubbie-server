/**
 * A stand-in phone for the server's tests: the phone's half of the household
 * key protocol, written with `node:crypto` so the tests exercise the real
 * protocol end to end.
 *
 * The app's own client will do the same things with expo-crypto
 * and @noble. This file is the reference those must agree with, byte for byte.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  randomBytes,
  sign,
  type KeyObject,
} from "node:crypto";
import { claimKey, claimReplyKey, hkdf, hmac, importPhoneKey, sameBytes } from "../src/crypto.ts";
import { replyProofInput, requestProofInput } from "../src/http-server.ts";

export function seal(key: Buffer, plaintext: Buffer, associatedData: string): Buffer {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(associatedData, "utf8"));
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([nonce, body, cipher.getAuthTag()]);
}

export function open(key: Buffer, sealed: Buffer, associatedData: string): Buffer {
  const decipher = createDecipheriv("aes-256-gcm", key, sealed.subarray(0, 12));
  decipher.setAAD(Buffer.from(associatedData, "utf8"));
  decipher.setAuthTag(sealed.subarray(sealed.length - 16));
  return Buffer.concat([decipher.update(sealed.subarray(12, sealed.length - 16)), decipher.final()]);
}

function raw(publicKey: KeyObject): Buffer {
  const der = publicKey.export({ type: "spki", format: "der" });
  return der.subarray(der.length - 32);
}

/**
 * An Ed25519 key pair from a 32-byte seed: a phone's own signing key,
 * or a door's, worked out from its code. `node:crypto` takes a seed only
 * inside PKCS#8, so the seed goes after that fixed prefix.
 */
export function signingPairFrom(seed: Buffer): { privateKey: KeyObject; publicKey: Buffer } {
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
  return { privateKey, publicKey: raw(createPublicKey(privateKey)) };
}

export function signText(privateKey: KeyObject, text: string): Buffer {
  return sign(null, Buffer.from(text, "utf8"), privateKey);
}

/** A door's key: from an invite's secret, or the recovery code. */
export function doorPair(kind: "invite" | "recovery", secret: Buffer): { privateKey: KeyObject; publicKey: Buffer } {
  return signingPairFrom(hkdf(secret, "", kind === "invite" ? "hc invite sign v1" : "hc recovery sign v1"));
}

export function vouchText(householdId: string, serverKey: Buffer, epoch: number, doorId: string, doorKey: Buffer): string {
  return `hc vouch v1\n${householdId}\n${serverKey.toString("base64url")}\n${epoch}\n${doorId}\n${doorKey.toString("base64url")}`;
}

export function arrivalText(
  householdId: string,
  serverKey: Buffer,
  doorId: string,
  phone: { id: string; publicKey: Buffer; signingKey: Buffer },
): string {
  return [
    "hc arrival v1",
    householdId,
    serverKey.toString("base64url"),
    doorId,
    phone.id,
    phone.publicKey.toString("base64url"),
    phone.signingKey.toString("base64url"),
  ].join("\n");
}

export interface Answer {
  status: number;
  json: Record<string, unknown>;
  bytes: Buffer;
  headers: Headers;
  /** Whether the reply carried a proof this phone could check, and it held. */
  replyProven: boolean;
}

export interface Household {
  id: string;
  key: Buffer;
  epoch: number;
}

/** The household's data key, from the household key. */
export function dataKey(household: Household): Buffer {
  return hkdf(household.key, household.id, "hc data v1");
}

export class Phone {
  readonly id = randomBytes(12).toString("base64url");
  readonly privateKey: KeyObject;
  readonly publicKey: Buffer;
  /** Its Ed25519 key, which signs its key changes, vouches and arrival. */
  readonly signing = signingPairFrom(randomBytes(32));
  readonly baseUrl: string;
  serverKey: Buffer | null = null;
  household: Household | null = null;
  batch = 0;
  since = 0;
  /** Overridden by tests that need to send from a wrong clock. */
  clock: () => number = () => Date.now();

  constructor(baseUrl: string, keyPair?: { privateKey: KeyObject; publicKey: KeyObject }) {
    const pair = keyPair ?? generateKeyPairSync("x25519");
    this.privateKey = pair.privateKey;
    this.publicKey = raw(pair.publicKey);
    this.baseUrl = baseUrl;
  }

  link(): Buffer {
    if (this.serverKey === null || this.household === null) throw new Error("Not joined.");
    const shared = diffieHellman({ privateKey: this.privateKey, publicKey: importPhoneKey(this.serverKey) });
    return hkdf(shared, this.household.id, "hc link v1");
  }

  async hello(): Promise<Record<string, unknown>> {
    const response = await fetch(`${this.baseUrl}/api/hello`);
    return (await response.json()) as Record<string, unknown>;
  }

  /** Sends a request proven with `key`, and checks the reply's proof against `replyKey`. */
  async send(
    method: string,
    path: string,
    options: {
      key: Buffer;
      replyKey?: Buffer | null;
      body?: Buffer | object;
      headers?: Record<string, string>;
      phoneHeader?: boolean;
      nonce?: string;
      time?: number;
      /** Sent in place of `body` after the proof is made, to test tampering. */
      sendBody?: Buffer;
    },
  ): Promise<Answer> {
    const body =
      options.body === undefined
        ? Buffer.alloc(0)
        : Buffer.isBuffer(options.body)
          ? options.body
          : Buffer.from(JSON.stringify(options.body));
    const time = options.time ?? this.clock();
    const nonce = options.nonce ?? randomBytes(16).toString("base64url");
    const proof = hmac(options.key, requestProofInput(method, path, time, nonce, body)).toString("base64url");
    const headers: Record<string, string> = {
      "X-HC-Time": String(time),
      "X-HC-Nonce": nonce,
      "X-HC-Proof": proof,
      ...options.headers,
    };
    if (options.phoneHeader !== false) headers["X-HC-Phone"] = this.id;
    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: method === "GET" || method === "HEAD" ? undefined : (options.sendBody ?? body),
    });
    const bytes = Buffer.from(await response.arrayBuffer());
    let json: Record<string, unknown> = {};
    if ((response.headers.get("content-type") ?? "").startsWith("application/json")) {
      json = JSON.parse(bytes.toString("utf8")) as Record<string, unknown>;
    }
    const replyKey = options.replyKey === undefined ? options.key : options.replyKey;
    const given = response.headers.get("x-hc-reply-proof");
    const replyProven =
      replyKey !== null &&
      given !== null &&
      sameBytes(hmac(replyKey, replyProofInput(nonce, response.status, bytes)), Buffer.from(given, "base64url"));
    return { status: response.status, json, bytes, headers: response.headers, replyProven };
  }

  /** A request from this phone once it has joined. */
  call(method: string, path: string, body?: Buffer | object, headers?: Record<string, string>): Promise<Answer> {
    return this.send(method, path, { key: this.link(), body, headers });
  }

  /** This phone as a roster holds it. */
  entry(): { phoneId: string; signingKey: string; phoneKey: string } {
    return { phoneId: this.id, signingKey: this.signing.publicKey.toString("base64url"), phoneKey: this.publicKey.toString("base64url") };
  }

  /**
   * A key change's statement, signed by this phone, as the app writes one
   * (`src/domain/sync/household-roster.ts`): the server keeps both as they come.
   */
  signedChange(input: {
    epoch: number;
    key: Buffer;
    kind?: "change" | "reset" | "move";
    removed?: string | null;
    roster?: { phoneId: string; signingKey: string; phoneKey: string }[];
  }): { statement: string; signature: string } {
    if (this.household === null || this.serverKey === null) throw new Error("Not joined.");
    const statement = JSON.stringify({
      householdId: this.household.id,
      serverKey: this.serverKey.toString("base64url"),
      epoch: input.epoch,
      keyHash: createHash("sha256").update(input.key).digest("hex"),
      kind: input.kind ?? "change",
      removed: input.removed ?? null,
      signer: this.id,
      roster: input.roster ?? [this.entry()],
    });
    return { statement, signature: signText(this.signing.privateKey, `hc key change v1\n${statement}`).toString("base64url") };
  }

  nameBlob(name: string): Buffer {
    if (this.household === null) throw new Error("Not joined.");
    return seal(dataKey(this.household), Buffer.from(name, "utf8"), `phone name ${this.id}`);
  }

  /**
   * The first phone: makes the household key and takes the server with its
   * setup code. `moving` is a household moving here from a lost server: its own id, at its next epoch, with that key change's proof.
   */
  async claim(
    setupCode: string,
    name = "First phone",
    moving?: { householdId: string; epoch: number; rekeyProof: Buffer | null },
  ): Promise<Answer> {
    const hello = await this.hello();
    this.serverKey = Buffer.from(hello.serverKey as string, "base64url");
    this.household = {
      id: moving?.householdId ?? randomBytes(16).toString("base64url"),
      key: randomBytes(32),
      epoch: moving?.epoch ?? 1,
    };
    const signed = moving === undefined ? null : this.signedChange({ epoch: moving.epoch, key: this.household.key, kind: "move" });
    return this.send("POST", "/api/claim", {
      key: claimKey(setupCode),
      replyKey: claimReplyKey(claimKey(setupCode), this.link()),
      phoneHeader: false,
      body: {
        householdId: this.household.id,
        phoneId: this.id,
        phoneKey: this.publicKey.toString("base64url"),
        nameBlob: this.nameBlob(name).toString("base64url"),
        serverKey: this.serverKey.toString("base64url"),
        signingKey: this.signing.publicKey.toString("base64url"),
        ...(moving === undefined
          ? {}
          : {
              epoch: moving.epoch,
              rekeyProof: moving.rekeyProof === null ? null : moving.rekeyProof.toString("base64url"),
              ...(moving.rekeyProof === null ? {} : signed),
            }),
      },
    });
  }

  /**
   * Makes an invite: uploads the packet and the join verifier, and returns what
   * the QR code would carry. `given` is a secret and the id the app works out
   * from it, for a test where the app joins with the typed code.
   */
  async invite(
    expiresInMs = 10 * 60 * 1000,
    given?: { secret: Buffer; inviteId: string },
  ): Promise<{ inviteId: string; secret: Buffer; answer: Answer }> {
    if (this.household === null || this.serverKey === null) throw new Error("Not joined.");
    const inviteId = given?.inviteId ?? randomBytes(16).toString("base64url");
    const secret = given?.secret ?? randomBytes(16);
    const packetKey = hkdf(secret, "", "hc invite v1");
    const verifier = hkdf(secret, "", "hc join v1");
    const packet = seal(packetKey, this.packetFor(), `invite ${inviteId}`);
    const transport = hkdf(this.link(), "", "hc transport v1");
    const answer = await this.call("POST", "/api/invites", {
      inviteId,
      sealedVerifier: seal(transport, verifier, `invite ${inviteId}`).toString("base64url"),
      packet: packet.toString("base64url"),
      expiresInMs,
      ...this.vouchFor(inviteId, doorPair("invite", secret).publicKey),
    });
    return { inviteId, secret, answer };
  }

  /**
   * Makes the household's recovery code: an invite with no
   * time limit. Returns the code, which no phone keeps.
   */
  async recoveryCode(): Promise<{ code: Buffer; recoveryId: string; answer: Answer }> {
    if (this.household === null || this.serverKey === null) throw new Error("Not joined.");
    const code = randomBytes(20);
    const recoveryId = hkdf(code, "", "hc recovery id v1").subarray(0, 16).toString("base64url");
    const packet = seal(hkdf(code, "", "hc recovery packet v1"), this.packetFor(), `recovery ${recoveryId}`);
    const transport = hkdf(this.link(), "", "hc transport v1");
    const answer = await this.call("POST", "/api/recovery", {
      recoveryId,
      sealedVerifier: seal(transport, hkdf(code, "", "hc recovery join v1"), `recovery ${recoveryId}`).toString("base64url"),
      packet: packet.toString("base64url"),
      epoch: this.household.epoch,
      ...this.vouchFor(recoveryId, doorPair("recovery", code).publicKey),
    });
    return { code, recoveryId, answer };
  }

  /** What an invite's or the recovery code's packet holds: the key, and who the household trusts. */
  private packetFor(): Buffer {
    if (this.household === null || this.serverKey === null) throw new Error("Not joined.");
    return Buffer.from(
      JSON.stringify({
        householdId: this.household.id,
        key: this.household.key.toString("base64url"),
        epoch: this.household.epoch,
        serverKey: this.serverKey.toString("base64url"),
        roster: [this.entry()],
      }),
    );
  }

  /** The door's public key, the epoch it opens at, and this phone's vouch for it. */
  private vouchFor(doorId: string, doorKey: Buffer): { doorKey: string; doorEpoch: number; vouch: string } {
    if (this.household === null || this.serverKey === null) throw new Error("Not joined.");
    const { epoch } = this.household;
    const vouch = signText(this.signing.privateKey, vouchText(this.household.id, this.serverKey, epoch, doorId, doorKey));
    return { doorKey: doorKey.toString("base64url"), doorEpoch: epoch, vouch: vouch.toString("base64url") };
  }

  /** A new phone, with no joined phone left to invite it: joins with the recovery code, through the same door. */
  recover(code: Buffer, serverKey: Buffer): Promise<Answer> {
    const recoveryId = hkdf(code, "", "hc recovery id v1").subarray(0, 16).toString("base64url");
    return this.joinThrough(
      {
        inviteId: recoveryId,
        verifier: hkdf(code, "", "hc recovery join v1"),
        packetKey: hkdf(code, "", "hc recovery packet v1"),
        label: `recovery ${recoveryId}`,
        door: doorPair("recovery", code),
      },
      serverKey,
    );
  }

  /** A new phone: joins with what it read from the QR code. */
  join(invite: { inviteId: string; secret: Buffer }, serverKey: Buffer): Promise<Answer> {
    return this.joinThrough(
      {
        inviteId: invite.inviteId,
        verifier: hkdf(invite.secret, "", "hc join v1"),
        packetKey: hkdf(invite.secret, "", "hc invite v1"),
        label: `invite ${invite.inviteId}`,
        door: doorPair("invite", invite.secret),
      },
      serverKey,
    );
  }

  private async joinThrough(
    door: { inviteId: string; verifier: Buffer; packetKey: Buffer; label: string; door: { privateKey: KeyObject; publicKey: Buffer } },
    serverKey: Buffer,
  ): Promise<Answer> {
    const { verifier } = door;
    // The reply is proven with this phone's link key, which needs the
    // household id the server announces and the server key the QR code named.
    const hello = await this.hello();
    this.serverKey = serverKey;
    this.household = { id: hello.householdId as string, key: Buffer.alloc(0), epoch: 0 };
    // Its arrival, signed with the door's key and with its own.
    const arrival = arrivalText(this.household.id, serverKey, door.inviteId, {
      id: this.id,
      publicKey: this.publicKey,
      signingKey: this.signing.publicKey,
    });
    const answer = await this.send("POST", "/api/join", {
      key: verifier,
      replyKey: this.link(),
      phoneHeader: false,
      body: {
        inviteId: door.inviteId,
        phoneId: this.id,
        phoneKey: this.publicKey.toString("base64url"),
        // The name is sealed under the data key, which this phone only has
        // once it opens the packet. A real phone sends a placeholder here and
        // records its name in the house as a change.
        nameBlob: randomBytes(28).toString("base64url"),
        signingKey: this.signing.publicKey.toString("base64url"),
        arrival: signText(door.door.privateKey, arrival).toString("base64url"),
        arrivalOwn: signText(this.signing.privateKey, arrival).toString("base64url"),
      },
    });
    if (answer.status !== 200) return answer;
    const packet = open(door.packetKey, Buffer.from(answer.json.packet as string, "base64url"), door.label);
    const contents = JSON.parse(packet.toString("utf8")) as {
      householdId: string;
      key: string;
      epoch: number;
      serverKey: string;
    };
    if (!Buffer.from(contents.serverKey, "base64url").equals(serverKey) || contents.householdId !== hello.householdId) {
      throw new Error("The packet names a different server or household.");
    }
    this.household = { id: contents.householdId, key: Buffer.from(contents.key, "base64url"), epoch: contents.epoch };
    return answer;
  }

  /** Encrypts some change rows as one batch, the way a phone's sync does. */
  batchOf(rows: unknown, schemaVersion = 41): { batch: number; epoch: number; schemaVersion: number; blob: string } {
    if (this.household === null) throw new Error("Not joined.");
    this.batch += 1;
    const associated = `change ${this.household.id} ${this.household.epoch} ${this.id} ${this.batch} ${schemaVersion}`;
    const blob = seal(dataKey(this.household), Buffer.from(JSON.stringify(rows)), associated);
    return { batch: this.batch, epoch: this.household.epoch, schemaVersion, blob: blob.toString("base64url") };
  }

  readBatch(change: { phoneId: string; batch: number; epoch: number; schemaVersion: number; blob: string }): unknown {
    if (this.household === null) throw new Error("Not joined.");
    const associated = `change ${this.household.id} ${change.epoch} ${change.phoneId} ${change.batch} ${change.schemaVersion}`;
    return JSON.parse(open(dataKey(this.household), Buffer.from(change.blob, "base64url"), associated).toString("utf8"));
  }

  /** Wraps a household key for another phone's public key, with a one-use key pair. */
  static wrapFor(target: { phoneId: string; phoneKey: Buffer }, household: Household): { phoneId: string; ephemeralKey: string; blob: string } {
    const ephemeral = generateKeyPairSync("x25519");
    const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: importPhoneKey(target.phoneKey) });
    const key = hkdf(shared, household.id, "hc wrap v1");
    const blob = seal(key, Buffer.concat([household.key]), `wrap ${household.id} ${household.epoch} ${target.phoneId}`);
    return { phoneId: target.phoneId, ephemeralKey: raw(ephemeral.publicKey).toString("base64url"), blob: blob.toString("base64url") };
  }

  /** Opens this phone's wrapped key after a key change. */
  unwrap(wrap: { epoch: number; ephemeralKey: string; blob: string }): void {
    if (this.household === null) throw new Error("Not joined.");
    const ephemeral = createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), Buffer.from(wrap.ephemeralKey, "base64url")]),
      format: "der",
      type: "spki",
    });
    const shared = diffieHellman({ privateKey: this.privateKey, publicKey: ephemeral });
    const key = hkdf(shared, this.household.id, "hc wrap v1");
    const householdKey = open(key, Buffer.from(wrap.blob, "base64url"), `wrap ${this.household.id} ${wrap.epoch} ${this.id}`);
    this.household = { ...this.household, key: householdKey, epoch: wrap.epoch };
  }
}
