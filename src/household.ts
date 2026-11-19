/**
 * What the household server does, with no HTTP in it.
 *
 * Every operation here either succeeds or throws a `Refusal` carrying a code
 * the app turns into one plain sentence ("Test connection names
 * the problem"). The server never interprets the house: it orders blobs it
 * can't read, hands them back, and enforces the handful of rules that need no
 * reading — who may talk to it, which key epoch is current, and which schema
 * version the house is on.
 */
import { randomUUID } from "node:crypto";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  exportPrivateKey,
  generateServerKeyPair,
  importPhoneKey,
  importServerKeyPair,
  linkKey,
  newSetupCode,
  open,
  sha256Hex,
  transportKey,
  type ServerKeyPair,
} from "./crypto.ts";
import { Store, type CopyRow, type PhoneRow } from "./store.ts";

/** Bumped when a phone and a server stop understanding each other: 2 since every key change is signed. */
export const PROTOCOL = 2;

/** This server's version, as `package.json` has it; a test keeps the two equal. The setup guide names it. */
export const SERVER_VERSION = "0.1.5";

export const LIMITS = {
  /** A wrong setup code this many times prints a new one. */
  claimFailures: 5,
  /** A wrong invite proof this many times deletes the invite. */
  inviteFailures: 5,
  /** How long an invite lives. */
  inviteMaxMs: 10 * 60 * 1000,
  /** A wrong recovery proof this many times shuts the code for `recoveryShutMs`. */
  recoveryFailures: 5,
  /**
   * Shut, not deleted: its id crosses the Wi-Fi when it's used, and someone
   * listening could otherwise throw away the household's only way back.
   */
  recoveryShutMs: 10 * 60 * 1000,
  /** How far a request's clock may be from the server's. */
  clockSkewMs: 5 * 60 * 1000,
  /** How long a used nonce is remembered; must exceed twice `clockSkewMs`. */
  nonceKeepMs: 11 * 60 * 1000,
  /** Change batches returned by one sync. */
  batchesPerSync: 500,
  /** Change batches accepted in one sync. */
  batchesPerPush: 500,
  /** Pieces in one file: 1 MiB each, so 4 GiB. */
  piecesPerFile: 4096,
} as const;

export type RefusalCode =
  | "not-set-up"
  | "already-set-up"
  | "bad-setup-code"
  | "bad-proof"
  | "unknown-phone"
  | "removed"
  | "clock"
  | "replay"
  | "invite-gone"
  | "recovery-exists"
  | "recovery-shut"
  | "app-too-old"
  | "copy-first"
  | "copy-behind"
  | "key-changed"
  | "identity-in-use"
  | "server-behind"
  | "not-found"
  | "bad-request"
  | "too-large"
  | "host-not-allowed";

const STATUS: Record<RefusalCode, number> = {
  "not-set-up": 409,
  "already-set-up": 409,
  "bad-setup-code": 401,
  "bad-proof": 401,
  "unknown-phone": 401,
  removed: 403,
  clock: 401,
  replay: 401,
  "invite-gone": 410,
  "recovery-exists": 409,
  "recovery-shut": 429,
  "app-too-old": 409,
  "copy-first": 409,
  "copy-behind": 409,
  "key-changed": 409,
  "identity-in-use": 409,
  "server-behind": 409,
  "not-found": 404,
  "bad-request": 400,
  "too-large": 413,
  "host-not-allowed": 421,
};

export class Refusal extends Error {
  readonly code: RefusalCode;
  readonly status: number;
  readonly details: Record<string, unknown>;

  constructor(code: RefusalCode, details: Record<string, unknown> = {}) {
    super(code);
    this.code = code;
    this.status = STATUS[code];
    this.details = details;
  }
}

export interface Clock {
  now(): number;
}

export const systemClock: Clock = { now: () => Date.now() };

export interface IncomingBatch {
  batch: number;
  epoch: number;
  schemaVersion: number;
  blob: Buffer;
}

export interface Logger {
  info(line: string): void;
}

const ID = /^[A-Za-z0-9_-]{16,64}$/;

export function isId(value: unknown): value is string {
  return typeof value === "string" && ID.test(value);
}

export class Household {
  readonly store: Store;
  readonly keys: ServerKeyPair;
  readonly clock: Clock;
  private readonly log: Logger;

  constructor(dataDir: string, options: { clock?: Clock; log?: Logger } = {}) {
    this.store = new Store(dataDir);
    this.clock = options.clock ?? systemClock;
    this.log = options.log ?? { info: () => undefined };
    this.keys = loadOrCreateKeys(join(dataDir, "server-key"));
    if (!this.isSetUp() && this.store.getMeta("setup_code") === null) this.store.setMeta("setup_code", newSetupCode());
  }

  close(): void {
    this.store.close();
  }

  private nowIso(): string {
    return new Date(this.clock.now()).toISOString();
  }

  isSetUp(): boolean {
    return this.store.getMeta("household_id") !== null;
  }

  householdId(): string {
    const id = this.store.getMeta("household_id");
    if (id === null) throw new Refusal("not-set-up");
    return id;
  }

  /** The code printed in the server's own log until a phone claims it. Never sent over the network. */
  setupCode(): string | null {
    return this.isSetUp() ? null : this.store.getMeta("setup_code");
  }

  epoch(): number {
    return this.store.getNumber("epoch", 1);
  }

  schemaVersion(): number {
    return this.store.getNumber("schema_version", 0);
  }

  /**
   * The oldest version whose changes the house takes: what the phone that put the copy in use said, and never above the
   * house's own. A copy from an older phone says nothing, and then only the
   * house's own version is taken, as before.
   */
  schemaFloor(): number {
    const house = this.schemaVersion();
    const floor = this.store.activeCopy()?.schema_floor;
    return floor === null || floor === undefined ? house : Math.min(floor, house);
  }

  hello() {
    return {
      app: "homecubbie",
      protocol: PROTOCOL,
      version: SERVER_VERSION,
      // The server's clock, so "Test connection" can say this phone's is wrong
      // before a proof is refused for it.
      time: this.clock.now(),
      setUp: this.isSetUp(),
      householdId: this.store.getMeta("household_id"),
      serverKey: this.keys.publicKey.toString("base64url"),
      // The house's database version, which the server holds in clear to
      // order copies and changes. A browser compares its own with it before it
      // spends an invite. 0 until the first copy is in.
      schemaVersion: this.schemaVersion(),
      // The household key's epoch, which already travels in clear beside every
      // change. A phone joining its household again compares it with its own
      // before it spends anything, to know whether it can check the key
      // change. Null until a phone sets it up.
      epoch: this.isSetUp() ? this.epoch() : null,
      // Which phone moved the household here, and which made the key change
      // to the current epoch: a phone joining again says beforehand
      // whether it can check them, and then checks their signatures.
      movedBy: this.movedBy(),
      keyChangedBy: this.isSetUp() ? (this.store.findRekey(this.epoch())?.signed_by ?? null) : null,
    };
  }

  private movedBy(): string | null {
    const first = this.store.firstRekey();
    return first?.kind === "move" ? first.signed_by : null;
  }

  /** The proof the key change to the current epoch carried, or null: epoch 1 has none. */
  currentRekeyProof(): string | null {
    const row = this.store.findRekey(this.epoch());
    return row === undefined ? null : Buffer.from(row.proof).toString("base64url");
  }

  /**
   * Every key change this server holds, each with its signed statement and
   * its proof, for a phone joining again to check from what it held.
   */
  keyChanges() {
    return this.store.listRekeys().flatMap((row) =>
      row.statement === null || row.signature === null
        ? []
        : [
            {
              epoch: row.epoch,
              statement: row.statement,
              signature: Buffer.from(row.signature).toString("base64url"),
              rekeyProof: Buffer.from(row.proof).toString("base64url"),
            },
          ],
    );
  }

  /** A phone's link key, for checking its proofs and signing replies to it. */
  linkKeyFor(phone: PhoneRow): Buffer {
    return linkKey(this.keys, Buffer.from(phone.public_key), this.householdId());
  }

  /**
   * Refuses a phone key that can't make a link key: the wrong length, or a
   * small-order point built so the shared secret would be predictable.
   * OpenSSL refuses those when deriving, so trying is the check.
   */
  private requireUsablePhoneKey(phoneKey: Buffer, householdId: string): void {
    try {
      linkKey(this.keys, phoneKey, householdId);
    } catch {
      throw new Refusal("bad-request");
    }
    if (this.store.listPhones().some((phone) => Buffer.from(phone.public_key).equals(phoneKey))) {
      throw new Refusal("identity-in-use");
    }
  }

  /** The phone behind a request, or a refusal saying why there isn't one. */
  requirePhone(phoneId: string): PhoneRow {
    if (!this.isSetUp()) throw new Refusal("not-set-up");
    const phone = isId(phoneId) ? this.store.findPhone(phoneId) : undefined;
    if (phone === undefined) throw new Refusal("unknown-phone");
    return phone;
  }

  /** Refused for a removed phone. Called after its proof has been checked, so the answer can be signed. */
  requireActive(phone: PhoneRow): void {
    if (phone.removed_at !== null) throw new Refusal("removed");
    this.store.markPhoneSeen(phone.id, this.nowIso());
  }

  checkFresh(timeMs: number, nonce: string): void {
    const now = this.clock.now();
    if (!Number.isFinite(timeMs) || Math.abs(now - timeMs) > LIMITS.clockSkewMs) {
      throw new Refusal("clock", { serverTime: now });
    }
    if (!this.store.rememberNonce(nonce, now, LIMITS.nonceKeepMs)) throw new Refusal("replay");
  }

  // ── setting up ────────────────────────────────────────────────────────

  /**
   * The first phone takes the server. The caller has already checked the
   * request's proof against the setup code; this counts a failure when it
   * hasn't, and prints a new code after `LIMITS.claimFailures` of them.
   */
  countClaimFailure(): void {
    const failures = this.store.getNumber("claim_failures", 0) + 1;
    if (failures >= LIMITS.claimFailures) {
      this.store.setMeta("setup_code", newSetupCode());
      this.store.setMeta("claim_failures", "0");
      this.log.info("Too many wrong setup codes. A new one is below; the old one no longer works.");
      this.printSetupCode();
    } else {
      this.store.setMeta("claim_failures", String(failures));
    }
  }

  printSetupCode(): void {
    const code = this.setupCode();
    if (code !== null) this.log.info(`Setup code: ${code.replace(/(.{4})(?=.)/g, "$1-")}`);
  }

  /**
   * A household moving here from a server that was lost starts at the epoch after its last, with the proof every
   * key change carries: `HMAC` under the data key before. The server
   * can't check it; it keeps it, and a phone joining again that holds the
   * key before checks it, as it checks any key change. A new household
   * starts at 1, with no proof. A move is also signed by the phone that moves
   * it, which the server keeps as it came, as it keeps the proof.
   */
  claim(input: {
    householdId: string;
    phoneId: string;
    phoneKey: Buffer;
    nameBlob: Buffer;
    serverKey: Buffer;
    signingKey: Buffer;
    epoch?: number;
    rekeyProof?: Buffer | null;
    signed?: { statement: string; signature: Buffer } | null;
  }): PhoneRow {
    if (this.isSetUp()) throw new Refusal("already-set-up");
    if (!isId(input.householdId) || !isId(input.phoneId)) throw new Refusal("bad-request");
    // The phone says which server key it saw. If someone on the Wi-Fi swapped
    // it, the proof covered the swap and this refuses it.
    if (!input.serverKey.equals(this.keys.publicKey)) throw new Refusal("bad-proof");
    const epoch = input.epoch ?? 1;
    const proof = input.rekeyProof ?? null;
    if (!Number.isInteger(epoch) || epoch < 1) throw new Refusal("bad-request");
    // A household's first epoch has no key before it, and every later one has a proof.
    if (epoch === 1 ? proof !== null : proof === null || proof.length !== 32) throw new Refusal("bad-request");
    const signed = input.signed ?? null;
    if ((proof === null) !== (signed === null)) throw new Refusal("bad-request");
    this.requireUsablePhoneKey(input.phoneKey, input.householdId);
    return this.store.transaction(() => {
      this.store.setMeta("household_id", input.householdId);
      this.store.setMeta("epoch", String(epoch));
      if (proof !== null && signed !== null) {
        this.store.insertRekey({ epoch, proof, ...signed, signedBy: input.phoneId, kind: "move" });
      }
      this.store.deleteMeta("setup_code");
      this.store.deleteMeta("claim_failures");
      this.store.insertPhone({
        id: input.phoneId,
        publicKey: input.phoneKey,
        nameBlob: input.nameBlob,
        kind: "phone",
        now: this.nowIso(),
        signingKey: input.signingKey,
        door: null,
      });
      this.log.info("A phone set this server up. The setup code no longer works.");
      return this.requirePhone(input.phoneId);
    });
  }

  // ── invites ───────────────────────────────────────────────────────────

  /**
   * An invite, with the door key its maker worked out from the invite's
   * secret and its maker's vouch for it. Kept as they came: the phones
   * check them, and the server can make neither.
   */
  createInvite(
    from: PhoneRow,
    input: {
      inviteId: string;
      sealedVerifier: Buffer;
      packet: Buffer;
      expiresInMs: number;
      doorKey: Buffer;
      doorEpoch: number;
      vouch: Buffer;
    },
  ): void {
    if (!isId(input.inviteId)) throw new Refusal("bad-request");
    if (input.expiresInMs <= 0 || input.expiresInMs > LIMITS.inviteMaxMs) throw new Refusal("bad-request");
    // The join verifier is the one secret a phone sends the server. It comes
    // sealed under that phone's link key, so the Wi-Fi never sees it.
    let verifier: Buffer;
    try {
      verifier = open(transportKey(this.linkKeyFor(from)), input.sealedVerifier, `invite ${input.inviteId}`);
    } catch {
      throw new Refusal("bad-request");
    }
    if (verifier.length !== 32) throw new Refusal("bad-request");
    this.store.deleteExpiredInvites(this.clock.now());
    this.store.insertInvite({
      id: input.inviteId,
      verifier,
      packet: input.packet,
      createdBy: from.id,
      expiresAt: this.clock.now() + input.expiresInMs,
      door: doorOf(input),
    });
  }

  /**
   * The verifier a join's proof is checked against, or a refusal if the invite
   * is gone. The id is an invite's or the recovery code's: the code is
   * an invite with no time limit, so it comes in by the same door.
   */
  inviteVerifier(inviteId: unknown): Buffer {
    if (!isId(inviteId)) throw new Refusal("bad-request");
    this.store.deleteExpiredInvites(this.clock.now());
    const invite = this.store.findInvite(inviteId);
    if (invite !== undefined) return Buffer.from(invite.verifier);
    const recovery = this.store.findRecoveryById(inviteId);
    if (recovery === undefined) throw new Refusal("invite-gone");
    if (recovery.shut_until > this.clock.now()) throw new Refusal("recovery-shut", { until: recovery.shut_until });
    return Buffer.from(recovery.verifier);
  }

  countJoinFailure(inviteId: string): void {
    if (this.store.findInvite(inviteId) !== undefined) {
      if (this.store.countInviteFailure(inviteId) >= LIMITS.inviteFailures) this.store.deleteInvite(inviteId);
      return;
    }
    if (this.store.findRecoveryById(inviteId) === undefined) return;
    if (this.store.countRecoveryFailure(inviteId) >= LIMITS.recoveryFailures) {
      this.store.shutRecovery(inviteId, this.clock.now() + LIMITS.recoveryShutMs);
    }
  }

  /**
   * Uses up the invite, or the recovery code: its packet is returned once and
   * deleted. The phone is kept with how it came in: the door, its
   * maker's vouch for it, and the arrival the phone signed with the door's
   * key and with its own.
   */
  join(input: {
    inviteId: string;
    phoneId: string;
    phoneKey: Buffer;
    nameBlob: Buffer;
    signingKey: Buffer;
    arrival: Buffer;
    arrivalOwn: Buffer;
    /** A browser says so, for the phones to draw it as one. */
    device?: "browser" | null;
  }): { phone: PhoneRow; packet: Buffer } {
    if (!isId(input.phoneId)) throw new Refusal("bad-request");
    this.requireUsablePhoneKey(input.phoneKey, this.householdId());
    return this.store.transaction(() => {
      const now = this.clock.now();
      const invite = this.store.findInvite(input.inviteId);
      const recovery = invite === undefined ? this.store.findRecoveryById(input.inviteId) : undefined;
      let packet: Uint8Array;
      let door: { id: string; created_by: string; door: string | null };
      if (invite !== undefined && invite.expires_at > now) {
        packet = invite.packet;
        door = invite;
      } else if (recovery !== undefined && recovery.shut_until <= now) {
        packet = recovery.packet;
        door = recovery;
      } else {
        throw new Refusal("invite-gone");
      }
      if (this.store.findPhone(input.phoneId) !== undefined) throw new Refusal("identity-in-use");
      if (invite !== undefined) {
        this.store.deleteInvite(invite.id);
      } else {
        // Used once. Every phone's Sharing screen then says when, and which
        // phone came in with it.
        this.store.deleteRecovery();
        this.store.deleteMeta("recovery_ended_at");
        this.store.setMeta("recovery_used_at", this.nowIso());
        this.store.setMeta("recovery_used_by", input.phoneId);
      }
      this.store.insertPhone({
        id: input.phoneId,
        publicKey: input.phoneKey,
        nameBlob: input.nameBlob,
        kind: "phone",
        now: this.nowIso(),
        signingKey: input.signingKey,
        door: arrivalOf(door, input),
        device: input.device ?? null,
      });
      return { phone: this.requirePhone(input.phoneId), packet: Buffer.from(packet) };
    });
  }

  // ── the recovery code ─────────────────────────────────────────────────

  /**
   * A recovery code, made by a phone in the
   * household. It is an invite with no time limit, used once through `join`.
   * It is never a phone, nothing is wrapped for it, and any key change deletes
   * it, so its packet always holds the key in force.
   *
   * One at a time. A phone replaces one by changing the key first, which ends
   * the old code, so a code someone may have seen can't stay good.
   */
  createRecovery(
    from: PhoneRow,
    input: { recoveryId: string; sealedVerifier: Buffer; packet: Buffer; epoch: number; doorKey: Buffer; vouch: Buffer },
  ): void {
    if (!isId(input.recoveryId)) throw new Refusal("bad-request");
    if (input.epoch !== this.epoch()) throw new Refusal("key-changed", { epoch: this.epoch() });
    let verifier: Buffer;
    try {
      verifier = open(transportKey(this.linkKeyFor(from)), input.sealedVerifier, `recovery ${input.recoveryId}`);
    } catch {
      throw new Refusal("bad-request");
    }
    if (verifier.length !== 32) throw new Refusal("bad-request");
    this.store.transaction(() => {
      if (this.store.findRecovery() !== undefined) throw new Refusal("recovery-exists");
      if (this.store.findInvite(input.recoveryId) !== undefined) throw new Refusal("bad-request");
      this.store.insertRecovery({
        id: input.recoveryId,
        verifier,
        packet: input.packet,
        epoch: input.epoch,
        createdBy: from.id,
        now: this.nowIso(),
        door: doorOf({ ...input, doorEpoch: input.epoch }),
      });
      this.store.deleteMeta("recovery_used_at");
      this.store.deleteMeta("recovery_used_by");
      this.store.deleteMeta("recovery_ended_at");
    });
    this.log.info("A phone made a recovery code.");
  }

  /** What every phone's Sharing screen says about the recovery code. Never its id, verifier or packet. */
  recoveryStatus() {
    const row = this.store.findRecovery();
    const usedAt = this.store.getMeta("recovery_used_at");
    const endedAt = this.store.getMeta("recovery_ended_at");
    return {
      recovery: row === undefined ? null : { epoch: row.epoch, madeBy: row.created_by, madeAt: row.created_at },
      used: usedAt === null ? null : { at: usedAt, by: this.store.getMeta("recovery_used_by") },
      // A printed code that stopped working at a key change, so every phone
      // can say so rather than "none yet".
      ended: endedAt === null ? null : { at: endedAt },
    };
  }

  /** Any key change, and any removal, ends the recovery code. Recorded, so the phones can say when. */
  private endRecovery(): void {
    if (!this.store.deleteRecovery()) return;
    this.store.deleteMeta("recovery_used_at");
    this.store.deleteMeta("recovery_used_by");
    this.store.setMeta("recovery_ended_at", this.nowIso());
  }

  /**
   * A phone replaces its own sealed name. A phone that joined by invite can only
   * seal its name once it has opened the invite's packet, after the join.
   */
  renamePhone(phone: PhoneRow, nameBlob: Buffer): void {
    this.store.renamePhone(phone.id, nameBlob);
  }

  removePhone(by: PhoneRow, phoneId: unknown): void {
    if (!isId(phoneId)) throw new Refusal("bad-request");
    const target = this.store.findPhone(phoneId);
    if (target === undefined) throw new Refusal("not-found");
    this.store.transaction(() => {
      this.store.removePhone(target.id, this.nowIso());
      this.store.deleteInvitesBy(target.id);
      // A removal ends the recovery code, on this path as in a key change: whoever is removed may have seen it. Leaving doesn't: the
      // phone that leaves deletes its own keys, and the key doesn't change.
      if (by.id !== target.id) this.endRecovery();
    });
    this.log.info(by.id === target.id ? "A phone left the household." : "A phone was removed from the household.");
  }

  phones() {
    return this.store.listPhones().map((phone) => ({
      phoneId: phone.id,
      phoneKey: Buffer.from(phone.public_key).toString("base64url"),
      nameBlob: Buffer.from(phone.name_blob).toString("base64url"),
      // A browser is listed as one. A phone from before this reads
      // any kind it doesn't know as a phone, which is what it drew already.
      kind: phone.device === "browser" ? "browser" : phone.kind,
      joinedAt: phone.joined_at,
      lastSeenAt: phone.last_seen_at,
      removed: phone.removed_at !== null,
      // What it signed, and how it came in, for the phones to check.
      signingKey: phone.signing_key === null ? null : Buffer.from(phone.signing_key).toString("base64url"),
      door: phone.door === null ? null : (JSON.parse(phone.door) as unknown),
    }));
  }

  // ── changes ───────────────────────────────────────────────────────────

  /**
   * Stores what the phone sent, then returns what it hasn't seen.
   *
   * All of `batches` lands or none of it does. Sending the same batch again
   * is harmless, which is what lets a phone retry after a dropped reply. A
   * different blob under a batch number this phone already used means two
   * installs share one identity — the case an iPhone transfer produces —
   * and is refused rather than silently kept.
   *
   * A batch this server already holds is recognised before its epoch is
   * looked at: one that arrived just before a key change, whose reply
   * was lost, is the same bytes under the old epoch. Refused as `key-changed`
   * it would go again sealed under the new key, as other bytes under its old
   * number, and read as a copied phone. So a request of held batches only is
   * answered as usual, and a `key-changed` refusal names the batches in it
   * this server already holds, for the phone to stop sending rather than
   * seal again.
   */
  sync(phone: PhoneRow, input: { since: number; batches: IncomingBatch[] }) {
    if (!Number.isInteger(input.since) || input.since < 0) throw new Refusal("bad-request");
    if (input.batches.length > LIMITS.batchesPerPush) throw new Refusal("too-large");
    const epoch = this.epoch();
    const house = this.schemaVersion();
    const floor = this.schemaFloor();
    const copy = this.store.activeCopy();
    // Changes up to a reset were dropped, and the copy it made is the whole
    // truth. A phone that hasn't loaded that copy yet starts again from it,
    // and what it sends now isn't stored: it was made against a house that no
    // longer exists. The app says so before anyone resets.
    const droppedThrough = this.store.getNumber("dropped_through", 0);
    const mustLoadCopy = copy !== undefined && (phone.must_reload === 1 || input.since < droppedThrough);
    if (mustLoadCopy) return this.syncReply(phone, copy, copy.through_seq, true);

    this.store.transaction(() => {
      const held: number[] = [];
      const fresh = new Map<number, { batch: IncomingBatch; hash: string }>();
      for (const batch of input.batches) {
        if (!Number.isInteger(batch.batch) || batch.batch < 1) throw new Refusal("bad-request");
        if (!Number.isInteger(batch.schemaVersion) || batch.schemaVersion < 1) throw new Refusal("bad-request");
        const hash = sha256Hex(batch.blob);
        const existing = this.store.findChange(phone.id, batch.batch)?.blob_hash ?? fresh.get(batch.batch)?.hash;
        if (existing === undefined) fresh.set(batch.batch, { batch, hash });
        else if (existing !== hash) throw new Refusal("identity-in-use");
        else if (!fresh.has(batch.batch)) held.push(batch.batch);
      }
      for (const { batch, hash } of fresh.values()) {
        if (batch.epoch !== epoch) throw new Refusal("key-changed", { epoch, held });
        // A phone a version behind keeps sharing, down to the floor.
        if (batch.schemaVersion < floor) throw new Refusal("app-too-old", { schemaVersion: house, schemaFloor: floor });
        if (batch.schemaVersion > house) throw new Refusal("copy-first", { schemaVersion: house });
        this.store.insertChange({
          phoneId: phone.id,
          batch: batch.batch,
          epoch,
          schemaVersion: batch.schemaVersion,
          blob: batch.blob,
          blobHash: hash,
          now: this.nowIso(),
        });
      }
    });

    // The phone has seen changes this server no longer has: it was restored
    // from an old backup, or its folder was replaced. The server says so
    // rather than quietly numbering new changes over the gap, and the app
    // offers a reset from the phone, whose house is whole.
    if (input.since > this.store.lastSeq()) throw new Refusal("server-behind", { lastSeq: this.store.lastSeq() });
    return this.syncReply(phone, copy, input.since, false);
  }

  private syncReply(phone: PhoneRow, copy: CopyRow | undefined, from: number, mustLoadCopy: boolean) {
    const lastSeq = this.store.lastSeq();
    const changes = this.store.changesAfter(from, LIMITS.batchesPerSync);
    const last = changes.at(-1);

    return {
      epoch: this.epoch(),
      schemaVersion: this.schemaVersion(),
      // A phone behind the house reads this to know it may keep sharing.
      schemaFloor: this.schemaFloor(),
      lastSeq,
      // The last batch this server holds from this phone. More than the phone
      // itself has numbered means a second install is using its identity: a
      // phone copied to a new handset by the system's transfer.
      lastBatch: this.store.lastBatchOf(phone.id),
      copy: copy === undefined ? null : describeCopy(copy),
      mustLoadCopy,
      next: last?.seq ?? from,
      more: last !== undefined && last.seq < lastSeq,
      changes: changes.map((row) => ({
        seq: row.seq,
        phoneId: row.phone_id,
        batch: row.batch,
        epoch: row.epoch,
        schemaVersion: row.schema_version,
        blob: Buffer.from(row.blob).toString("base64url"),
      })),
    };
  }

  // ── full copies ───────────────────────────────────────────────────────

  /**
   * Stores a full copy of the house, not yet in use. It becomes the copy every
   * new phone starts from when `activateCopy` or `changeKey` names it.
   *
   * Only a phone on the house's version makes one: a phone behind it shares,
   * but holds a newer phone's details only as changes waiting for its update, so its copy would leave them out.
   */
  uploadCopy(
    phone: PhoneRow,
    input: { epoch: number; schemaVersion: number; throughSeq: number; bytes: Buffer; schemaFloor?: number },
  ): string {
    const epoch = this.epoch();
    if (input.epoch !== epoch && input.epoch !== epoch + 1) throw new Refusal("key-changed", { epoch });
    if (!Number.isInteger(input.schemaVersion) || input.schemaVersion < this.schemaVersion()) {
      throw new Refusal("app-too-old", { schemaVersion: this.schemaVersion(), schemaFloor: this.schemaFloor() });
    }
    if (!Number.isInteger(input.throughSeq) || input.throughSeq < 0 || input.throughSeq > this.store.lastSeq()) {
      throw new Refusal("bad-request");
    }
    const floor = input.schemaFloor;
    if (floor !== undefined && (!Number.isInteger(floor) || floor < 1 || floor > input.schemaVersion)) {
      throw new Refusal("bad-request");
    }
    const id = randomUUID();
    this.store.writeCopyBytes(id, input.bytes);
    this.store.insertCopy({
      id,
      epoch: input.epoch,
      schema_version: input.schemaVersion,
      through_seq: input.throughSeq,
      byte_size: input.bytes.length,
      phone_id: phone.id,
      schema_floor: floor ?? null,
      now: this.nowIso(),
    });
    return id;
  }

  /**
   * Puts an uploaded copy in use, under the current key. This is how the
   * first phone's house arrives and how an updated app raises the house's
   * schema version. A new phone starts from it; the changes it holds stay,
   * so a phone that hasn't synced lately carries on from where it was.
   */
  activateCopy(copyId: unknown): void {
    const copy = this.pendingCopy(copyId);
    if (copy.epoch !== this.epoch()) throw new Refusal("key-changed", { epoch: this.epoch() });
    this.requireCopyPastEarlierKeys(copy);
    this.store.transaction(() => {
      this.store.activateCopy(copy.id);
      this.store.setMeta("schema_version", String(Math.max(copy.schema_version, this.schemaVersion())));
    });
  }

  /**
   * A new household key, after a phone is removed or on "Reset sharing from
   * this phone". It lands in one step with the copy made under it, so no phone
   * ever sees the new epoch without a copy it can read.
   *
   * A reset also drops every change on the server, including other phones'
   * that the copy doesn't hold. The app says so first.
   */
  changeKey(
    phone: PhoneRow,
    input: {
      epoch: number;
      copyId: unknown;
      reset: boolean;
      /** HMAC under the old data key: the phones check it, so this server can't hand them a key of its own. */
      rekeyProof: Buffer;
      /** The change, signed by the phone making it. Kept as it came, and checked by the phones. */
      statement: string;
      signature: Buffer;
      /** A phone to take out in the same step, so it is never out with the old key still in force. */
      remove?: unknown;
      wraps: { phoneId: string; ephemeralKey: Buffer; blob: Buffer }[];
    },
  ) {
    const next = this.epoch() + 1;
    if (input.epoch !== next) throw new Refusal("key-changed", { epoch: this.epoch() });
    if (input.rekeyProof.length !== 32) throw new Refusal("bad-request");
    const copy = this.pendingCopy(input.copyId);
    if (copy.epoch !== next) throw new Refusal("bad-request");
    // A reset's copy covers everything there is, whatever it said (below).
    if (!input.reset) this.requireCopyPastEarlierKeys(copy);
    let removing: PhoneRow | undefined;
    if (input.remove !== undefined) {
      if (!isId(input.remove) || input.remove === phone.id) throw new Refusal("bad-request");
      removing = this.store.findPhone(input.remove);
      if (removing === undefined || removing.removed_at !== null) throw new Refusal("not-found");
    }
    const active = this.store.listPhones().filter((row) => row.removed_at === null && row.id !== removing?.id);
    const wrapped = new Set(input.wraps.map((wrap) => wrap.phoneId));
    // Every phone still in the household must be able to read the new key,
    // or it would be locked out by a phone that forgot it.
    for (const row of active) {
      if (row.id !== phone.id && !wrapped.has(row.id)) throw new Refusal("bad-request", { missing: row.id });
    }
    for (const wrap of input.wraps) {
      if (!active.some((row) => row.id === wrap.phoneId)) throw new Refusal("bad-request");
      importPhoneKey(wrap.ephemeralKey);
    }
    this.store.transaction(() => {
      if (removing !== undefined) {
        this.store.removePhone(removing.id, this.nowIso());
        this.store.deleteInvitesBy(removing.id);
      }
      // Any key change ends the recovery code. Its packet
      // holds the key before, and nothing is wrapped for it, so it could only
      // be a key someone removed still had.
      this.endRecovery();
      this.store.insertRekey({
        epoch: next,
        proof: input.rekeyProof,
        statement: input.statement,
        signature: input.signature,
        signedBy: phone.id,
        kind: input.reset ? "reset" : "change",
      });
      for (const wrap of input.wraps) this.store.insertWrap({ epoch: next, ...wrap });
      this.store.setMeta("epoch", String(next));
      this.store.activateCopy(copy.id);
      this.store.setMeta("schema_version", String(Math.max(copy.schema_version, this.schemaVersion())));
      // Only a reset drops changes: the copy is the whole truth then, and a
      // phone behind it starts again from it. A key change keeps them, sealed
      // under the old key, which every phone still in the household holds.
      if (input.reset) {
        const through = this.store.lastSeq();
        this.store.dropChangesThrough(through);
        this.store.setMeta("dropped_through", String(through));
        // The copy holds everything up to now, whatever the phone said it
        // had seen: after a server restored from a backup, the phone has
        // seen numbers this server never gave out.
        this.store.setCopyThrough(copy.id, through);
        // Every other phone starts again from it, including one that was
        // fully up to date: its house may not be the one this phone reset to.
        this.store.markMustReload(phone.id);
        this.store.clearMustReload(phone.id);
      }
      // Older wraps stay: a phone that missed several key changes walks
      // forward one epoch at a time, checking each against the key before.
    });
    this.log.info(input.reset ? "Sharing was reset from a phone." : "The household key was changed.");
    return { epoch: next, lastSeq: this.store.lastSeq() };
  }

  /**
   * A phone that joins from a copy holds only that copy's key, and reads on
   * from where the copy stops. So a copy must run past every change sealed
   * under a key before its own, or that phone could never open them, and
   * would stop syncing for good. The changes stay: the phones already
   * in the household still hold those keys, and read them.
   */
  private requireCopyPastEarlierKeys(copy: { epoch: number; through_seq: number }): void {
    const needed = this.store.lastSeqSealedBefore(copy.epoch);
    if (copy.through_seq < needed) throw new Refusal("copy-behind", { lastSeq: needed });
  }

  /** A phone has loaded the active copy after a reset, so what it sends counts again. */
  copyLoaded(phone: PhoneRow, copyId: unknown): void {
    const copy = this.store.activeCopy();
    if (copy === undefined || copy.id !== copyId) throw new Refusal("not-found");
    this.store.clearMustReload(phone.id);
  }

  /** This phone's wrap of the key at `epoch` (the current one when not given), with that key change's proof. */
  wrapFor(phone: PhoneRow, epoch: number = this.epoch()) {
    if (!Number.isInteger(epoch) || epoch < 1 || epoch > this.epoch()) throw new Refusal("bad-request");
    const wrap = this.store.findWrap(epoch, phone.id);
    if (wrap === undefined) throw new Refusal("not-found");
    const rekey = this.store.findRekey(wrap.epoch);
    return {
      epoch: wrap.epoch,
      current: this.epoch(),
      ephemeralKey: Buffer.from(wrap.ephemeral_key).toString("base64url"),
      blob: Buffer.from(wrap.blob).toString("base64url"),
      rekeyProof: rekey === undefined ? null : Buffer.from(rekey.proof).toString("base64url"),
      // Who made the change, signed, for the phone to check.
      statement: rekey?.statement ?? null,
      signature: rekey?.signature === null || rekey?.signature === undefined ? null : Buffer.from(rekey.signature).toString("base64url"),
    };
  }

  activeCopyBytes(): { copy: ReturnType<typeof describeCopy>; bytes: Buffer } {
    const copy = this.store.activeCopy();
    if (copy === undefined) throw new Refusal("not-found");
    return { copy: describeCopy(copy), bytes: this.store.readCopyBytes(copy.id) };
  }

  private pendingCopy(copyId: unknown) {
    if (typeof copyId !== "string") throw new Refusal("bad-request");
    const copy = this.store.findCopy(copyId);
    if (copy === undefined) throw new Refusal("not-found");
    return copy;
  }

  // ── files ─────────────────────────────────────────────────────────────

  putPiece(fileId: string, piece: number, bytes: Buffer): void {
    requireFileId(fileId);
    requirePiece(piece);
    const file = this.store.findFile(fileId);
    if (file?.pieces != null) throw new Refusal("bad-request", { reason: "file-complete" });
    this.store.ensureFile(fileId, this.nowIso());
    this.store.writePiece(fileId, piece, bytes);
  }

  getPiece(fileId: string, piece: number): Buffer {
    requireFileId(fileId);
    requirePiece(piece);
    const bytes = this.store.readPiece(fileId, piece);
    if (bytes === null) throw new Refusal("not-found");
    return bytes;
  }

  /** Marks a file whole once every piece from 0 to `pieces - 1` is stored. */
  completeFile(fileId: string, pieces: unknown): void {
    requireFileId(fileId);
    if (!Number.isInteger(pieces) || (pieces as number) < 1 || (pieces as number) > LIMITS.piecesPerFile) {
      throw new Refusal("bad-request");
    }
    const count = pieces as number;
    if (this.store.findFile(fileId) === undefined) throw new Refusal("not-found");
    const stored = new Set(this.store.storedPieces(fileId));
    for (let piece = 0; piece < count; piece += 1) {
      if (!stored.has(piece)) throw new Refusal("bad-request", { missingPiece: piece });
    }
    this.store.completeFile(fileId, count);
  }

  fileStatus(fileId: string) {
    requireFileId(fileId);
    const file = this.store.findFile(fileId);
    if (file === undefined) throw new Refusal("not-found");
    return { fileId, complete: file.pieces !== null, pieces: file.pieces, stored: this.store.storedPieces(fileId) };
  }

  /** Only a phone decides a file is no longer needed: the server can't read which records use it. */
  deleteFile(fileId: string): void {
    requireFileId(fileId);
    this.store.deleteFile(fileId);
  }
}

/** A door as an invite or the recovery code keeps it: its public key, the epoch it was made at, and its maker's vouch. */
function doorOf(input: { doorKey: Buffer; doorEpoch: number; vouch: Buffer }): string {
  if (input.doorKey.length !== 32 || input.vouch.length !== 64 || !Number.isInteger(input.doorEpoch)) throw new Refusal("bad-request");
  return JSON.stringify({ key: input.doorKey.toString("base64url"), epoch: input.doorEpoch, vouch: input.vouch.toString("base64url") });
}

/** How a phone came in, as `phones()` lists it: the door, who made it, the vouch, and the arrival's two signatures. */
function arrivalOf(row: { id: string; created_by: string; door: string | null }, input: { arrival: Buffer; arrivalOwn: Buffer }): string | null {
  if (row.door === null) return null;
  if (input.arrival.length !== 64 || input.arrivalOwn.length !== 64) throw new Refusal("bad-request");
  const door = JSON.parse(row.door) as { key: string; epoch: number; vouch: string };
  return JSON.stringify({
    id: row.id,
    key: door.key,
    epoch: door.epoch,
    by: row.created_by,
    vouch: door.vouch,
    arrival: input.arrival.toString("base64url"),
    arrivalOwn: input.arrivalOwn.toString("base64url"),
  });
}

function describeCopy(copy: { id: string; epoch: number; schema_version: number; through_seq: number; byte_size: number }) {
  return {
    copyId: copy.id,
    epoch: copy.epoch,
    schemaVersion: copy.schema_version,
    throughSeq: copy.through_seq,
    byteSize: copy.byte_size,
  };
}

/** A file is named by a random id the phone made, never by its contents' hash. */
function requireFileId(fileId: string): void {
  if (!/^[0-9a-f]{32}$/.test(fileId)) throw new Refusal("bad-request");
}

function requirePiece(piece: number): void {
  if (!Number.isInteger(piece) || piece < 0 || piece >= LIMITS.piecesPerFile) throw new Refusal("bad-request");
}

function loadOrCreateKeys(path: string): ServerKeyPair {
  if (existsSync(path)) return importServerKeyPair(readFileSync(path));
  const keys = generateServerKeyPair();
  writeFileSync(path, exportPrivateKey(keys.privateKey), { mode: 0o600 });
  chmodSync(path, 0o600);
  return keys;
}
