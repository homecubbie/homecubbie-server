/**
 * Everything the server keeps, in one SQLite file beside a folder of file
 * pieces and full copies.
 *
 * None of it can be read here. Changes, full copies, files and phone names
 * arrive encrypted under the household's data key, which never reaches the
 * server. What is stored in clear is only what the server needs to do its job:
 * arrival order, which phone sent what, the house's schema version, the key
 * epoch, and each phone's public key.
 */
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS phone (
    id TEXT PRIMARY KEY NOT NULL,
    public_key BLOB NOT NULL UNIQUE,
    name_blob BLOB NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('phone', 'paper')),
    joined_at TEXT NOT NULL,
    last_seen_at TEXT,
    removed_at TEXT,
    must_reload INTEGER NOT NULL DEFAULT 0 CHECK (must_reload IN (0, 1)),
    -- Its signing key, and how it came in (JSON: the door, the
    -- vouch for it, and the arrival's two signatures). What the phones
    -- signed, kept as it came; this server checks none of it.
    signing_key BLOB,
    door TEXT,
    -- 'browser' for a browser that joined, so the phones can draw
    -- it as one. Said by the browser, unsigned, like last_seen_at.
    device TEXT CHECK (device IS NULL OR device = 'browser')
  );

  CREATE TABLE IF NOT EXISTS change (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    phone_id TEXT NOT NULL REFERENCES phone(id),
    batch INTEGER NOT NULL,
    epoch INTEGER NOT NULL,
    schema_version INTEGER NOT NULL,
    blob BLOB NOT NULL,
    blob_hash TEXT NOT NULL,
    received_at TEXT NOT NULL,
    UNIQUE (phone_id, batch)
  );

  CREATE TABLE IF NOT EXISTS copy (
    id TEXT PRIMARY KEY NOT NULL,
    epoch INTEGER NOT NULL,
    schema_version INTEGER NOT NULL,
    through_seq INTEGER NOT NULL,
    byte_size INTEGER NOT NULL,
    phone_id TEXT NOT NULL REFERENCES phone(id),
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL,
    -- The oldest version whose changes the house
    -- takes while this copy is in use. Null from a phone older than mixed-version sharing: then only
    -- the copy's own version.
    schema_floor INTEGER
  );

  CREATE TABLE IF NOT EXISTS invite (
    id TEXT PRIMARY KEY NOT NULL,
    verifier BLOB NOT NULL,
    packet BLOB NOT NULL,
    created_by TEXT NOT NULL REFERENCES phone(id),
    expires_at INTEGER NOT NULL,
    failures INTEGER NOT NULL DEFAULT 0,
    door TEXT
  );

  -- The household's recovery code, an invite with
  -- no time limit. At most one. Never a phone, never wrapped for, and deleted
  -- by any key change.
  CREATE TABLE IF NOT EXISTS recovery (
    id TEXT PRIMARY KEY NOT NULL,
    verifier BLOB NOT NULL,
    packet BLOB NOT NULL,
    epoch INTEGER NOT NULL,
    created_by TEXT NOT NULL REFERENCES phone(id),
    created_at TEXT NOT NULL,
    failures INTEGER NOT NULL DEFAULT 0,
    shut_until INTEGER NOT NULL DEFAULT 0,
    door TEXT
  );

  -- Each key change's statement as its signer wrote it, the
  -- signature, which phone sent it, and whether it was a change, a reset or
  -- a move, for /api/hello.
  CREATE TABLE IF NOT EXISTS rekey (
    epoch INTEGER PRIMARY KEY NOT NULL,
    proof BLOB NOT NULL,
    statement TEXT,
    signature BLOB,
    signed_by TEXT,
    kind TEXT
  );

  CREATE TABLE IF NOT EXISTS wrap (
    epoch INTEGER NOT NULL,
    phone_id TEXT NOT NULL REFERENCES phone(id),
    ephemeral_key BLOB NOT NULL,
    blob BLOB NOT NULL,
    PRIMARY KEY (epoch, phone_id)
  );

  CREATE TABLE IF NOT EXISTS file (
    id TEXT PRIMARY KEY NOT NULL,
    pieces INTEGER,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS seen_nonce (
    nonce TEXT PRIMARY KEY NOT NULL,
    seen_at INTEGER NOT NULL
  );
`;

export interface PhoneRow {
  id: string;
  public_key: Uint8Array;
  name_blob: Uint8Array;
  kind: "phone" | "paper";
  joined_at: string;
  last_seen_at: string | null;
  removed_at: string | null;
  /** 1 from a reset until this phone has loaded the copy it made. */
  must_reload: number;
  /** Null only in a folder from before signed key changes. */
  signing_key: Uint8Array | null;
  /** JSON, as `Household.phones` lists it; null for the phone that set the server up or moved the household here. */
  door: string | null;
  /** "browser" for a browser that joined; null for a phone, and for any member of a folder from before. */
  device: "browser" | null;
}

export interface ChangeRow {
  seq: number;
  phone_id: string;
  batch: number;
  epoch: number;
  schema_version: number;
  blob: Uint8Array;
  blob_hash: string;
}

export interface CopyRow {
  id: string;
  epoch: number;
  schema_version: number;
  through_seq: number;
  byte_size: number;
  phone_id: string;
  active: number;
  /** The oldest version whose changes are taken while it is in use; null for its own only. */
  schema_floor: number | null;
}

export interface InviteRow {
  id: string;
  verifier: Uint8Array;
  packet: Uint8Array;
  created_by: string;
  expires_at: number;
  failures: number;
  /** JSON: the door's public key, and its maker's vouch for it. */
  door: string | null;
}

export interface RecoveryRow {
  id: string;
  verifier: Uint8Array;
  packet: Uint8Array;
  epoch: number;
  created_by: string;
  created_at: string;
  failures: number;
  /** Milliseconds; 0 when open. Wrong proofs shut it for a while rather than delete it. */
  shut_until: number;
  door: string | null;
}

export interface RekeyRow {
  epoch: number;
  proof: Uint8Array;
  statement: string | null;
  signature: Uint8Array | null;
  signed_by: string | null;
  kind: string | null;
}

export interface WrapRow {
  epoch: number;
  phone_id: string;
  ephemeral_key: Uint8Array;
  blob: Uint8Array;
}

export class Store {
  readonly db: DatabaseSync;
  readonly dataDir: string;

  constructor(dataDir: string) {
    this.dataDir = dataDir;
    mkdirSync(join(dataDir, "files"), { recursive: true });
    mkdirSync(join(dataDir, "copies"), { recursive: true });
    this.db = new DatabaseSync(join(dataDir, "household.db"));
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;");
    this.db.exec(SCHEMA);
    // A folder made before a column existed gets it here. CREATE TABLE IF
    // NOT EXISTS leaves an existing table as it was.
    this.addColumn("phone", "must_reload", "INTEGER NOT NULL DEFAULT 0 CHECK (must_reload IN (0, 1))");
    // A folder from before signed key changes keeps its phones without a signing
    // key, so no member can trace them: such a household shares again from a
    // new folder.
    this.addColumn("phone", "signing_key", "BLOB");
    this.addColumn("phone", "door", "TEXT");
    // A folder from before browsers were told apart: its browsers stay listed as phones.
    this.addColumn("phone", "device", "TEXT CHECK (device IS NULL OR device = 'browser')");
    this.addColumn("invite", "door", "TEXT");
    this.addColumn("recovery", "door", "TEXT");
    for (const column of ["statement TEXT", "signature BLOB", "signed_by TEXT", "kind TEXT"]) {
      const [name, type] = column.split(" ") as [string, string];
      this.addColumn("rekey", name, type);
    }
    // A folder from before mixed-version sharing keeps its copy, which takes only its own version.
    this.addColumn("copy", "schema_floor", "INTEGER");
  }

  private addColumn(table: string, column: string, definition: string): void {
    const columns = this.db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[];
    if (!columns.some((existing) => existing.name === column)) this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }

  close(): void {
    this.db.close();
  }

  /** Runs `work` in one transaction: all of it lands, or none of it does. */
  transaction<T>(work: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = work();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  // ── meta ──────────────────────────────────────────────────────────────

  getMeta(key: string): string | null {
    const row = this.db.prepare("SELECT value FROM meta WHERE key = ?").get(key) as
      | { value: string }
      | undefined;
    return row?.value ?? null;
  }

  setMeta(key: string, value: string): void {
    this.db
      .prepare("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
      .run(key, value);
  }

  deleteMeta(key: string): void {
    this.db.prepare("DELETE FROM meta WHERE key = ?").run(key);
  }

  getNumber(key: string, fallback: number): number {
    const value = this.getMeta(key);
    return value === null ? fallback : Number(value);
  }

  // ── phones ────────────────────────────────────────────────────────────

  findPhone(id: string): PhoneRow | undefined {
    return this.db.prepare("SELECT * FROM phone WHERE id = ?").get(id) as PhoneRow | undefined;
  }

  listPhones(): PhoneRow[] {
    return this.db.prepare("SELECT * FROM phone ORDER BY joined_at, id").all() as unknown as PhoneRow[];
  }

  insertPhone(row: {
    id: string;
    publicKey: Buffer;
    nameBlob: Buffer;
    kind: "phone" | "paper";
    now: string;
    signingKey: Buffer;
    door: string | null;
    device?: "browser" | null;
  }): void {
    this.db
      .prepare(
        "INSERT INTO phone (id, public_key, name_blob, kind, joined_at, signing_key, door, device) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(row.id, row.publicKey, row.nameBlob, row.kind, row.now, row.signingKey, row.door, row.device ?? null);
  }

  renamePhone(id: string, nameBlob: Buffer): void {
    this.db.prepare("UPDATE phone SET name_blob = ? WHERE id = ?").run(nameBlob, id);
  }

  markPhoneSeen(id: string, now: string): void {
    this.db.prepare("UPDATE phone SET last_seen_at = ? WHERE id = ?").run(now, id);
  }

  removePhone(id: string, now: string): void {
    this.db.prepare("UPDATE phone SET removed_at = ? WHERE id = ? AND removed_at IS NULL").run(now, id);
  }

  // ── changes ───────────────────────────────────────────────────────────

  findChange(phoneId: string, batch: number): ChangeRow | undefined {
    return this.db.prepare("SELECT * FROM change WHERE phone_id = ? AND batch = ?").get(phoneId, batch) as
      | ChangeRow
      | undefined;
  }

  insertChange(row: {
    phoneId: string;
    batch: number;
    epoch: number;
    schemaVersion: number;
    blob: Buffer;
    blobHash: string;
    now: string;
  }): number {
    const result = this.db
      .prepare(
        `INSERT INTO change (phone_id, batch, epoch, schema_version, blob, blob_hash, received_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(row.phoneId, row.batch, row.epoch, row.schemaVersion, row.blob, row.blobHash, row.now);
    return Number(result.lastInsertRowid);
  }

  changesAfter(seq: number, limit: number): ChangeRow[] {
    return this.db
      .prepare("SELECT * FROM change WHERE seq > ? ORDER BY seq LIMIT ?")
      .all(seq, limit) as unknown as ChangeRow[];
  }

  lastSeq(): number {
    const row = this.db.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'change'").get() as
      | { seq: number }
      | undefined;
    return row?.seq ?? 0;
  }

  /** The last change sealed under a key before `epoch`'s, or 0: a copy at `epoch` runs at least this far. */
  lastSeqSealedBefore(epoch: number): number {
    const row = this.db.prepare("SELECT MAX(seq) AS seq FROM change WHERE epoch < ?").get(epoch) as { seq: number | null };
    return row.seq ?? 0;
  }

  lastBatchOf(phoneId: string): number {
    const row = this.db.prepare("SELECT MAX(batch) AS batch FROM change WHERE phone_id = ?").get(phoneId) as {
      batch: number | null;
    };
    return row.batch ?? 0;
  }

  dropChangesThrough(seq: number): void {
    this.db.prepare("DELETE FROM change WHERE seq <= ?").run(seq);
  }

  /** Every phone still in the household but `exceptId` starts again from the copy at its next sync. */
  markMustReload(exceptId: string): void {
    this.db.prepare("UPDATE phone SET must_reload = 1 WHERE id != ? AND removed_at IS NULL").run(exceptId);
  }

  clearMustReload(id: string): void {
    this.db.prepare("UPDATE phone SET must_reload = 0 WHERE id = ?").run(id);
  }

  // ── full copies ───────────────────────────────────────────────────────

  copyPath(id: string): string {
    return join(this.dataDir, "copies", id);
  }

  /** Written to a temporary name and renamed, so a crash never leaves half a copy under the real one. */
  writeCopyBytes(id: string, bytes: Buffer): void {
    const temporary = `${this.copyPath(id)}.partial`;
    writeFileSync(temporary, bytes);
    renameSync(temporary, this.copyPath(id));
  }

  readCopyBytes(id: string): Buffer {
    return readFileSync(this.copyPath(id));
  }

  insertCopy(row: Omit<CopyRow, "active"> & { now: string }): void {
    this.db
      .prepare(
        `INSERT INTO copy (id, epoch, schema_version, through_seq, byte_size, phone_id, active, created_at, schema_floor)
         VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`,
      )
      .run(row.id, row.epoch, row.schema_version, row.through_seq, row.byte_size, row.phone_id, row.now, row.schema_floor);
  }

  findCopy(id: string): CopyRow | undefined {
    return this.db.prepare("SELECT * FROM copy WHERE id = ?").get(id) as CopyRow | undefined;
  }

  activeCopy(): CopyRow | undefined {
    return this.db.prepare("SELECT * FROM copy WHERE active = 1").get() as CopyRow | undefined;
  }

  setCopyThrough(id: string, seq: number): void {
    this.db.prepare("UPDATE copy SET through_seq = ? WHERE id = ?").run(seq, id);
  }

  /** Makes `id` the one active copy and deletes every other copy, row and bytes. */
  activateCopy(id: string): void {
    const others = this.db.prepare("SELECT id FROM copy WHERE id != ?").all(id) as { id: string }[];
    this.db.prepare("DELETE FROM copy WHERE id != ?").run(id);
    this.db.prepare("UPDATE copy SET active = 1 WHERE id = ?").run(id);
    for (const other of others) rmSync(this.copyPath(other.id), { force: true });
  }

  // ── invites ───────────────────────────────────────────────────────────

  insertInvite(row: { id: string; verifier: Buffer; packet: Buffer; createdBy: string; expiresAt: number; door: string }): void {
    this.db
      .prepare("INSERT INTO invite (id, verifier, packet, created_by, expires_at, door) VALUES (?, ?, ?, ?, ?, ?)")
      .run(row.id, row.verifier, row.packet, row.createdBy, row.expiresAt, row.door);
  }

  findInvite(id: string): InviteRow | undefined {
    return this.db.prepare("SELECT * FROM invite WHERE id = ?").get(id) as InviteRow | undefined;
  }

  countInviteFailure(id: string): number {
    this.db.prepare("UPDATE invite SET failures = failures + 1 WHERE id = ?").run(id);
    return this.findInvite(id)?.failures ?? 0;
  }

  deleteInvite(id: string): void {
    this.db.prepare("DELETE FROM invite WHERE id = ?").run(id);
  }

  deleteExpiredInvites(nowMs: number): void {
    this.db.prepare("DELETE FROM invite WHERE expires_at <= ?").run(nowMs);
  }

  deleteInvitesBy(phoneId: string): void {
    this.db.prepare("DELETE FROM invite WHERE created_by = ?").run(phoneId);
  }

  // ── the recovery code ─────────────────────────────────────────────────

  insertRecovery(row: {
    id: string;
    verifier: Buffer;
    packet: Buffer;
    epoch: number;
    createdBy: string;
    now: string;
    door: string;
  }): void {
    this.db
      .prepare("INSERT INTO recovery (id, verifier, packet, epoch, created_by, created_at, door) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(row.id, row.verifier, row.packet, row.epoch, row.createdBy, row.now, row.door);
  }

  /** The household's recovery code, if it has one. There is never more than one. */
  findRecovery(): RecoveryRow | undefined {
    return this.db.prepare("SELECT * FROM recovery LIMIT 1").get() as RecoveryRow | undefined;
  }

  findRecoveryById(id: string): RecoveryRow | undefined {
    return this.db.prepare("SELECT * FROM recovery WHERE id = ?").get(id) as RecoveryRow | undefined;
  }

  countRecoveryFailure(id: string): number {
    this.db.prepare("UPDATE recovery SET failures = failures + 1 WHERE id = ?").run(id);
    return this.findRecoveryById(id)?.failures ?? 0;
  }

  shutRecovery(id: string, untilMs: number): void {
    this.db.prepare("UPDATE recovery SET failures = 0, shut_until = ? WHERE id = ?").run(untilMs, id);
  }

  /** Whether there was one to delete. */
  deleteRecovery(): boolean {
    return Number(this.db.prepare("DELETE FROM recovery").run().changes) > 0;
  }

  // ── wrapped keys ──────────────────────────────────────────────────────

  insertWrap(row: { epoch: number; phoneId: string; ephemeralKey: Buffer; blob: Buffer }): void {
    this.db
      .prepare(
        `INSERT INTO wrap (epoch, phone_id, ephemeral_key, blob) VALUES (?, ?, ?, ?)
         ON CONFLICT(epoch, phone_id) DO UPDATE SET ephemeral_key = excluded.ephemeral_key, blob = excluded.blob`,
      )
      .run(row.epoch, row.phoneId, row.ephemeralKey, row.blob);
  }

  findWrap(epoch: number, phoneId: string): WrapRow | undefined {
    return this.db.prepare("SELECT * FROM wrap WHERE epoch = ? AND phone_id = ?").get(epoch, phoneId) as
      | WrapRow
      | undefined;
  }

  /**
   * A key change's proof, made with the key before it, which this server never
   * has, and its statement as its signer signed it.
   */
  insertRekey(row: { epoch: number; proof: Buffer; statement: string; signature: Buffer; signedBy: string; kind: string }): void {
    this.db
      .prepare("INSERT INTO rekey (epoch, proof, statement, signature, signed_by, kind) VALUES (?, ?, ?, ?, ?, ?)")
      .run(row.epoch, row.proof, row.statement, row.signature, row.signedBy, row.kind);
  }

  findRekey(epoch: number): RekeyRow | undefined {
    return this.db.prepare("SELECT * FROM rekey WHERE epoch = ?").get(epoch) as RekeyRow | undefined;
  }

  /** Every key change this server holds, oldest first. */
  listRekeys(): RekeyRow[] {
    return this.db.prepare("SELECT * FROM rekey ORDER BY epoch").all() as unknown as RekeyRow[];
  }

  /** The first key change this server holds: the move that brought the household here, if one did. */
  firstRekey(): RekeyRow | undefined {
    return this.db.prepare("SELECT * FROM rekey ORDER BY epoch LIMIT 1").get() as RekeyRow | undefined;
  }

  // ── files ─────────────────────────────────────────────────────────────

  fileDir(id: string): string {
    return join(this.dataDir, "files", id);
  }

  ensureFile(id: string, now: string): void {
    this.db.prepare("INSERT INTO file (id, created_at) VALUES (?, ?) ON CONFLICT(id) DO NOTHING").run(id, now);
    mkdirSync(this.fileDir(id), { recursive: true });
  }

  findFile(id: string): { id: string; pieces: number | null } | undefined {
    return this.db.prepare("SELECT id, pieces FROM file WHERE id = ?").get(id) as
      | { id: string; pieces: number | null }
      | undefined;
  }

  writePiece(id: string, piece: number, bytes: Buffer): void {
    const path = join(this.fileDir(id), String(piece));
    writeFileSync(`${path}.partial`, bytes);
    renameSync(`${path}.partial`, path);
  }

  readPiece(id: string, piece: number): Buffer | null {
    const path = join(this.fileDir(id), String(piece));
    return existsSync(path) ? readFileSync(path) : null;
  }

  storedPieces(id: string): number[] {
    if (!existsSync(this.fileDir(id))) return [];
    return readdirSync(this.fileDir(id))
      .filter((name) => /^\d+$/.test(name))
      .map(Number)
      .sort((a, b) => a - b);
  }

  completeFile(id: string, pieces: number): void {
    this.db.prepare("UPDATE file SET pieces = ? WHERE id = ?").run(pieces, id);
  }

  deleteFile(id: string): void {
    this.db.prepare("DELETE FROM file WHERE id = ?").run(id);
    rmSync(this.fileDir(id), { recursive: true, force: true });
  }

  // ── replay protection ─────────────────────────────────────────────────

  /** False if the nonce was already used. Old nonces are pruned as it goes. */
  rememberNonce(nonce: string, nowMs: number, keepMs: number): boolean {
    this.db.prepare("DELETE FROM seen_nonce WHERE seen_at < ?").run(nowMs - keepMs);
    const result = this.db
      .prepare("INSERT INTO seen_nonce (nonce, seen_at) VALUES (?, ?) ON CONFLICT(nonce) DO NOTHING")
      .run(nonce, nowMs);
    return result.changes === 1;
  }
}
