/**
 * The household server's HTTP face: `node:http`, nothing else.
 *
 * Anything outside `/api` is the web app: HomeCubbie's web build,
 * from a list read once at start (`web-app.ts`), or this page when the server
 * was started without one. The `/api` routes are of three kinds, checked in
 * this order:
 *
 *  1. **Open:** `GET /api/hello`. It says what this is, whether it has been
 *     set up, its public key and the house's database version. Nothing secret.
 *  2. **Door:** `POST /api/claim` and `POST /api/join`. Proven with a key
 *     derived from the setup code or from an invite, because the phone has no
 *     link key yet.
 *  3. **Phone:** everything else. Proven with that phone's link key, which
 *     neither side ever sends.
 *
 * Every proof covers the method, the path, the time, a one-use nonce and the
 * body's hash, and every reply to a known phone carries a proof back, so a
 * phone can tell its own server from another one at the same address. No
 * token, cookie or password crosses the network.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { claimKey, claimReplyKey, fromBase64Url, hmac, sameBytes, sha256Hex } from "./crypto.ts";
import { Household, Refusal, type IncomingBatch } from "./household.ts";
import { answerHomeOnly } from "./home-network.ts";
import type { PhoneRow } from "./store.ts";
import type { WebApp, WebFile } from "./web-app.ts";

export const BODY_LIMITS = {
  json: 16 * 1024 * 1024,
  /** A 1 MiB piece plus its nonce and tag, with room to spare. */
  piece: 1024 * 1024 + 1024,
  copy: 256 * 1024 * 1024,
} as const;

export interface ServerOptions {
  /** Host names this server answers to besides IP addresses and `localhost`. */
  hostNames?: readonly string[];
  /** The web build to serve outside `/api`, or none: then only the landing page. */
  webApp?: WebApp | null;
  /** Answer any address, not only this computer and the home ranges (`home-network.ts`). */
  anyAddress?: boolean;
  /** Answer this computer and nothing else, even with `anyAddress` (`home-network.ts`). */
  thisComputerOnly?: boolean;
  /** Where the server says what it refused. */
  log?: { info(line: string): void };
}

const SECURITY_HEADERS: Record<string, string> = {
  "Cache-Control": "no-store",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

const LANDING_PAGE = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HomeCubbie server</title>
<h1>HomeCubbie server</h1>
<p>This computer holds a household's HomeCubbie data, encrypted. It can't read it, and it never contacts anyone.</p>
<p>To connect a phone, open HomeCubbie on it and go to Settings › Sharing.</p>`;

/**
 * For a browser that reached the server by a name it wasn't given. It repeats
 * nothing from the request, so nothing a link put there is shown back.
 */
const REFUSED_HOST_PAGE = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HomeCubbie</title>
<h1>This server doesn't answer to that name</h1>
<p>A HomeCubbie server answers to its own address, to localhost on its own computer, and to the names it was given in HOMECUBBIE_HOSTS.</p>
<p>If this is your household's server and you reached it by a name, add the name to HOMECUBBIE_HOSTS where the server runs, and start it again.</p>`;

/**
 * Sent with every file of the web app. Cross-origin isolation is what
 * the web build's database needs for its worker. The Content-Security-Policy and Cache-Control are added
 * per file.
 */
const WEB_HEADERS: Record<string, string> = {
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

/** A file named by its hash never changes; anything else may with the next build. */
const CACHE_HASHED = "public, max-age=31536000, immutable";

interface Reply {
  status: number;
  json?: unknown;
  bytes?: Buffer;
  headers?: Record<string, string>;
}

interface Signed {
  method: string;
  path: string;
  time: number;
  nonce: string;
  proof: Buffer;
  body: Buffer;
}

export function createHouseholdServer(household: Household, options: ServerOptions = {}): Server {
  const server = createServer(householdRequestListener(household, options));
  answerHomeOnly(server, options);
  return server;
}

/**
 * What answers every request, over plain http on the phones' port and, given
 * a certificate, over HTTPS for a browser on another computer: the
 * same routes, proofs and Host check on both, so neither is a side door.
 */
export function householdRequestListener(
  household: Household,
  options: ServerOptions = {},
): (request: IncomingMessage, response: ServerResponse) => void {
  const hostNames = new Set((options.hostNames ?? []).map((name) => name.toLowerCase()));
  const webApp = options.webApp ?? null;

  return (request, response) => {
    if (!/^\/api(?:[/?]|$)/.test(request.url ?? "/")) {
      serveWeb(request, response, webApp, hostNames);
      return;
    }
    handle(household, hostNames, request)
      .then((outcome) => send(response, outcome.reply, outcome.replyKey, outcome.nonce))
      .catch((error: unknown) => {
        const refusal = error instanceof Refusal ? error : null;
        if (refusal === null) console.error("homecubbie-server: unexpected error", error);
        const reply: Reply = refusal
          ? { status: refusal.status, json: { error: refusal.code, ...refusal.details } }
          : { status: 500, json: { error: "server-error" } };
        const signing = error instanceof SignedRefusal ? error : null;
        send(response, reply, signing?.replyKey ?? null, signing?.nonce ?? null);
      });
  };
}

/** A refusal to a phone whose proof checked out, so the refusal can be signed too. */
class SignedRefusal extends Refusal {
  readonly replyKey: Buffer;
  readonly nonce: string;
  constructor(inner: Refusal, replyKey: Buffer, nonce: string) {
    super(inner.code, inner.details);
    this.replyKey = replyKey;
    this.nonce = nonce;
  }
}

async function handle(
  household: Household,
  hostNames: Set<string>,
  request: IncomingMessage,
): Promise<{ reply: Reply; replyKey: Buffer | null; nonce: string | null }> {
  checkHost(request, hostNames);
  const url = new URL(request.url ?? "/", "http://placeholder");
  const method = request.method ?? "GET";
  const path = url.pathname + url.search;

  if (method === "GET" && url.pathname === "/api/hello") {
    return { reply: { status: 200, json: household.hello() }, replyKey: null, nonce: null };
  }

  // Before the body, who is asking: a phone this server knows, or one of the
  // two doors. Anyone who can reach the port could otherwise make it hold a
  // whole upload in memory before it knew.
  const door = method === "POST" && (url.pathname === "/api/claim" || url.pathname === "/api/join");
  if (!door) household.requirePhone(request.headers["x-hc-phone"] as string);
  const body = await readBody(request, bodyLimitFor(method, url.pathname));
  const signed = readSignature(request, method, path, body);

  if (method === "POST" && url.pathname === "/api/claim") {
    const code = household.setupCode();
    if (code === null) throw new Refusal("already-set-up");
    if (!proofHolds(claimKey(code), signed)) {
      household.countClaimFailure();
      throw new Refusal("bad-setup-code");
    }
    household.checkFresh(signed.time, signed.nonce);
    const input = parseJson(body);
    const phone = household.claim({
      householdId: requireString(input.householdId),
      phoneId: requireString(input.phoneId),
      phoneKey: decode(input.phoneKey, 32),
      nameBlob: decode(input.nameBlob),
      serverKey: decode(input.serverKey, 32),
      signingKey: decode(input.signingKey, 32),
      // A household moving here starts at its next epoch,
      // with the move signed by the phone moving it.
      ...(input.epoch === undefined ? {} : { epoch: requireInteger(input.epoch) }),
      ...(input.rekeyProof === undefined || input.rekeyProof === null ? {} : { rekeyProof: decode(input.rekeyProof, 32) }),
      ...(input.statement === undefined
        ? {}
        : { signed: { statement: requireStatement(input.statement), signature: decode(input.signature, 64) } }),
    });
    return {
      reply: { status: 200, json: { householdId: household.householdId(), epoch: household.epoch() } },
      replyKey: claimReplyKey(claimKey(code), household.linkKeyFor(phone)),
      nonce: signed.nonce,
    };
  }

  if (method === "POST" && url.pathname === "/api/join") {
    const input = parseJson(body);
    const inviteId = requireString(input.inviteId);
    const verifier = household.inviteVerifier(inviteId);
    if (!proofHolds(verifier, signed)) {
      household.countJoinFailure(inviteId);
      throw new Refusal("bad-proof");
    }
    household.checkFresh(signed.time, signed.nonce);
    const { phone, packet } = household.join({
      inviteId,
      phoneId: requireString(input.phoneId),
      phoneKey: decode(input.phoneKey, 32),
      nameBlob: decode(input.nameBlob),
      signingKey: decode(input.signingKey, 32),
      arrival: decode(input.arrival, 64),
      arrivalOwn: decode(input.arrivalOwn, 64),
      // Only "browser" means anything; whatever else is a phone.
      device: input.device === "browser" ? "browser" : null,
    });
    return {
      reply: {
        status: 200,
        json: {
          householdId: household.householdId(),
          epoch: household.epoch(),
          packet: packet.toString("base64url"),
          // The proof of the change to this epoch, for a phone joining again
          // that holds the key before to check.
          rekeyProof: household.currentRekeyProof(),
          // Every signed key change, and every phone with how it came in, for
          // a phone joining again to check the key from what it held.
          keyChanges: household.keyChanges(),
          phones: household.phones(),
        },
      },
      replyKey: household.linkKeyFor(phone),
      nonce: signed.nonce,
    };
  }

  // Everything else is a joined phone's.
  const phone = household.requirePhone(request.headers["x-hc-phone"] as string);
  const key = household.linkKeyFor(phone);
  if (!proofHolds(key, signed)) throw new Refusal("bad-proof");
  try {
    household.checkFresh(signed.time, signed.nonce);
    household.requireActive(phone);
    const reply = route(household, phone, method, url, request, body);
    return { reply, replyKey: key, nonce: signed.nonce };
  } catch (error) {
    if (error instanceof Refusal) throw new SignedRefusal(error, key, signed.nonce);
    throw error;
  }
}

function route(household: Household, phone: PhoneRow, method: string, url: URL, request: IncomingMessage, body: Buffer): Reply {
  const path = url.pathname;
  const file = /^\/api\/files\/([0-9a-f]{32})(?:\/(\d+))?$/.exec(path);

  if (method === "POST" && path === "/api/sync") {
    const input = parseJson(body);
    if (!Array.isArray(input.batches)) throw new Refusal("bad-request");
    const batches: IncomingBatch[] = input.batches.map((raw: unknown) => {
      const item = requireObject(raw);
      return {
        batch: requireInteger(item.batch),
        epoch: requireInteger(item.epoch),
        schemaVersion: requireInteger(item.schemaVersion),
        blob: decode(item.blob),
      };
    });
    return { status: 200, json: household.sync(phone, { since: requireInteger(input.since), batches }) };
  }

  if (method === "GET" && path === "/api/phones") return { status: 200, json: { phones: household.phones() } };

  // No route adds a phone except an invite. A route that let any member add a
  // "paper" phone, for a recovery code, let a member plant one the others
  // couldn't see or remove. The recovery code is an invite instead,
  // used through `/api/join` like any other.

  if (method === "POST" && path === "/api/phones/name") {
    household.renamePhone(phone, decode(parseJson(body).nameBlob));
    return { status: 200, json: { ok: true } };
  }

  if (method === "POST" && path === "/api/phones/remove") {
    household.removePhone(phone, parseJson(body).phoneId);
    return { status: 200, json: { ok: true } };
  }

  if (method === "POST" && path === "/api/leave") {
    household.removePhone(phone, phone.id);
    return { status: 200, json: { ok: true } };
  }

  if (method === "POST" && path === "/api/invites") {
    const input = parseJson(body);
    household.createInvite(phone, {
      inviteId: requireString(input.inviteId),
      sealedVerifier: decode(input.sealedVerifier),
      packet: decode(input.packet),
      expiresInMs: requireInteger(input.expiresInMs),
      doorKey: decode(input.doorKey, 32),
      doorEpoch: requireInteger(input.doorEpoch),
      vouch: decode(input.vouch, 64),
    });
    return { status: 200, json: { ok: true } };
  }

  if (method === "POST" && path === "/api/recovery") {
    const input = parseJson(body);
    household.createRecovery(phone, {
      recoveryId: requireString(input.recoveryId),
      sealedVerifier: decode(input.sealedVerifier),
      packet: decode(input.packet),
      epoch: requireInteger(input.epoch),
      doorKey: decode(input.doorKey, 32),
      vouch: decode(input.vouch, 64),
    });
    return { status: 200, json: { ok: true } };
  }

  if (method === "GET" && path === "/api/recovery") return { status: 200, json: household.recoveryStatus() };

  if (method === "PUT" && path === "/api/copy") {
    // In the query, which the request proof covers, not in headers, which it
    // doesn't: a raised schema version would lock every phone out, and
    // a raised floor would lock out the phones behind it.
    const floor = url.searchParams.get("floor");
    const copyId = household.uploadCopy(phone, {
      epoch: requireInteger(Number(url.searchParams.get("epoch"))),
      schemaVersion: requireInteger(Number(url.searchParams.get("schema"))),
      throughSeq: requireInteger(Number(url.searchParams.get("through"))),
      bytes: body,
      ...(floor === null ? {} : { schemaFloor: requireInteger(Number(floor)) }),
    });
    return { status: 200, json: { copyId } };
  }

  if (method === "POST" && path === "/api/copy/activate") {
    household.activateCopy(parseJson(body).copyId);
    return { status: 200, json: { ok: true } };
  }

  if (method === "GET" && path === "/api/copy") {
    const { copy, bytes } = household.activeCopyBytes();
    return { status: 200, bytes, headers: { ...downloadHeaders(), "X-HC-Copy": JSON.stringify(copy) } };
  }

  if (method === "POST" && path === "/api/key") {
    const input = parseJson(body);
    const changed = household.changeKey(phone, {
      epoch: requireInteger(input.epoch),
      copyId: input.copyId,
      reset: input.reset === true,
      rekeyProof: decode(input.rekeyProof, 32),
      statement: requireStatement(input.statement),
      signature: decode(input.signature, 64),
      remove: input.remove,
      wraps: parseWraps(input.wraps),
    });
    return { status: 200, json: changed };
  }

  if (method === "POST" && path === "/api/copy/loaded") {
    household.copyLoaded(phone, parseJson(body).copyId);
    return { status: 200, json: { ok: true } };
  }


  if (method === "GET" && url.pathname === "/api/key") {
    const asked = url.searchParams.get("epoch");
    return { status: 200, json: household.wrapFor(phone, asked === null ? undefined : requireInteger(Number(asked))) };
  }

  if (file !== null) {
    const fileId = file[1] as string;
    const piece = file[2] === undefined ? null : Number(file[2]);
    if (piece !== null && method === "PUT") {
      household.putPiece(fileId, piece, body);
      return { status: 200, json: { ok: true } };
    }
    if (piece !== null && method === "GET") return { status: 200, bytes: household.getPiece(fileId, piece), headers: downloadHeaders() };
    if (piece === null && method === "GET") return { status: 200, json: household.fileStatus(fileId) };
    if (piece === null && method === "POST") {
      household.completeFile(fileId, parseJson(body).pieces);
      return { status: 200, json: { ok: true } };
    }
    if (piece === null && method === "DELETE") {
      household.deleteFile(fileId);
      return { status: 200, json: { ok: true } };
    }
  }

  throw new Refusal("not-found");
}

/**
 * The server answers only to an IP address, `localhost`, or a name it was
 * given. That stops a website the household happens to visit from pointing
 * its own domain at this server's address and talking to it through the
 * browser (DNS rebinding).
 */
function checkHost(request: IncomingMessage, hostNames: Set<string>): void {
  const name = hostName(request);
  if (name === null || !hostAllowed(name, hostNames)) throw new Refusal("host-not-allowed");
}

/** The name in the request's Host, lower-cased, without its port or an IPv6 address's brackets. */
function hostName(request: IncomingMessage): string | null {
  const host = request.headers.host;
  if (host === undefined) return null;
  const name = host.startsWith("[") ? host.slice(1, host.indexOf("]")) : host.replace(/:\d+$/, "");
  return name.toLowerCase();
}

function hostAllowed(name: string, hostNames: Set<string>): boolean {
  return isIP(name) !== 0 || name === "localhost" || hostNames.has(name);
}

/** `127.0.0.1` and `::1`: this computer, by a number rather than by `localhost`. */
function isLoopbackAddress(name: string): boolean {
  return (isIP(name) === 4 && name.startsWith("127.")) || name === "::1" || name === "0:0:0:0:0:0:0:1";
}

// ── the web app ────────────────────────────────────────────────────────

/**
 * Everything outside `/api`: the web app's files, read once at start, or the
 * landing page when the server has none. Only `GET` and `HEAD`; no
 * request is ever turned into a path on disk (`web-app.ts`).
 */
function serveWeb(request: IncomingMessage, response: ServerResponse, web: WebApp | null, hostNames: Set<string>): void {
  const name = hostName(request);
  if (name === null || !hostAllowed(name, hostNames)) {
    sendPlain(response, 421, REFUSED_HOST_PAGE, "text/html; charset=utf-8");
    return;
  }
  const method = request.method ?? "GET";
  if (method !== "GET" && method !== "HEAD") {
    sendPlain(response, 405, "This server's pages can only be read.", "text/plain; charset=utf-8", { Allow: "GET, HEAD" });
    return;
  }
  const target = request.url ?? "/";
  const pathname = webPathname(target);
  if (pathname === null) {
    sendPlain(response, 400, "That isn't an address this server has.", "text/plain; charset=utf-8");
    return;
  }
  if (web === null) {
    if (pathname === "/") sendPlain(response, 200, LANDING_PAGE, "text/html; charset=utf-8");
    else sendPlain(response, 404, "Not found.", "text/plain; charset=utf-8");
    return;
  }
  // `localhost`, `127.0.0.1` and an https name are three sites to a browser,
  // and each would need its own join. One computer is one: `localhost`.
  if (isLoopbackAddress(name)) {
    const port = /:(\d+)$/.exec(request.headers.host ?? "")?.[1];
    const scheme = (request.socket as { encrypted?: boolean }).encrypted === true ? "https:" : "http:";
    sendPlain(response, 307, "", "text/plain; charset=utf-8", { Location: `${scheme}//localhost${port === undefined ? "" : `:${port}`}${target}` });
    return;
  }
  const file = web.find(pathname);
  if (file === null) {
    if (web.notFound === null) sendPlain(response, 404, "Not found.", "text/plain; charset=utf-8");
    else sendWebFile(response, 404, web, web.notFound, method);
    return;
  }
  sendWebFile(response, 200, web, file, method);
}

/**
 * The path a browser asked for, decoded, or null when it can't be one of the
 * web app's: a `.` or `..` part, a backslash, a NUL, or bad escaping. Those
 * would find nothing in the list anyway; they are refused rather than looked up.
 */
function webPathname(target: string): string | null {
  const raw = target.split("?")[0] ?? "";
  if (!raw.startsWith("/")) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    return null;
  }
  if (decoded.includes("\\") || decoded.includes("\0")) return null;
  if (decoded.split("/").some((part) => part === "." || part === "..")) return null;
  return decoded;
}

function sendWebFile(response: ServerResponse, status: number, web: WebApp, file: WebFile, method: string): void {
  response.writeHead(status, {
    ...WEB_HEADERS,
    "Content-Security-Policy": web.contentSecurityPolicy,
    "Cache-Control": file.hashed && status === 200 ? CACHE_HASHED : "no-store",
    "Content-Type": file.type,
    "Content-Length": String(file.bytes.length),
  });
  response.end(method === "HEAD" ? undefined : file.bytes);
}

function sendPlain(response: ServerResponse, status: number, text: string, type: string, extra: Record<string, string> = {}): void {
  const body = Buffer.from(text);
  response.writeHead(status, { ...SECURITY_HEADERS, "Content-Type": type, ...extra, "Content-Length": String(body.length) });
  response.end(body);
}

function bodyLimitFor(method: string, path: string): number {
  if (method === "PUT" && path === "/api/copy") return BODY_LIMITS.copy;
  if (method === "PUT" && path.startsWith("/api/files/")) return BODY_LIMITS.piece;
  return BODY_LIMITS.json;
}

/**
 * How many request-body bytes the server holds at once, across every request:
 * one full copy and a little more. Uploads beyond it wait for the phone to
 * try again, so no number of requests can run it out of memory.
 */
export const BODY_BYTES_IN_FLIGHT = BODY_LIMITS.copy + 16 * BODY_LIMITS.piece;
let bodyBytesHeld = 0;

function readBody(request: IncomingMessage, limit: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const declared = Number(request.headers["content-length"] ?? "0");
    if (declared > limit) {
      request.resume();
      reject(new Refusal("too-large"));
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    const release = () => {
      bodyBytesHeld -= size;
      size = 0;
    };
    request.on("data", (chunk: Buffer) => {
      size += chunk.length;
      bodyBytesHeld += chunk.length;
      if (size > limit || bodyBytesHeld > BODY_BYTES_IN_FLIGHT) {
        const busy = size <= limit;
        release();
        request.destroy();
        reject(new Refusal("too-large", busy ? { reason: "busy" } : {}));
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      const whole = Buffer.concat(chunks);
      release();
      resolve(whole);
    });
    request.on("error", (error) => {
      release();
      reject(error);
    });
  });
}

function readSignature(request: IncomingMessage, method: string, path: string, body: Buffer): Signed {
  const time = Number(request.headers["x-hc-time"]);
  const nonce = request.headers["x-hc-nonce"];
  const proof = request.headers["x-hc-proof"];
  if (typeof nonce !== "string" || typeof proof !== "string" || !Number.isFinite(time)) throw new Refusal("bad-proof");
  try {
    fromBase64Url(nonce, 16);
    return { method, path, time, nonce, proof: fromBase64Url(proof, 32), body };
  } catch {
    throw new Refusal("bad-proof");
  }
}

/** The string every request proof is computed over. The phone builds the same one. */
export function requestProofInput(method: string, path: string, time: number, nonce: string, body: Buffer): string {
  return `${method}\n${path}\n${time}\n${nonce}\n${sha256Hex(body)}`;
}

/** The string every reply proof is computed over. */
/**
 * The string every reply proof covers. `copy` is the `X-HC-Copy` header a
 * copy download carries: how far through the changes the copy runs, which a
 * phone acts on and so must not be able to be changed on the way.
 */
export function replyProofInput(nonce: string, status: number, body: Buffer, copy: string | null = null): string {
  return `reply\n${nonce}\n${status}\n${sha256Hex(body)}` + (copy === null ? "" : `\ncopy ${copy}`);
}

function proofHolds(key: Buffer, signed: Signed): boolean {
  const expected = hmac(key, requestProofInput(signed.method, signed.path, signed.time, signed.nonce, signed.body));
  return sameBytes(expected, signed.proof);
}

function send(response: ServerResponse, reply: Reply, replyKey: Buffer | null, nonce: string | null): void {
  const body = reply.bytes ?? Buffer.from(JSON.stringify(reply.json ?? {}));
  const headers: Record<string, string> = {
    ...SECURITY_HEADERS,
    "Content-Type": "application/json; charset=utf-8",
    ...reply.headers,
    "Content-Length": String(body.length),
  };
  if (replyKey !== null && nonce !== null) {
    const copy = reply.headers?.["X-HC-Copy"] ?? null;
    headers["X-HC-Reply-Proof"] = hmac(replyKey, replyProofInput(nonce, reply.status, body, copy)).toString("base64url");
  }
  response.writeHead(reply.status, headers);
  response.end(body);
}

/** Files and copies go out as downloads, never as something a browser would show or run. */
function downloadHeaders(): Record<string, string> {
  return { "Content-Type": "application/octet-stream", "Content-Disposition": "attachment" };
}

function parseJson(body: Buffer): Record<string, unknown> {
  try {
    return requireObject(JSON.parse(body.toString("utf8")));
  } catch (error) {
    if (error instanceof Refusal) throw error;
    throw new Refusal("bad-request");
  }
}

function requireObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Refusal("bad-request");
  return value as Record<string, unknown>;
}

function requireString(value: unknown): string {
  if (typeof value !== "string") throw new Refusal("bad-request");
  return value;
}

function requireInteger(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value)) throw new Refusal("bad-request");
  return value;
}

/** A signed key change's statement: text, kept as it came, so its signature still holds when it is served. */
function requireStatement(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 64 * 1024) throw new Refusal("bad-request");
  return value;
}

function decode(value: unknown, bytes?: number): Buffer {
  try {
    return fromBase64Url(value, bytes);
  } catch {
    throw new Refusal("bad-request");
  }
}

function parseWraps(value: unknown): { phoneId: string; ephemeralKey: Buffer; blob: Buffer }[] {
  if (!Array.isArray(value)) throw new Refusal("bad-request");
  return value.map((raw) => {
    const item = requireObject(raw);
    return { phoneId: requireString(item.phoneId), ephemeralKey: decode(item.ephemeralKey, 32), blob: decode(item.blob) };
  });
}
