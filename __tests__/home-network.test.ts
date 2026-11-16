/**
 * The server answers only this computer and the home network's address
 * ranges, unless it is told to answer any.
 */
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { answerHomeOnly, isHomeAddress } from "../src/home-network.ts";
import { Household } from "../src/household.ts";
import { createHouseholdServer } from "../src/http-server.ts";

const HOME = [
  "127.0.0.1",
  "127.8.9.10",
  "10.0.0.5",
  "172.16.0.1",
  "172.31.255.255",
  "192.168.1.20",
  "169.254.10.1",
  "100.64.0.1",
  "100.101.102.103",
  "100.127.255.255",
  "::1",
  "fe80::1",
  "fe80::1c2b:3a4d:5e6f:7081%en0",
  "fd7a:115c:a1e0::1",
  "fc00::5",
  "::ffff:192.168.1.5",
  "::ffff:127.0.0.1",
];

const NOT_HOME = [
  "8.8.8.8",
  "1.1.1.1",
  "172.15.255.255",
  "172.32.0.1",
  "192.169.0.1",
  "169.253.0.1",
  "100.63.255.255",
  "100.128.0.1",
  "11.0.0.1",
  "2607:f8b0:4005:80a::200e",
  "2001:db8::1",
  "fec0::1",
  "::ffff:8.8.8.8",
  "::2",
  "",
  "not an address",
];

/** A socket that says it came from `address`, as one from the network would. */
function socketFrom(address: string): Socket {
  const socket = new Socket();
  Object.defineProperty(socket, "remoteAddress", { value: address });
  return socket;
}

describe("the addresses the server answers", () => {
  for (const address of HOME) {
    it(`answers ${address}`, () => assert.equal(isHomeAddress(address), true));
  }
  for (const address of NOT_HOME) {
    it(`refuses ${address || "an empty address"}`, () => assert.equal(isHomeAddress(address), false));
  }
  it("refuses a connection that gives no address", () => assert.equal(isHomeAddress(undefined), false));
});

describe("a connection from outside the home network", () => {
  it("closes a connection from outside the home network before reading it", () => {
    const server = createServer();
    const logged: string[] = [];
    answerHomeOnly(server, { log: { info: (line) => logged.push(line) } });
    const later: Socket[] = [];
    server.on("connection", (socket: Socket) => later.push(socket));

    const stranger = socketFrom("203.0.113.9");
    const phone = socketFrom("192.168.1.20");
    server.emit("connection", stranger);
    server.emit("connection", phone);

    assert.equal(stranger.destroyed, true);
    assert.equal(phone.destroyed, false);
    // It goes first, so the listener after it still sees the socket, closed.
    assert.deepEqual(later, [stranger, phone]);
    assert.equal(logged.length, 1);
    assert.match(logged[0] ?? "", /refused a connection from 203\.0\.113\.9.*HOMECUBBIE_ALLOW_ANY_ADDRESS=1/);
    phone.destroy();
  });

  it("logs only the first refusal, so a scan can't fill the log", () => {
    const server = createServer();
    const logged: string[] = [];
    answerHomeOnly(server, { log: { info: (line) => logged.push(line) } });

    for (const address of ["203.0.113.9", "203.0.113.10", "198.51.100.1"]) server.emit("connection", socketFrom(address));

    assert.equal(logged.length, 1);
  });

  it("answers any address when told to", () => {
    const server = createServer();
    answerHomeOnly(server, { anyAddress: true });

    const stranger = socketFrom("203.0.113.9");
    server.emit("connection", stranger);

    assert.equal(stranger.destroyed, false);
    stranger.destroy();
  });

  it("is the first thing the household server does with a connection, unless told otherwise", () => {
    const dataDir = mkdtempSync(join(tmpdir(), "homecubbie-home-network-"));
    const household = new Household(dataDir, { log: { info: () => undefined } });
    try {
      const guarded = createHouseholdServer(household);
      const open = createHouseholdServer(household, { anyAddress: true });

      assert.equal(guarded.listeners("connection")[0]?.name, "refuseOutsideHome");
      assert.equal(
        open.listeners("connection").some((listener) => listener.name === "refuseOutsideHome"),
        false,
      );
    } finally {
      household.close();
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  it("is applied to the HTTPS server too, and read from the environment at start", () => {
    const https = readFileSync(join(import.meta.dirname, "..", "src", "https-listener.ts"), "utf8");
    const main = readFileSync(join(import.meta.dirname, "..", "src", "start.ts"), "utf8");

    assert.match(https, /createServer\(first, householdRequestListener\(household, options\)\);\n\s+answerHomeOnly\(server, options\);/);
    assert.match(main, /anyAddress: process\.env\.HOMECUBBIE_ALLOW_ANY_ADDRESS === "1"/);
  });
});
