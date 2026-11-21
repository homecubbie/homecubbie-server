import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { connect, createServer } from "node:net";
import { networkInterfaces, tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

/**
 * A server started with `HOMECUBBIE_THIS_COMPUTER_ONLY=1` answers this
 * computer and nothing else: what a laptop away from home needs, since
 * a café's Wi-Fi uses the home ranges too. Started for real, as the npm
 * package's bin is, so the setting is shown read from the environment and
 * applied, not only written down.
 */

const MAIN = join(import.meta.dirname, "..", "src", "main.ts");

/** A port nothing is listening on, for the server to take. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const address = probe.address();
      const port = typeof address === "object" && address !== null ? address.port : 0;
      probe.close(() => resolve(port));
    });
  });
}

/** This computer's own address on a network, the one a phone would use, if it has one. */
function networkAddress(): string | undefined {
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === "IPv4" && !entry.internal) return entry.address;
    }
  }
  return undefined;
}

/** What comes back to a plain request for `/api/hello` at `host`, or "" when the server closes it unread. */
function askHello(host: string, port: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect({ host, port });
    let answer = "";
    socket.setTimeout(5_000, () => {
      socket.destroy();
      reject(new Error(`no answer and no close from ${host}:${port} in 5 s`));
    });
    socket.on("connect", () => socket.write(`GET /api/hello HTTP/1.0\r\nHost: ${host}:${port}\r\n\r\n`));
    socket.on("data", (chunk: Buffer) => {
      answer += chunk.toString();
    });
    socket.on("error", () => resolve(answer));
    socket.on("close", () => resolve(answer));
  });
}

/** Resolves once `read()` matches `pattern`, for output a moment behind what caused it; fails after 5 s. */
async function eventually(read: () => string, pattern: RegExp): Promise<void> {
  for (let waited = 0; waited < 5_000; waited += 50) {
    if (pattern.test(read())) return;
    await new Promise((done) => setTimeout(done, 50));
  }
  assert.match(read(), pattern);
}

/** Starts the server with `env` and resolves once it says it's listening, with a way to stop it. */
function start(env: NodeJS.ProcessEnv): Promise<{ stdout: () => string; stop: () => Promise<void> }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [MAIN], { env: { ...process.env, NODE_OPTIONS: "", ...env } });
    let stdout = "";
    let stderr = "";
    let exited = false;
    const exit = new Promise<void>((done) => child.on("exit", () => {
      exited = true;
      done();
    }));
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`not listening after 20 s\n${stdout}\n${stderr}`));
    }, 20_000);
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
      if (!/listening at http:/.test(stdout)) return;
      clearTimeout(timer);
      resolve({
        stdout: () => stdout,
        stop: async () => {
          if (!exited) child.kill("SIGTERM");
          await exit;
        },
      });
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`exited with ${String(code)} before listening\n${stdout}\n${stderr}`));
    });
  });
}

describe("a server started to answer this computer only", () => {
  it("answers this computer, and closes a connection to its address on the Wi-Fi unread", async (t) => {
    const dataDir = mkdtempSync(join(tmpdir(), "this-computer-only-"));
    const port = await freePort();
    const server = await start({ HOMECUBBIE_DATA: dataDir, HOMECUBBIE_PORT: String(port), HOMECUBBIE_THIS_COMPUTER_ONLY: "1" });
    try {
      assert.match(server.stdout(), /answering this computer only \(HOMECUBBIE_THIS_COMPUTER_ONLY=1\)/);
      assert.match(server.stdout(), new RegExp(`listening at http://localhost:${port}\\n`));

      const here = await askHello("127.0.0.1", port);
      assert.match(here, /^HTTP\/1\.1 200 /);
      assert.match(here, /"app":"homecubbie"/);

      const address = networkAddress();
      if (address === undefined) {
        t.skip("this computer has no network address to try");
        return;
      }
      // The same computer, by the address a phone on the Wi-Fi would use: the
      // server sees that address, not this computer's own, and closes it.
      assert.equal(await askHello(address, port), "");
      await eventually(server.stdout, new RegExp(`refused a connection from (::ffff:)?${address.replaceAll(".", "\\.")}: this server answers only this computer`));
    } finally {
      await server.stop();
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  it("won't start told to answer any address as well", async () => {
    const dataDir = mkdtempSync(join(tmpdir(), "this-computer-only-"));
    try {
      const result = await new Promise<{ code: number | null; stderr: string }>((resolve) => {
        const child = spawn(process.execPath, [MAIN], {
          env: { ...process.env, NODE_OPTIONS: "", HOMECUBBIE_DATA: dataDir, HOMECUBBIE_PORT: "0", HOMECUBBIE_THIS_COMPUTER_ONLY: "1", HOMECUBBIE_ALLOW_ANY_ADDRESS: "1" },
        });
        let stderr = "";
        child.stderr.on("data", (chunk: Buffer) => {
          stderr += chunk.toString();
        });
        child.on("exit", (code) => resolve({ code, stderr }));
      });
      assert.equal(result.code, 1);
      assert.match(result.stderr, /HOMECUBBIE_ALLOW_ANY_ADDRESS and HOMECUBBIE_THIS_COMPUTER_ONLY say opposite things/);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });
});
