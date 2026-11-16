import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { isSqliteExperimentalWarning, withoutSqliteWarning } from "../src/quiet-warnings.ts";

/**
 * `npx homecubbie-server` starts with no flags, from the bin's
 * `#!/usr/bin/env node` line, so Node's "SQLite is an experimental feature"
 * warning was the first line a household read.
 */

const SRC = join(import.meta.dirname, "..", "src");

/**
 * Runs `node <args>` with no flags of ours. With `done`, it is stopped half a
 * second after its output matches, because Node prints a warning a moment after
 * the code that caused it has run; without, it runs until it exits.
 */
function run(args: string[], env: NodeJS.ProcessEnv, done?: RegExp): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, { env: { ...process.env, NODE_OPTIONS: "", ...env } });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`still running after 20 s\n${stdout}\n${stderr}`));
    }, 20_000);
    let stopping = false;
    const check = (): void => {
      if (done === undefined || stopping || !done.test(stdout)) return;
      stopping = true;
      setTimeout(() => child.kill("SIGTERM"), 500);
    };
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
      check();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    child.on("exit", () => {
      clearTimeout(timer);
      resolve({ stdout, stderr });
    });
  });
}

describe("starting the server", () => {
  it("prints no SQLite warning, started as the npm package's bin is", async () => {
    const dataDir = mkdtempSync(join(tmpdir(), "quiet-start-"));
    try {
      const { stdout, stderr } = await run(
        [join(SRC, "main.ts")],
        { HOMECUBBIE_DATA: dataDir, HOMECUBBIE_PORT: "0" },
        /not set up yet|set up\./,
      );
      assert.match(stdout, /homecubbie-server: keeping the household's data in/);
      assert.doesNotMatch(stderr, /ExperimentalWarning|SQLite is an experimental feature/);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  it("is needed: Node itself still warns when node:sqlite loads (if this fails, Node stopped warning and quiet-warnings.ts can go)", async () => {
    const { stderr } = await run(["--input-type=module", "-e", "await import('node:sqlite'); console.log('loaded');"], {});
    assert.match(stderr, /ExperimentalWarning: SQLite is an experimental feature/);
  });

  it("drops only the SQLite warning, and passes every other one on", () => {
    const passed: unknown[][] = [];
    const emit = withoutSqliteWarning(((...args: unknown[]) => {
      passed.push(args);
    }) as typeof process.emitWarning);

    emit("SQLite is an experimental feature and might change at any time", "ExperimentalWarning");
    emit("SQLite is an experimental feature and might change at any time", { type: "ExperimentalWarning" });
    emit("Some other feature is experimental", "ExperimentalWarning");
    emit("SQLite said something", "Warning");
    emit("A deprecation", "DeprecationWarning", "DEP0001");

    assert.deepEqual(passed.map((args) => args[0]), ["Some other feature is experimental", "SQLite said something", "A deprecation"]);
    assert.equal(isSqliteExperimentalWarning(Object.assign(new Error("SQLite is an experimental feature"), { name: "ExperimentalWarning" })), true);
  });
});
