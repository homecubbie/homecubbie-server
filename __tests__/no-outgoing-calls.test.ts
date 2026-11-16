/**
 * The server never starts a connection of its own.
 *
 * It answers phones on the home network and does nothing else with a
 * network: no update check, no telemetry, no time server, no model download.
 * This reads the server's own source the way `src/__tests__/no-network.test.ts`
 * reads the app's: text, with comments blanked, so a file explaining what it
 * doesn't do isn't caught by its own explanation.
 *
 * It also refuses a model download in anything the package builds or runs
 * (`-hf`, `ollama pull`): the rule is that a model arrives
 * inside the server image, never fetched on first start.
 */
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

const SOURCE = join(import.meta.dirname, "..", "src");
const PACKAGE = join(import.meta.dirname, "..", "package.json");

/** Every way Node can open a connection outward, as it would be written. */
const OUTGOING = [
  { name: "fetch", pattern: /(?<![.\w])fetch\s*\(/ },
  { name: "http(s).request / get", pattern: /\b(?:request|get)\s*\(\s*\{[^}]*\bhost\b/ },
  // The server listens over HTTPS when it is given a certificate: that
  // is `createServer` from node:https and nothing else. Anything more from it
  // (`request`, `get`, an `Agent`, the whole module) is a way to call out.
  {
    name: "node:https, beyond createServer",
    pattern:
      /import\s*\{[^}]*\b(?:request|get|Agent|globalAgent)\b[^}]*\}\s*from\s*["'](?:node:)?https["']|import\s+(?:\*\s+as\s+)?\w+\s+from\s*["'](?:node:)?https["']|require\(\s*["'](?:node:)?https["']\s*\)|import\(\s*["'](?:node:)?https["']\s*\)/,
  },
  { name: "an https module by any other name", pattern: /["']https["']/ },
  { name: "node:net connect", pattern: /\b(?:connect|createConnection)\s*\(/ },
  { name: "node:dgram", pattern: /["'](?:node:)?dgram["']/ },
  { name: "node:dns", pattern: /["'](?:node:)?dns(?:\/promises)?["']/ },
  { name: "node:tls", pattern: /["'](?:node:)?tls["']/ },
  { name: "node:child_process", pattern: /["'](?:node:)?child_process["']/ },
  { name: "WebSocket", pattern: /\bWebSocket\b/ },
  { name: "XMLHttpRequest", pattern: /\bXMLHttpRequest\b/ },
];

function withoutComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, (match) => match.replace(/[^\n]/g, " ")).replace(/(?<![:"'])\/\/.*$/gm, "");
}

describe("the server's own source", () => {
  const files = readdirSync(SOURCE).filter((name) => name.endsWith(".ts"));

  it("exists, so this check is checking something", () => {
    assert.ok(files.length >= 4);
  });

  for (const file of files) {
    it(`${file} opens no outgoing connection`, () => {
      const source = withoutComments(readFileSync(join(SOURCE, file), "utf8"));
      for (const { name, pattern } of OUTGOING) {
        assert.equal(pattern.test(source), false, `${file} uses ${name}`);
      }
    });
  }

  it("fetches no model at runtime: no -hf, no ollama pull, anywhere in the package", () => {
    const root = join(import.meta.dirname, "..");
    const scripts = ["Dockerfile", "package.json", ...files.map((file) => join("src", file))];
    for (const file of scripts) {
      const text = readFileSync(join(root, file), "utf8");
      assert.equal(/(?:^|\s)-hf(?:\s|=)/m.test(text), false, `${file} downloads a model with -hf`);
      assert.equal(/ollama\s+pull/.test(text), false, `${file} downloads a model with ollama pull`);
    }
  });

  it("takes only createServer from node:https, for its own HTTPS listener", () => {
    const users = files.filter((file) => /["']node:https["']/.test(withoutComments(readFileSync(join(SOURCE, file), "utf8"))));
    assert.deepEqual(users, ["https-listener.ts"]);
    const source = withoutComments(readFileSync(join(SOURCE, "https-listener.ts"), "utf8"));
    const imported = /import\s*\{([^}]*)\}\s*from\s*["']node:https["']/.exec(source)?.[1] ?? "";
    const names = imported.split(",").map((name) => name.trim().replace(/^type\s+/, "")).filter((name) => name !== "");
    assert.deepEqual(names.sort(), ["Server", "createServer"]);
  });

  it("depends on nothing outside Node itself", () => {
    const manifest = JSON.parse(readFileSync(PACKAGE, "utf8")) as { dependencies?: Record<string, string> };
    assert.deepEqual(Object.keys(manifest.dependencies ?? {}), []);
  });
});
