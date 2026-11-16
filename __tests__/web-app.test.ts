/**
 * The web app, as the household server serves it: a page,
 * a file named by its hash, a route that takes an id, and a path that tries
 * to climb out of the list, each against a real server on a spare port.
 *
 * The web build here is a small one made in a temporary folder, shaped as
 * `expo export --platform web` writes it, so these tests need no export.
 * `src/__tests__/server-web-build.test.ts`, in the app, holds a real one.
 */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { startServer, type Running } from "./harness.ts";
import { loadWebApp, MANIFEST, type WebApp } from "../src/web-app.ts";

const POLICY = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; object-src 'none'";
const HASH = "0123456789abcdef0123456789abcdef";

/** A page as the export writes it: the policy in a `<meta>`, its quotes escaped as React escapes them. */
function page(title: string): string {
  const escaped = POLICY.replace(/'/g, "&#x27;");
  return `<!DOCTYPE html><html lang="en"><head><meta charSet="utf-8"/><meta http-equiv="Content-Security-Policy" content="${escaped}"/></head><body>${title}</body></html>`;
}

function makeBuild(files: Record<string, string>): string {
  const folder = mkdtempSync(join(tmpdir(), "homecubbie-web-"));
  for (const [path, contents] of Object.entries(files)) {
    mkdirSync(dirname(join(folder, path)), { recursive: true });
    writeFileSync(join(folder, path), contents);
  }
  return folder;
}

const BUILD: Record<string, string> = {
  [MANIFEST]: JSON.stringify({ app: "homecubbie", schemaVersion: 47 }),
  "index.html": page("the home page"),
  "+not-found.html": page("the app's own not-found screen"),
  "home/thing/[id].html": page("a Thing"),
  "records/year/[year].html": page("a year"),
  "records/history.html": page("History"),
  "settings/index.html": page("Settings"),
  [`_expo/static/js/web/entry-${HASH}.js`]: "console.log('the app');",
  "favicon.ico": "an icon",
  "_expo/.routes.json": "{}",
};

function loaded(folder: string): WebApp {
  const result = loadWebApp(folder);
  if (!("app" in result)) throw new Error(result.missing);
  return result.app;
}

async function withWebServer(run: (server: Running, port: string) => Promise<void>, files = BUILD) {
  const folder = makeBuild(files);
  const server = await startServer({ webApp: loaded(folder), hostNames: ["mac-mini.local"] });
  try {
    await run(server, new URL(server.baseUrl).port);
  } finally {
    await server.close();
    rmSync(folder, { recursive: true, force: true });
  }
}

interface Got {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

/**
 * A request sent exactly as written, with the Host given. `fetch` would tidy
 * `..` out of the path before sending it, which is the case being tested.
 */
function get(port: string, path: string, options: { host?: string; method?: string } = {}): Promise<Got> {
  return new Promise((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port, path, method: options.method ?? "GET", headers: { Host: options.host ?? `localhost:${port}` } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

describe("the web app", () => {
  it("serves a page, a file named by its hash, and the page for a route that takes an id", async () => {
    await withWebServer(async (_server, port) => {
      const home = await get(port, "/");
      assert.equal(home.status, 200);
      assert.match(home.body, /the home page/);
      assert.equal(home.headers["content-type"], "text/html; charset=utf-8");
      assert.equal(home.headers["cache-control"], "no-store");

      const bundle = await get(port, `/_expo/static/js/web/entry-${HASH}.js`);
      assert.equal(bundle.status, 200);
      assert.equal(bundle.body, "console.log('the app');");
      assert.equal(bundle.headers["cache-control"], "public, max-age=31536000, immutable");

      const thing = await get(port, "/home/thing/0b6f6c2e-6f0a-4bde-9d5e-0f1b2c3d4e5f");
      assert.equal(thing.status, 200);
      assert.match(thing.body, /a Thing/);
      assert.equal(thing.headers["cache-control"], "no-store");

      assert.match((await get(port, "/records/history")).body, /History/);
      assert.match((await get(port, "/records/year/2026")).body, /a year/);
      assert.match((await get(port, "/settings")).body, /Settings/);
      assert.match((await get(port, "/settings/")).body, /Settings/);
    });
  });

  it("refuses a path that climbs out, however it is spelled, and never reads outside the list", async () => {
    await withWebServer(async (_server, port) => {
      for (const path of ["/home/thing/../../../etc/passwd", "/..%2f..%2fetc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/home/./thing", "/a%5c..%5cb", "/%E0%A4%A"]) {
        const refused = await get(port, path);
        assert.equal(refused.status, 400, path);
        assert.doesNotMatch(refused.body, /root:/, path);
      }
      // Left out of the list: names starting with a dot, and the build's own manifest.
      assert.equal((await get(port, "/_expo/.routes.json")).status, 404);
      assert.equal((await get(port, `/${MANIFEST}`)).status, 404);
      // One part, not two: `[id]` stands for exactly one part of a path.
      assert.equal((await get(port, "/home/thing/one/two")).status, 404);
      assert.equal((await get(port, "/home/thing/")).status, 404);
    });
  });

  it("answers an address it hasn't with the app's own not-found page, and nothing cached", async () => {
    await withWebServer(async (_server, port) => {
      const missing = await get(port, "/no/such/screen");
      assert.equal(missing.status, 404);
      assert.match(missing.body, /the app's own not-found screen/);
      assert.equal(missing.headers["cache-control"], "no-store");
    });
  });

  it("sends the export's own policy as a header, with frame-ancestors added, and the isolation headers", async () => {
    await withWebServer(async (_server, port) => {
      for (const path of ["/", `/_expo/static/js/web/entry-${HASH}.js`, "/home/thing/abc"]) {
        const got = await get(port, path);
        assert.equal(got.headers["content-security-policy"], `${POLICY}; frame-ancestors 'none'`, path);
        assert.equal(got.headers["cross-origin-opener-policy"], "same-origin", path);
        assert.equal(got.headers["cross-origin-embedder-policy"], "require-corp", path);
        assert.equal(got.headers["x-content-type-options"], "nosniff", path);
        assert.equal(got.headers["set-cookie"], undefined, path);
      }
    });
  });

  it("sends a page asked for at 127.0.0.1 to localhost, so one computer isn't two joins", async () => {
    await withWebServer(async (_server, port) => {
      const sent = await get(port, "/home/thing/abc?x=1", { host: `127.0.0.1:${port}` });
      assert.equal(sent.status, 307);
      assert.equal(sent.headers.location, `http://localhost:${port}/home/thing/abc?x=1`);
      const ipv6 = await get(port, "/", { host: `[::1]:${port}` });
      assert.equal(ipv6.headers.location, `http://localhost:${port}/`);
      // Not the phones' address, and not the API, which phones reach by number.
      assert.equal((await get(port, "/", { host: `192.168.1.20:${port}` })).status, 200);
      assert.equal((await get(port, "/api/hello", { host: `127.0.0.1:${port}` })).status, 200);
    });
  });

  it("gives a refused Host a page a person can read, which repeats nothing from the request", async () => {
    await withWebServer(async (_server, port) => {
      const refused = await get(port, "/<script>alert(1)</script>", { host: `evil-example.test:${port}` });
      assert.equal(refused.status, 421);
      assert.equal(refused.headers["content-type"], "text/html; charset=utf-8");
      assert.match(refused.body, /HOMECUBBIE_HOSTS/);
      assert.doesNotMatch(refused.body, /evil-example|script|alert/);
      assert.equal((await get(port, "/", { host: `mac-mini.local:${port}` })).status, 200);
      // The API still answers a refused Host in JSON, which the phones read.
      const api = await get(port, "/api/hello", { host: `evil-example.test:${port}` });
      assert.equal(api.status, 421);
      assert.equal(JSON.parse(api.body).error, "host-not-allowed");
    });
  });

  it("only reads: no other method, and a HEAD has no body", async () => {
    await withWebServer(async (_server, port) => {
      const posted = await get(port, "/", { method: "POST" });
      assert.equal(posted.status, 405);
      assert.equal(posted.headers.allow, "GET, HEAD");
      const head = await get(port, "/", { method: "HEAD" });
      assert.equal(head.status, 200);
      assert.equal(head.body, "");
      assert.ok(Number(head.headers["content-length"]) > 0);
    });
  });

  it("reads its list once, at start: a file added to the folder later isn't served", async () => {
    const folder = makeBuild(BUILD);
    const server = await startServer({ webApp: loaded(folder) });
    try {
      const port = new URL(server.baseUrl).port;
      writeFileSync(join(folder, "added-later.html"), page("added later"));
      assert.equal((await get(port, "/added-later")).status, 404);
    } finally {
      await server.close();
      rmSync(folder, { recursive: true, force: true });
    }
  });

  it("isn't served without its manifest, or without the export's policy in its pages", () => {
    const { [MANIFEST]: _manifest, ...withoutManifest } = BUILD;
    const noManifest = makeBuild(withoutManifest);
    const noPolicy = makeBuild({ ...BUILD, "index.html": "<!DOCTYPE html><html><body>no policy</body></html>" });
    try {
      assert.match((loadWebApp(noManifest) as { missing: string }).missing, /no web app/);
      assert.match((loadWebApp(noPolicy) as { missing: string }).missing, /Content-Security-Policy/);
    } finally {
      rmSync(noManifest, { recursive: true, force: true });
      rmSync(noPolicy, { recursive: true, force: true });
    }
  });

  it("keeps the landing page when it has no web app", async () => {
    const server = await startServer();
    try {
      const port = new URL(server.baseUrl).port;
      const landing = await get(port, "/");
      assert.equal(landing.status, 200);
      assert.match(landing.body, /HomeCubbie server/);
      assert.equal((await get(port, "/home/thing/abc")).status, 404);
    } finally {
      await server.close();
    }
  });
});
