/**
 * HTTPS for a browser on a computer that isn't the server's: given a certificate and key, the server also listens over HTTPS,
 * with the same routes and the same proofs; it serves a replaced certificate
 * from the next connection on; it sends no HSTS; and behind a reverse proxy a
 * proven request goes through with the proxy's name as Host.
 *
 * The certificates are made here, with the system's `openssl`, for
 * `localhost` and `127.0.0.1`, so no private key is kept in the repository.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, describe, it } from "node:test";
import type { TLSSocket } from "node:tls";
import { hmac, sameBytes } from "../src/crypto.ts";
import { Household } from "../src/household.ts";
import { replyProofInput, requestProofInput } from "../src/http-server.ts";
import { certificateFilesFrom, certificateLastDay, createHouseholdHttpsServer, RELOAD_POLL_MS } from "../src/https-listener.ts";
import { loadWebApp, MANIFEST, type WebApp } from "../src/web-app.ts";
import { startServer } from "./harness.ts";
import { Phone } from "./phone.ts";

const folder = mkdtempSync(join(tmpdir(), "homecubbie-https-"));

/** A self-signed certificate for this computer, made fresh for the run. */
function makeCertificate(name: string): { cert: string; key: string; fingerprint: string } {
  const cert = join(folder, `${name}.crt`);
  const key = join(folder, `${name}.private`);
  execFileSync(
    "openssl",
    ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "36500", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
    { stdio: "ignore" },
  );
  const der = Buffer.from(readFileSync(cert, "utf8").replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
  return { cert, key, fingerprint: createHash("sha256").update(der).digest("hex") };
}

function webBuild(): WebApp {
  const web = join(folder, "web");
  const policy = "default-src 'self'; connect-src 'self'".replace(/'/g, "&#x27;");
  for (const [path, contents] of Object.entries({
    [MANIFEST]: JSON.stringify({ app: "homecubbie", schemaVersion: 47 }),
    "index.html": `<!DOCTYPE html><html><head><meta http-equiv="Content-Security-Policy" content="${policy}"/></head><body>the web app</body></html>`,
  })) {
    mkdirSync(dirname(join(web, path)), { recursive: true });
    writeFileSync(join(web, path), contents);
  }
  const loaded = loadWebApp(web);
  if (!("app" in loaded)) throw new Error(loaded.missing);
  return loaded.app;
}

interface Got {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  fingerprint: string;
}

/** A request over HTTPS that trusts `cert`, as a browser that has its authority installed would. */
function getSecure(port: number, path: string, cert: string, host = `localhost:${port}`): Promise<Got> {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      { host: "127.0.0.1", servername: "localhost", port, path, ca: readFileSync(cert), agent: false, headers: { Host: host } },
      (res) => {
        const chunks: Buffer[] = [];
        const fingerprint = ((res.socket as TLSSocket).getPeerCertificate().fingerprint256 ?? "").replace(/:/g, "").toLowerCase();
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString("utf8"), fingerprint }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

describe("HTTPS for another computer", () => {
  const first = { cert: "", key: "", fingerprint: "" };
  let household: Household;

  before(() => {
    Object.assign(first, makeCertificate("first"));
    household = new Household(mkdtempSync(join(folder, "data-")));
  });

  after(() => {
    household.close();
    rmSync(folder, { recursive: true, force: true });
  });

  it("listens only when given both a certificate and a key", () => {
    assert.equal(certificateFilesFrom({}), null);
    assert.equal(certificateFilesFrom({ HOMECUBBIE_HTTPS_CERT: "", HOMECUBBIE_HTTPS_KEY: "" }), null);
    assert.equal(certificateFilesFrom({ HOMECUBBIE_HTTPS_CERT: "/a.crt" }), "half");
    assert.equal(certificateFilesFrom({ HOMECUBBIE_HTTPS_KEY: "/a.key" }), "half");
    assert.deepEqual(certificateFilesFrom({ HOMECUBBIE_HTTPS_CERT: "/a.crt", HOMECUBBIE_HTTPS_KEY: "/a.key" }), { certFile: "/a.crt", keyFile: "/a.key" });
  });

  it("serves the web app and the /api routes over HTTPS, with no HSTS, and says the certificate's last day", async () => {
    const logged: string[] = [];
    const secure = createHouseholdHttpsServer(household, { certFile: first.cert, keyFile: first.key }, { webApp: webBuild(), log: { info: (line) => logged.push(line) } });
    await new Promise<void>((done) => secure.server.listen(0, "127.0.0.1", done));
    const { port } = secure.server.address() as AddressInfo;
    try {
      const page = await getSecure(port, "/", first.cert);
      assert.equal(page.status, 200);
      assert.match(page.body, /the web app/);
      assert.equal(page.headers["strict-transport-security"], undefined);
      assert.match(String(page.headers["content-security-policy"]), /frame-ancestors 'none'/);

      const hello = await getSecure(port, "/api/hello", first.cert);
      assert.equal(hello.status, 200);
      assert.equal(JSON.parse(hello.body).app, "homecubbie");
      assert.equal(hello.headers["strict-transport-security"], undefined);
      assert.equal(hello.fingerprint, first.fingerprint);

      const lastDay = certificateLastDay(readFileSync(first.cert)) as Date;
      assert.ok(logged.some((line) => line.includes(`runs out on ${lastDay.toISOString().slice(0, 10)}`)), logged.join("\n"));
    } finally {
      secure.stopWatching();
      secure.server.close();
    }
  });

  it("serves a replaced certificate from the next connection on, with no restart", async () => {
    const live = { cert: join(folder, "live.crt"), key: join(folder, "live.private") };
    copyFileSync(first.cert, live.cert);
    copyFileSync(first.key, live.key);
    const logged: string[] = [];
    const secure = createHouseholdHttpsServer(household, { certFile: live.cert, keyFile: live.key }, { log: { info: (line) => logged.push(line) } });
    await new Promise<void>((done) => secure.server.listen(0, "127.0.0.1", done));
    const { port } = secure.server.address() as AddressInfo;
    try {
      assert.equal((await getSecure(port, "/api/hello", first.cert)).fingerprint, first.fingerprint);

      const renewed = makeCertificate("renewed");
      copyFileSync(renewed.key, live.key);
      copyFileSync(renewed.cert, live.cert);
      let seen = first.fingerprint;
      for (let tries = 0; tries < 20 && seen !== renewed.fingerprint; tries += 1) {
        await new Promise((done) => setTimeout(done, RELOAD_POLL_MS / 2));
        seen = (await getSecure(port, "/api/hello", renewed.cert).catch(() => ({ fingerprint: first.fingerprint }))).fingerprint;
      }
      assert.equal(seen, renewed.fingerprint);
      assert.ok(logged.some((line) => line.startsWith("read the certificate again")), logged.join("\n"));
    } finally {
      secure.stopWatching();
      secure.server.close();
    }
  });

  it("lets a proven request through a reverse proxy, with the proxy's name as Host", async () => {
    const server = await startServer({ hostNames: ["house.tailnet-example.ts.net"] });
    try {
      const phone = new Phone(server.baseUrl);
      assert.equal((await phone.claim(server.setupCode())).status, 200);
      const port = new URL(server.baseUrl).port;
      const path = "/api/phones";
      const time = Date.now();
      const nonce = randomBytes(16).toString("base64url");
      const proof = hmac(phone.link(), requestProofInput("GET", path, time, nonce, Buffer.alloc(0))).toString("base64url");
      const answer = await new Promise<{ status: number; body: Buffer; replyProof: string }>((resolve, reject) => {
        const req = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path,
            headers: {
              // As `tailscale serve` or nginx forwards it: the name the browser used.
              Host: "house.tailnet-example.ts.net",
              "X-HC-Phone": phone.id,
              "X-HC-Time": String(time),
              "X-HC-Nonce": nonce,
              "X-HC-Proof": proof,
            },
          },
          (res) => {
            const chunks: Buffer[] = [];
            res.on("data", (chunk: Buffer) => chunks.push(chunk));
            res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks), replyProof: String(res.headers["x-hc-reply-proof"]) }));
          },
        );
        req.on("error", reject);
        req.end();
      });
      assert.equal(answer.status, 200);
      const expected = hmac(phone.link(), replyProofInput(nonce, 200, answer.body));
      assert.ok(sameBytes(expected, Buffer.from(answer.replyProof, "base64url")));
    } finally {
      await server.close();
    }
  });
});
