/**
 * The household server, end to end over HTTP, with stand-in phones that speak
 * the household key protocol.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, it } from "node:test";
import { Phone, dataKey, open, seal } from "./phone.ts";
import { startServer, type Running } from "./harness.ts";
import { Store } from "../src/store.ts";

async function withServer(run: (server: Running) => Promise<void>, options?: Parameters<typeof startServer>[0]) {
  const server = await startServer(options);
  try {
    await run(server);
  } finally {
    await server.close();
  }
}

/**
 * A server with one phone that has set it up and uploaded its house, and a
 * second that joined by invite. Changes are refused until the first copy is
 * in, because there is no house on the server for them to change.
 */
async function household(server: Running): Promise<{ first: Phone; second: Phone }> {
  const first = new Phone(server.baseUrl);
  assert.equal((await first.claim(server.setupCode())).status, 200);
  await uploadHouse(first, "the first phone's house");
  const invite = await first.invite();
  assert.equal(invite.answer.status, 200);
  const second = new Phone(server.baseUrl);
  assert.equal((await second.join(invite, first.serverKey as Buffer)).status, 200);
  return { first, second };
}

describe("setting the server up", () => {
  it("says what it is, and that it isn't set up, without giving out the setup code", async () => {
    await withServer(async (server) => {
      const hello = await new Phone(server.baseUrl).hello();
      assert.equal(hello.app, "homecubbie");
      assert.equal(hello.setUp, false);
      assert.equal(Buffer.from(hello.serverKey as string, "base64url").length, 32);
      // Its version, for the setup guide, and its clock, for "Test connection".
      const pkg = JSON.parse(readFileSync(join(import.meta.dirname, "..", "package.json"), "utf8")) as { version: string };
      assert.equal(hello.version, pkg.version);
      assert.ok(Math.abs((hello.time as number) - Date.now()) < 60_000);
      assert.ok(!JSON.stringify(hello).includes(server.setupCode()));
      const page = await (await fetch(server.baseUrl)).text();
      assert.ok(!page.includes(server.setupCode()));
    });
  });

  it("says the house's database version, before and after a copy at a higher one is in", async () => {
    await withServer(async (server) => {
      const phone = new Phone(server.baseUrl);
      assert.equal((await phone.hello()).schemaVersion, 0);
      const { first } = await household(server);
      assert.equal((await first.hello()).schemaVersion, 41);
      // Uploaded but not yet the copy every phone starts from: still 41.
      const bytes = seal(dataKey(first.household as never), Buffer.from("the house, a version on"), "copy");
      const uploaded = await first.call("PUT", `/api/copy?epoch=${first.household?.epoch}&schema=42&through=0`, bytes);
      assert.equal((await first.hello()).schemaVersion, 41);
      await first.call("POST", "/api/copy/activate", { copyId: uploaded.json.copyId });
      assert.equal((await first.hello()).schemaVersion, 42);
      // Unproven, as the rest of hello is: what the browser does with it is tested with the browser.
      assert.equal(typeof (await fetch(`${server.baseUrl}/api/hello`)).headers.get("x-hc-reply-proof"), "object");
    });
  });

  it("is taken by the first phone with the setup code, and by nobody after that", async () => {
    await withServer(async (server) => {
      const code = server.setupCode();
      const first = new Phone(server.baseUrl);
      const claimed = await first.claim(code);
      assert.equal(claimed.status, 200);
      assert.equal(claimed.replyProven, true);
      assert.equal(server.household.setupCode(), null);

      const late = await new Phone(server.baseUrl).claim(code);
      assert.equal(late.status, 409);
      assert.equal(late.json.error, "already-set-up");
    });
  });

  it("takes a household moving from a lost server at its next epoch, keeps the proof, and gives both back", async () => {
    await withServer(async (server) => {
      // Before it is set up, it has no epoch to give.
      assert.equal((await new Phone(server.baseUrl).hello()).epoch, null);

      const householdId = randomBytes(16).toString("base64url");
      const proof = randomBytes(32);
      const mover = new Phone(server.baseUrl);
      const claimed = await mover.claim(server.setupCode(), "Moving phone", { householdId, epoch: 4, rekeyProof: proof });
      assert.equal(claimed.status, 200);
      assert.equal(claimed.replyProven, true);
      assert.equal(claimed.json.householdId, householdId);
      assert.equal(claimed.json.epoch, 4);

      const hello = await mover.hello();
      assert.equal(hello.householdId, householdId);
      assert.equal(hello.epoch, 4);
      // Unproven, as the rest of hello is: it is only ever a reason to ask.
      assert.equal(typeof (await fetch(`${server.baseUrl}/api/hello`)).headers.get("x-hc-reply-proof"), "object");

      // A phone that joins here is told the proof, to check against the key it held.
      await uploadHouse(mover, "the moving phone's house");
      const invite = await mover.invite();
      const joined = await new Phone(server.baseUrl).join(invite, mover.serverKey as Buffer);
      assert.equal(joined.status, 200);
      assert.equal(joined.replyProven, true);
      assert.equal(joined.json.epoch, 4);
      assert.equal(joined.json.rekeyProof, proof.toString("base64url"));

      // A second claim is refused, as now, whatever it says it is.
      const late = await new Phone(server.baseUrl).claim("AAAABBBBCCCCDDDD", "Late", { householdId, epoch: 5, rekeyProof: randomBytes(32) });
      assert.equal(late.status, 409);
      assert.equal(late.json.error, "already-set-up");
    });
  });

  it("refuses a starting epoch with no proof, and a first epoch with one", async () => {
    await withServer(async (server) => {
      const householdId = randomBytes(16).toString("base64url");
      const withoutProof = await new Phone(server.baseUrl).claim(server.setupCode(), "x", { householdId, epoch: 3, rekeyProof: null });
      assert.equal(withoutProof.status, 400);
      const shortProof = await new Phone(server.baseUrl).claim(server.setupCode(), "x", { householdId, epoch: 3, rekeyProof: randomBytes(8) });
      assert.equal(shortProof.status, 400);
      const firstWithProof = await new Phone(server.baseUrl).claim(server.setupCode(), "x", { householdId, epoch: 1, rekeyProof: randomBytes(32) });
      assert.equal(firstWithProof.status, 400);
      const zero = await new Phone(server.baseUrl).claim(server.setupCode(), "x", { householdId, epoch: 0, rekeyProof: randomBytes(32) });
      assert.equal(zero.status, 400);
      assert.equal((await new Phone(server.baseUrl).hello()).setUp, false);
    });
  });

  it("gives a join no proof at a household's first epoch, and the key change's after one", async () => {
    await withServer(async (server) => {
      const { first } = await household(server);
      assert.equal((await first.hello()).epoch, 1);
      const before = await new Phone(server.baseUrl).join(await first.invite(), first.serverKey as Buffer);
      assert.equal(before.json.rekeyProof, null);

      const rekeyProof = randomBytes(32).toString("base64url");
      const copy = await first.call("PUT", "/api/copy?epoch=2&schema=41&through=0", seal(dataKey(first.household as never), Buffer.from("house"), "copy"));
      const phones = (await first.call("GET", "/api/phones")).json.phones as { phoneId: string; phoneKey: string; removed: boolean }[];
      const next = { ...(first.household as { id: string; key: Buffer; epoch: number }), key: randomBytes(32), epoch: 2 };
      const wraps = phones
        .filter((row) => row.phoneId !== first.id && !row.removed)
        .map((row) => Phone.wrapFor({ phoneId: row.phoneId, phoneKey: Buffer.from(row.phoneKey, "base64url") }, next));
      assert.equal((await first.call("POST", "/api/key", { epoch: 2, copyId: copy.json.copyId, rekeyProof, ...first.signedChange({ epoch: 2, key: next.key }), wraps })).status, 200);
      first.household = next;
      assert.equal((await first.hello()).epoch, 2);
      const after = await new Phone(server.baseUrl).join(await first.invite(), first.serverKey as Buffer);
      assert.equal(after.json.rekeyProof, rekeyProof);
    });
  });

  it("refuses a wrong setup code, and replaces the code after five wrong ones", async () => {
    await withServer(async (server) => {
      const original = server.setupCode();
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const wrong = await new Phone(server.baseUrl).claim("AAAABBBBCCCCDDDD");
        assert.equal(wrong.status, 401);
        assert.equal(wrong.json.error, "bad-setup-code");
      }
      assert.notEqual(server.setupCode(), original);
      assert.equal((await new Phone(server.baseUrl).claim(original)).status, 401);
      assert.ok(server.logged.some((line) => line.includes("new one")));
    });
  });

  it("accepts the setup code typed in lower case, with dashes", async () => {
    await withServer(async (server) => {
      const typed = server.setupCode().toLowerCase().replace(/(.{4})(?=.)/g, "$1-");
      assert.equal((await new Phone(server.baseUrl).claim(typed)).status, 200);
    });
  });

  it("refuses a claim made against a swapped server key", async () => {
    await withServer(async (server) => {
      const phone = new Phone(server.baseUrl);
      const realHello = phone.hello.bind(phone);
      phone.hello = async () => ({ ...(await realHello()), serverKey: randomBytes(32).toString("base64url") });
      const answer = await phone.claim(server.setupCode());
      assert.equal(answer.status, 401);
      assert.equal(server.household.isSetUp(), false);
    });
  });
});

describe("proving every request", () => {
  it("refuses a request with no proof", async () => {
    await withServer(async (server) => {
      const { first } = await household(server);
      const response = await fetch(`${server.baseUrl}/api/phones`, { headers: { "X-HC-Phone": first.id } });
      assert.equal(response.status, 401);
    });
  });

  it("refuses a stranger before reading what it sends", async () => {
    await withServer(async (server) => {
      await household(server);
      const response = await fetch(`${server.baseUrl}/api/copy?epoch=1&schema=41&through=0`, {
        method: "PUT",
        headers: { "X-HC-Phone": "not-a-phone-here" },
        body: Buffer.alloc(8 * 1024 * 1024),
      });
      assert.equal(response.status, 401);
      assert.equal(((await response.json()) as { error: string }).error, "unknown-phone");
    });
  });

  it("refuses an altered request and a replayed one", async () => {
    await withServer(async (server) => {
      const { first } = await household(server);
      const nonce = randomBytes(16).toString("base64url");
      const time = Date.now();
      const body = { since: 0, batches: [] };
      assert.equal((await first.send("POST", "/api/sync", { key: first.link(), body, nonce, time })).status, 200);
      const replayed = await first.send("POST", "/api/sync", { key: first.link(), body, nonce, time });
      assert.equal(replayed.json.error, "replay");

      // The proof covers the body's hash, so a body changed on the way is refused.
      const altered = await first.send("POST", "/api/sync", {
        key: first.link(),
        body,
        sendBody: Buffer.from(JSON.stringify({ since: 5, batches: [] })),
      });
      assert.equal(altered.json.error, "bad-proof");
    });
  });

  it("refuses a request from a clock five minutes off, and says the server's time", async () => {
    await withServer(async (server) => {
      const { first } = await household(server);
      first.clock = () => Date.now() - 6 * 60 * 1000;
      const answer = await first.call("GET", "/api/phones");
      assert.equal(answer.json.error, "clock");
      assert.equal(typeof answer.json.serverTime, "number");
      assert.equal(answer.replyProven, true);
    });
  });

  it("proves its replies, so a phone can tell its own server from another one", async () => {
    await withServer(async (server) => {
      const { first } = await household(server);
      assert.equal((await first.call("GET", "/api/phones")).replyProven, true);

      // Another HomeCubbie server, such as a friend's, at the address this phone knows.
      await withServer(async (other) => {
        const confused = Object.assign(Object.create(Object.getPrototypeOf(first)), first, { baseUrl: other.baseUrl }) as Phone;
        const answer = await confused.call("GET", "/api/phones");
        assert.equal(answer.replyProven, false);
        assert.notEqual(answer.status, 200);
      });
    });
  });

  it("answers only to an IP address, localhost, or a name it was given", async () => {
    await withServer(
      async (server) => {
        const port = new URL(server.baseUrl).port;
        const hello = (host: string) =>
          new Promise<number>((resolve, reject) => {
            import("node:http").then(({ request }) => {
              const req = request({ host: "127.0.0.1", port, path: "/api/hello", headers: { Host: host } }, (res) => {
                res.resume();
                resolve(res.statusCode ?? 0);
              });
              req.on("error", reject);
              req.end();
            });
          });
        assert.equal(await hello(`127.0.0.1:${port}`), 200);
        assert.equal(await hello(`localhost:${port}`), 200);
        assert.equal(await hello(`mac-mini.local:${port}`), 200);
        assert.equal(await hello(`evil.example:${port}`), 421);
      },
      { hostNames: ["mac-mini.local"] },
    );
  });

  it("refuses a body over its limit", async () => {
    await withServer(async (server) => {
      const { first } = await household(server);
      const answer = await first.call("PUT", `/api/files/${randomBytes(16).toString("hex")}/0`, randomBytes(1024 * 1024 + 2048));
      assert.equal(answer.status, 413);
    });
  });
});

describe("inviting a phone", () => {
  it("lets a phone join once, with the household key it couldn't have had before", async () => {
    await withServer(async (server) => {
      const first = new Phone(server.baseUrl);
      await first.claim(server.setupCode());
      const invite = await first.invite();
      const second = new Phone(server.baseUrl);
      const joined = await second.join(invite, first.serverKey as Buffer);
      assert.equal(joined.status, 200);
      assert.equal(joined.replyProven, true);
      assert.deepEqual(second.household?.key, first.household?.key);

      const again = await new Phone(server.baseUrl).join(invite, first.serverKey as Buffer);
      assert.equal(again.status, 410);
      assert.equal(again.json.error, "invite-gone");
    });
  });

  it("lists a browser that joined as a browser, and a phone as a phone", async () => {
    await withServer(async (server) => {
      const first = new Phone(server.baseUrl);
      await first.claim(server.setupCode());
      const browser = new Phone(server.baseUrl);
      browser.device = "browser";
      assert.equal((await browser.join(await first.invite(), first.serverKey as Buffer)).status, 200);
      const phone = new Phone(server.baseUrl);
      assert.equal((await phone.join(await first.invite(), first.serverKey as Buffer)).status, 200);

      const listed = (await first.call("GET", "/api/phones")).json.phones as { phoneId: string; kind: string }[];
      const kindOf = (id: string) => listed.find((entry) => entry.phoneId === id)?.kind;
      assert.equal(kindOf(first.id), "phone");
      assert.equal(kindOf(browser.id), "browser");
      assert.equal(kindOf(phone.id), "phone");
    });
  });

  it("forgets an invite once it has expired", async () => {
    let now = Date.now();
    await withServer(
      async (server) => {
        const first = new Phone(server.baseUrl);
        first.clock = () => now;
        await first.claim(server.setupCode());
        const invite = await first.invite(60_000);
        now += 61_000;
        const late = new Phone(server.baseUrl);
        late.clock = () => now;
        assert.equal((await late.join(invite, first.serverKey as Buffer)).json.error, "invite-gone");
      },
      { clock: { now: () => now } },
    );
  });

  it("refuses a phone key built to make the shared secret predictable", async () => {
    await withServer(async (server) => {
      const first = new Phone(server.baseUrl);
      await first.claim(server.setupCode());
      const invite = await first.invite();
      const hostile = new Phone(server.baseUrl);
      Object.defineProperty(hostile, "publicKey", { value: Buffer.alloc(32) });
      const answer = await hostile.send("POST", "/api/join", {
        key: (await import("../src/crypto.ts")).hkdf(invite.secret, "", "hc join v1"),
        replyKey: null,
        phoneHeader: false,
        body: { inviteId: invite.inviteId, phoneId: hostile.id, phoneKey: Buffer.alloc(32).toString("base64url"), nameBlob: "AAAA" },
      });
      assert.equal(answer.status, 400);
      assert.equal(server.household.store.findPhone(hostile.id), undefined);
    });
  });

  it("refuses an invite that would last longer than ten minutes", async () => {
    await withServer(async (server) => {
      const first = new Phone(server.baseUrl);
      await first.claim(server.setupCode());
      assert.equal((await first.invite(11 * 60 * 1000)).answer.status, 400);
    });
  });

  it("deletes an invite after five wrong proofs", async () => {
    await withServer(async (server) => {
      const first = new Phone(server.baseUrl);
      await first.claim(server.setupCode());
      const invite = await first.invite();
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const guess = await new Phone(server.baseUrl).join({ inviteId: invite.inviteId, secret: randomBytes(16) }, first.serverKey as Buffer);
        assert.equal(guess.json.error, "bad-proof");
      }
      assert.equal((await new Phone(server.baseUrl).join(invite, first.serverKey as Buffer)).json.error, "invite-gone");
    });
  });
});

describe("passing changes between phones", () => {
  it("hands one phone's changes to the other, in arrival order", async () => {
    await withServer(async (server) => {
      const { first, second } = await household(server);
      const pushed = await first.call("POST", "/api/sync", {
        since: 0,
        batches: [first.batchOf([{ table: "location", column: "name", value: "Kitchen" }]), first.batchOf([{ n: 2 }])],
      });
      assert.equal(pushed.status, 200);

      const pulled = await second.call("POST", "/api/sync", { since: 0, batches: [] });
      const changes = pulled.json.changes as { seq: number; phoneId: string; batch: number; epoch: number; schemaVersion: number; blob: string }[];
      assert.equal(changes.length, 2);
      assert.ok((changes[0]?.seq ?? 0) < (changes[1]?.seq ?? 0));
      assert.deepEqual(second.readBatch(changes[0] as (typeof changes)[number]), [{ table: "location", column: "name", value: "Kitchen" }]);
      assert.equal(pulled.json.next, changes[1]?.seq);
      assert.equal(pulled.json.more, false);
    });
  });

  it("takes the same batch again without storing it twice", async () => {
    await withServer(async (server) => {
      const { first } = await household(server);
      const batch = first.batchOf([{ n: 1 }]);
      await first.call("POST", "/api/sync", { since: 0, batches: [batch] });
      const retried = await first.call("POST", "/api/sync", { since: 0, batches: [batch] });
      assert.equal((retried.json.changes as unknown[]).length, 1);
      assert.equal(retried.json.lastBatch, 1);
    });
  });

  it("refuses a different batch under a number this phone already used: two installs share one identity", async () => {
    await withServer(async (server) => {
      const { first } = await household(server);
      await first.call("POST", "/api/sync", { since: 0, batches: [first.batchOf([{ from: "the old iPhone" }])] });
      first.batch = 0;
      const copied = await first.call("POST", "/api/sync", { since: 0, batches: [first.batchOf([{ from: "the copy" }])] });
      assert.equal(copied.json.error, "identity-in-use");
    });
  });

  it("knows a batch it holds before it looks at the key, and names it when it refuses the rest for the key", async () => {
    await withServer(async (server) => {
      const { first } = await household(server);
      const arrived = first.batchOf([{ n: 1 }]);
      await first.call("POST", "/api/sync", { since: 0, batches: [arrived] });

      // Its reply was lost, and the key changed before the phone tried again.
      const again = await first.call("POST", "/api/sync", { since: 0, batches: [{ ...arrived, epoch: 7 }] });
      assert.equal(again.json.error, undefined);
      assert.equal(again.json.lastBatch, 1);

      const refused = await first.call("POST", "/api/sync", {
        since: 0,
        batches: [{ ...arrived, epoch: 7 }, { ...first.batchOf([{ n: 2 }]), epoch: 7 }],
      });
      assert.equal(refused.json.error, "key-changed");
      assert.deepEqual(refused.json.held, [1]);
      assert.equal(server.household.store.lastBatchOf(first.id), 1);
    });
  });

  it("refuses changes under an old key, and from an app older than the house", async () => {
    await withServer(async (server) => {
      const { first } = await household(server);
      const stale = { ...first.batchOf([{}]), epoch: 7 };
      assert.equal((await first.call("POST", "/api/sync", { since: 0, batches: [stale] })).json.error, "key-changed");

      // An updated phone raises the house's schema version with a full copy first.
      const copy = await first.call("PUT", "/api/copy?epoch=1&schema=42&through=0", randomBytes(64));
      await first.call("POST", "/api/copy/activate", { copyId: copy.json.copyId });
      const older = await first.call("POST", "/api/sync", { since: 0, batches: [first.batchOf([{}], 41)] });
      assert.equal(older.json.error, "app-too-old");
      assert.equal(older.json.schemaVersion, 42);
      const newer = await first.call("POST", "/api/sync", { since: 0, batches: [first.batchOf([{}], 43)] });
      assert.equal(newer.json.error, "copy-first");
    });
  });

  it("takes changes from a phone behind the house, down to the floor its copy named, and says the floor", async () => {
    await withServer(async (server) => {
      const { first, second } = await household(server);
      // A copy from an app older than mixed-version sharing names no floor: only its own version is taken.
      assert.equal(server.household.schemaFloor(), 41);

      // One that names a floor takes every version from it up to the house's.
      const copy = await first.call("PUT", "/api/copy?epoch=1&schema=43&through=0&floor=41", randomBytes(64));
      await first.call("POST", "/api/copy/activate", { copyId: copy.json.copyId });
      assert.equal(server.household.schemaVersion(), 43);
      assert.equal(server.household.schemaFloor(), 41);
      const behind = await second.call("POST", "/api/sync", { since: 0, batches: [second.batchOf([{}], 41), second.batchOf([{}], 42)] });
      assert.equal(behind.status, 200);
      assert.equal(behind.json.schemaVersion, 43);
      assert.equal(behind.json.schemaFloor, 41);
      assert.deepEqual(
        (behind.json.changes as { schemaVersion: number }[]).map((change) => change.schemaVersion),
        [41, 42],
      );

      // Below the floor is still too old, and says where the floor is.
      const below = await second.call("POST", "/api/sync", { since: 0, batches: [second.batchOf([{}], 40)] });
      assert.equal(below.json.error, "app-too-old");
      assert.equal(below.json.schemaFloor, 41);
      // Ahead of the house still uploads a copy first.
      assert.equal((await second.call("POST", "/api/sync", { since: 0, batches: [second.batchOf([{}], 44)] })).json.error, "copy-first");

      // A copy from the phone behind is refused: it holds the newer details only as waiting changes.
      assert.equal((await second.call("PUT", "/api/copy?epoch=1&schema=42&through=0&floor=41", randomBytes(64))).json.error, "app-too-old");
      // A floor above the copy's own version, or below 1, is nonsense.
      for (const floor of [44, 0, -1]) {
        assert.equal((await first.call("PUT", `/api/copy?epoch=1&schema=43&through=0&floor=${floor}`, randomBytes(64))).json.error, "bad-request");
      }
    });
  });

  it("tells a phone when the server is behind what the phone has seen", async () => {
    await withServer(async (server) => {
      const { first } = await household(server);
      const answer = await first.call("POST", "/api/sync", { since: 900, batches: [] });
      assert.equal(answer.json.error, "server-behind");
      assert.equal(answer.json.lastSeq, 0);
    });
  });
});

describe("full copies of the house", () => {
  it("starts a new phone from the newest copy, and keeps the changes for phones that are behind", async () => {
    await withServer(async (server) => {
      const { first, second } = await household(server);
      await first.call("POST", "/api/sync", { since: 0, batches: [first.batchOf([1]), first.batchOf([2]), first.batchOf([3])] });
      await uploadHouse(first, "the whole house", 2);

      // A phone that was behind carries on from where it was.
      const behind = await second.call("POST", "/api/sync", { since: 0, batches: [] });
      assert.equal(behind.json.mustLoadCopy, false);
      assert.deepEqual((behind.json.changes as { seq: number }[]).map((change) => change.seq), [1, 2, 3]);

      // A new phone loads the copy and asks only for what came after it.
      const copy = await second.call("GET", "/api/copy");
      assert.equal(copy.headers.get("content-disposition"), "attachment");
      assert.equal(JSON.parse(copy.headers.get("x-hc-copy") ?? "{}").throughSeq, 2);
      assert.equal(open(dataKey(second.household as never), copy.bytes, "copy").toString(), "the whole house");
      const after = await second.call("POST", "/api/sync", { since: 2, batches: [] });
      assert.deepEqual((after.json.changes as { seq: number }[]).map((change) => change.seq), [3]);
    });
  });

  it("drops every change on a reset, and sends a phone that was behind back to the copy", async () => {
    await withServer(async (server) => {
      const { first, second } = await household(server);
      await first.call("POST", "/api/sync", { since: 0, batches: [first.batchOf([1]), first.batchOf([2])] });
      const next = { id: first.household?.id as string, key: randomBytes(32), epoch: 2 };
      const copy = await first.call("PUT", "/api/copy?epoch=2&schema=41&through=2", seal(dataKey(next), Buffer.from("house"), "copy"));
      const reset = await first.call("POST", "/api/key", {
        epoch: 2,
        copyId: copy.json.copyId,
        reset: true,
        rekeyProof: randomBytes(32).toString("base64url"),
        ...first.signedChange({ epoch: 2, key: next.key, kind: "reset" }),
        wraps: [Phone.wrapFor({ phoneId: second.id, phoneKey: second.publicKey }, next)],
      });
      assert.equal(reset.status, 200);
      const behind = await second.call("POST", "/api/sync", { since: 0, batches: [] });
      assert.equal(behind.json.mustLoadCopy, true);
      assert.deepEqual(behind.json.changes, []);
    });
  });

  it("sends every other phone back to the copy after a reset, even one that was up to date", async () => {
    await withServer(async (server) => {
      const { first, second } = await household(server);
      await first.call("POST", "/api/sync", { since: 0, batches: [first.batchOf([1]), first.batchOf([2])] });
      // The second phone has seen everything: by numbers alone it is not behind.
      const upToDate = await second.call("POST", "/api/sync", { since: 0, batches: [] });
      assert.equal(upToDate.json.next, 2);

      const next = { id: first.household?.id as string, key: randomBytes(32), epoch: 2 };
      // The resetting phone says it has seen 0, as a phone restored from a
      // backup might. The copy covers everything regardless.
      const copy = await first.call("PUT", "/api/copy?epoch=2&schema=41&through=0", seal(dataKey(next), Buffer.from("house"), "copy"));
      const reset = await first.call("POST", "/api/key", {
        epoch: 2,
        copyId: copy.json.copyId,
        reset: true,
        rekeyProof: randomBytes(32).toString("base64url"),
        ...first.signedChange({ epoch: 2, key: next.key, kind: "reset" }),
        wraps: [Phone.wrapFor({ phoneId: second.id, phoneKey: second.publicKey }, next)],
      });
      assert.deepEqual(reset.json, { epoch: 2, lastSeq: 2 });

      // What it sends before loading the copy was made against the old house, and isn't kept.
      const stale = await second.call("POST", "/api/sync", { since: 2, batches: [{ ...second.batchOf([9]), epoch: 1 }] });
      assert.equal(stale.json.mustLoadCopy, true);
      assert.equal((stale.json.copy as { throughSeq: number }).throughSeq, 2);
      assert.equal(stale.json.lastBatch, 0);

      // Only the copy now in use clears the mark.
      assert.equal((await second.call("POST", "/api/copy/loaded", { copyId: "not-that-one" })).json.error, "not-found");
      assert.equal((await second.call("POST", "/api/copy/loaded", { copyId: copy.json.copyId })).status, 200);
      const after = await second.call("POST", "/api/sync", { since: 2, batches: [{ ...second.batchOf([10]), epoch: 2 }] });
      assert.equal(after.json.mustLoadCopy, false);
      assert.equal(after.json.lastBatch, 2);

      // The phone that reset is never sent back.
      const own = await first.call("POST", "/api/sync", { since: 2, batches: [] });
      assert.equal(own.json.mustLoadCopy, false);
    });
  });

  it("adds the reload mark to a server folder made before it existed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "hc-old-folder-"));
    const old = new DatabaseSync(join(dir, "household.db"));
    old.exec(`CREATE TABLE phone (
      id TEXT PRIMARY KEY NOT NULL, public_key BLOB NOT NULL UNIQUE, name_blob BLOB NOT NULL,
      kind TEXT NOT NULL CHECK (kind IN ('phone', 'paper')), joined_at TEXT NOT NULL,
      last_seen_at TEXT, removed_at TEXT)`);
    old.prepare("INSERT INTO phone (id, public_key, name_blob, kind, joined_at) VALUES ('p', x'01', x'02', 'phone', 'then')").run();
    old.close();
    const store = new Store(dir);
    assert.equal(store.findPhone("p")?.must_reload, 0);
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("removing a phone and changing the key", () => {
  it("shuts a removed phone out at once, and hands the new key only to the phones still in", async () => {
    await withServer(async (server) => {
      const { first, second } = await household(server);
      const third = new Phone(server.baseUrl);
      await third.join(await first.invite(), first.serverKey as Buffer);

      const next = { id: first.household?.id as string, key: randomBytes(32), epoch: 2 };
      const copy = await first.call("PUT", "/api/copy?epoch=2&schema=41&through=0", seal(dataKey(next), Buffer.from("house"), "copy"));
      const rekeyProof = randomBytes(32).toString("base64url");
      const signed = first.signedChange({ epoch: 2, key: next.key, removed: second.id });

      // Forgetting a phone that's still in is refused, so nobody is locked out.
      const forgetful = await first.call("POST", "/api/key", { epoch: 2, copyId: copy.json.copyId, rekeyProof, ...signed, remove: second.id, wraps: [] });
      assert.equal(forgetful.status, 400);
      // And so is a key change with no proof from the key before it.
      const unproven = await first.call("POST", "/api/key", {
        epoch: 2,
        copyId: copy.json.copyId,
        ...signed,
        remove: second.id,
        wraps: [Phone.wrapFor({ phoneId: third.id, phoneKey: third.publicKey }, next)],
      });
      assert.equal(unproven.status, 400);
      // Neither took the phone out.
      assert.equal((await second.call("POST", "/api/sync", { since: 0, batches: [] })).status, 200);

      // Removing and changing the key are one step.
      const changed = await first.call("POST", "/api/key", {
        epoch: 2,
        copyId: copy.json.copyId,
        rekeyProof,
        ...signed,
        remove: second.id,
        wraps: [Phone.wrapFor({ phoneId: third.id, phoneKey: third.publicKey }, next)],
      });
      assert.equal(changed.status, 200);
      const removed = await second.call("POST", "/api/sync", { since: 0, batches: [] });
      assert.equal(removed.status, 403);
      assert.equal(removed.json.error, "removed");

      const wrap = await third.call("GET", "/api/key");
      assert.equal(wrap.json.rekeyProof, rekeyProof);
      third.unwrap(wrap.json as never);
      assert.deepEqual(third.household?.key, next.key);
      assert.equal((await second.call("GET", "/api/key")).status, 403);
      // The wrap for an earlier epoch is still there, for a phone walking forward.
      assert.equal((await third.call("GET", "/api/key?epoch=2")).json.epoch, 2);
      assert.equal((await third.call("GET", "/api/key?epoch=3")).status, 400);
    });
  });

  // A phone that joins from a copy holds only the key in force, so
  // the copy must run past every change sealed under a key before it.
  it("changes the key only with a copy that runs through every change under the key before", async () => {
    await withServer(async (server) => {
      const { first, second } = await household(server);
      assert.equal((await second.call("POST", "/api/sync", { since: 0, batches: [second.batchOf([{ from: "second" }])] })).status, 200);

      const next = { id: first.household?.id as string, key: randomBytes(32), epoch: 2 };
      const change = (copyId: unknown) =>
        first.call("POST", "/api/key", {
          epoch: 2,
          copyId,
          rekeyProof: randomBytes(32).toString("base64url"),
          ...first.signedChange({ epoch: 2, key: next.key }),
          wraps: [Phone.wrapFor({ phoneId: second.id, phoneKey: second.publicKey }, next)],
        });
      // Made before the second phone's change arrived.
      const behind = await first.call("PUT", "/api/copy?epoch=2&schema=41&through=0", seal(dataKey(next), Buffer.from("house"), "copy"));
      const refused = await change(behind.json.copyId);
      assert.equal(refused.status, 409);
      assert.equal(refused.json.error, "copy-behind");
      // Nothing changed: the old key still holds.
      assert.equal((await second.call("POST", "/api/sync", { since: 1, batches: [second.batchOf([{}])] })).status, 200);

      const whole = await first.call("PUT", "/api/copy?epoch=2&schema=41&through=2", seal(dataKey(next), Buffer.from("house"), "copy"));
      assert.equal((await change(whole.json.copyId)).status, 200);
    });
  });

  it("raises the house's version only with a copy that runs past every change under an earlier key", async () => {
    await withServer(async (server) => {
      const { first, second } = await household(server);
      assert.equal((await second.call("POST", "/api/sync", { since: 0, batches: [second.batchOf([{ from: "second" }])] })).status, 200);
      const next = { id: first.household?.id as string, key: randomBytes(32), epoch: 2 };
      const keyCopy = await first.call("PUT", "/api/copy?epoch=2&schema=41&through=1", seal(dataKey(next), Buffer.from("house"), "copy"));
      const changed = await first.call("POST", "/api/key", {
        epoch: 2,
        copyId: keyCopy.json.copyId,
        rekeyProof: randomBytes(32).toString("base64url"),
        ...first.signedChange({ epoch: 2, key: next.key }),
        wraps: [Phone.wrapFor({ phoneId: second.id, phoneKey: second.publicKey }, next)],
      });
      assert.equal(changed.status, 200);

      // A phone on a newer app, under the new key, whose house is from before the change under key 1.
      const behind = await first.call("PUT", "/api/copy?epoch=2&schema=42&through=0", seal(dataKey(next), Buffer.from("house"), "copy"));
      const refused = await first.call("POST", "/api/copy/activate", { copyId: behind.json.copyId });
      assert.equal(refused.status, 409);
      assert.equal(refused.json.error, "copy-behind");
      const whole = await first.call("PUT", "/api/copy?epoch=2&schema=42&through=1", seal(dataKey(next), Buffer.from("house"), "copy"));
      assert.equal((await first.call("POST", "/api/copy/activate", { copyId: whole.json.copyId })).status, 200);
    });
  });

  it("adds no phone but by invite: a member can't plant one the others can't see", async () => {
    await withServer(async (server) => {
      const { first } = await household(server);
      const planted = await first.call("POST", "/api/phones", {
        phoneId: randomBytes(12).toString("base64url"),
        phoneKey: randomBytes(32).toString("base64url"),
        nameBlob: randomBytes(40).toString("base64url"),
        kind: "paper",
      });
      assert.equal(planted.status, 404);
      assert.equal(((await first.call("GET", "/api/phones")).json.phones as unknown[]).length, 2);
    });
  });

  it("lets a phone leave, after which it can't sync", async () => {
    await withServer(async (server) => {
      const { second } = await household(server);
      assert.equal((await second.call("POST", "/api/leave")).status, 200);
      assert.equal((await second.call("POST", "/api/sync", { since: 0, batches: [] })).json.error, "removed");
    });
  });
});

type RecoveryStatus = {
  recovery: { epoch: number; madeBy: string; madeAt: string } | null;
  used: { at: string; by: string | null } | null;
  ended: { at: string } | null;
};

async function recoveryStatus(phone: Phone): Promise<RecoveryStatus> {
  return (await phone.call("GET", "/api/recovery")).json as unknown as RecoveryStatus;
}

/** A key change from `phone` to the next epoch, wrapped for `others`, optionally removing one. */
async function changeKey(phone: Phone, others: Phone[], remove?: string): Promise<number> {
  const next = { id: phone.household?.id as string, key: randomBytes(32), epoch: (phone.household?.epoch ?? 0) + 1 };
  const copy = await phone.call("PUT", `/api/copy?epoch=${next.epoch}&schema=41&through=0`, seal(dataKey(next), Buffer.from("house"), "copy"));
  const changed = await phone.call("POST", "/api/key", {
    epoch: next.epoch,
    copyId: copy.json.copyId,
    rekeyProof: randomBytes(32).toString("base64url"),
    ...phone.signedChange({ epoch: next.epoch, key: next.key, removed: remove ?? null }),
    ...(remove === undefined ? {} : { remove }),
    wraps: others.map((other) => Phone.wrapFor({ phoneId: other.id, phoneKey: other.publicKey }, next)),
  });
  if (changed.status === 200) phone.household = next;
  return changed.status;
}

describe("the recovery code", () => {
  it("lets one new phone in, through the same join as an invite, and only once", async () => {
    await withServer(async (server) => {
      const { first } = await household(server);
      const made = await first.recoveryCode();
      assert.equal(made.answer.status, 200);
      assert.deepEqual((await recoveryStatus(first)).recovery?.madeBy, first.id);
      // It is not a phone: nothing lists it, and nothing is wrapped for it.
      assert.equal(((await first.call("GET", "/api/phones")).json.phones as unknown[]).length, 2);

      const replacement = new Phone(server.baseUrl);
      assert.equal((await replacement.recover(made.code, first.serverKey as Buffer)).status, 200);
      assert.deepEqual(replacement.household?.key, first.household?.key);
      assert.equal((await replacement.call("POST", "/api/sync", { since: 0, batches: [] })).status, 200);

      const again = await new Phone(server.baseUrl).recover(made.code, first.serverKey as Buffer);
      assert.equal(again.json.error, "invite-gone");
      const after = await recoveryStatus(first);
      assert.equal(after.recovery, null);
      // Every phone can see it was used, and by which phone.
      assert.equal(after.used?.by, replacement.id);
    });
  });

  it("ends at any key change, and at a removal by any route, but not when a phone leaves", async () => {
    await withServer(async (server) => {
      const { first, second } = await household(server);
      const third = new Phone(server.baseUrl);
      await third.join(await first.invite(), first.serverKey as Buffer);

      const kept = await first.recoveryCode();
      assert.equal((await third.call("POST", "/api/leave")).status, 200);
      assert.notEqual((await recoveryStatus(first)).recovery, null, "a phone leaving ended the code");
      assert.equal((await recoveryStatus(first)).ended, null);

      // Removing a phone without a key change, the route the app doesn't use.
      assert.equal((await first.call("POST", "/api/phones/remove", { phoneId: second.id })).status, 200);
      assert.equal((await recoveryStatus(first)).recovery, null);
      // Said, so a household with the code printed is told it stopped working.
      assert.notEqual((await recoveryStatus(first)).ended, null);
      assert.equal((await new Phone(server.baseUrl).recover(kept.code, first.serverKey as Buffer)).json.error, "invite-gone");

      // And a key change, whatever it is for.
      const ended = await first.recoveryCode();
      assert.equal((await recoveryStatus(first)).ended, null, "a new code still said the last one had ended");
      assert.equal(await changeKey(first, []), 200);
      assert.equal((await recoveryStatus(first)).recovery, null);
      assert.notEqual((await recoveryStatus(first)).ended, null);
      assert.equal((await new Phone(server.baseUrl).recover(ended.code, first.serverKey as Buffer)).json.error, "invite-gone");
    });
  });

  it("is shut for ten minutes by five wrong proofs, not thrown away", async () => {
    let now = Date.now();
    await withServer(
      async (server) => {
        const first = new Phone(server.baseUrl);
        first.clock = () => now;
        await first.claim(server.setupCode());
        const made = await first.recoveryCode();
        // Its id crosses the Wi-Fi when it's used. Someone who heard it can
        // try proofs, and can't make one.
        for (let attempt = 0; attempt < 5; attempt += 1) {
          const guess = new Phone(server.baseUrl);
          guess.clock = () => now;
          const answer = await guess.join({ inviteId: made.recoveryId, secret: randomBytes(16) }, first.serverKey as Buffer);
          assert.equal(answer.json.error, "bad-proof");
        }
        const replacement = new Phone(server.baseUrl);
        replacement.clock = () => now;
        assert.equal((await replacement.recover(made.code, first.serverKey as Buffer)).json.error, "recovery-shut");
        now += 10 * 60 * 1000 + 1000;
        assert.equal((await replacement.recover(made.code, first.serverKey as Buffer)).status, 200);
      },
      { clock: { now: () => now } },
    );
  });

  it("keeps one at a time, made under the key in force", async () => {
    await withServer(async (server) => {
      const { first } = await household(server);
      const household1 = first.household as NonNullable<typeof first.household>;
      first.household = { ...household1, epoch: household1.epoch + 1 };
      assert.equal((await first.recoveryCode()).answer.json.error, "key-changed");
      first.household = household1;
      assert.equal((await first.recoveryCode()).answer.status, 200);
      // A second would leave the first good beside it. The app changes the key first.
      assert.equal((await first.recoveryCode()).answer.json.error, "recovery-exists");
    });
  });

  it("holds neither the code nor anything that opens its packet", async () => {
    await withServer(async (server) => {
      const { first } = await household(server);
      const { code } = await first.recoveryCode();
      const everything = Buffer.concat(listFiles(server.dataDir).map((path) => readFileSync(path)));
      const { hkdf } = await import("../src/crypto.ts");
      assert.equal(everything.includes(code), false, "found the recovery code on the server");
      assert.equal(everything.includes(hkdf(code, "", "hc recovery packet v1")), false, "found the packet key on the server");
      assert.equal(everything.includes(first.household?.key as Buffer), false, "found the household key on the server");
    });
  });
});

describe("files", () => {
  it("stores a file in pieces, marks it whole, and gives each piece back as a download", async () => {
    await withServer(async (server) => {
      const { first, second } = await household(server);
      const fileId = randomBytes(16).toString("hex");
      const pieces = [randomBytes(1024), randomBytes(512)];
      for (const [index, piece] of pieces.entries()) {
        assert.equal((await first.call("PUT", `/api/files/${fileId}/${index}`, piece)).status, 200);
      }
      assert.equal((await first.call("POST", `/api/files/${fileId}`, { pieces: 3 })).status, 400);
      assert.equal((await first.call("POST", `/api/files/${fileId}`, { pieces: 2 })).status, 200);

      const status = await second.call("GET", `/api/files/${fileId}`);
      assert.equal(status.json.complete, true);
      const back = await second.call("GET", `/api/files/${fileId}/1`);
      assert.deepEqual(back.bytes, pieces[1]);
      assert.equal(back.headers.get("content-type"), "application/octet-stream");
      assert.equal(back.headers.get("content-disposition"), "attachment");

      await first.call("DELETE", `/api/files/${fileId}`);
      assert.equal((await second.call("GET", `/api/files/${fileId}`)).status, 404);
    });
  });

  it("refuses a file named by anything but 32 hex characters", async () => {
    await withServer(async (server) => {
      const { first } = await household(server);
      assert.equal((await first.call("PUT", "/api/files/..%2F..%2Fserver-key/0", randomBytes(8))).status, 404);
      assert.equal((await first.call("PUT", `/api/files/${"A".repeat(32)}/0`, randomBytes(8))).status, 404);
    });
  });
});

describe("what the server keeps", () => {
  it("survives a restart with the same key, phones and changes", async () => {
    const server = await startServer();
    const { first } = await household(server);
    await first.call("POST", "/api/sync", { since: 0, batches: [first.batchOf(["kept"])] });
    const key = (await first.hello()).serverKey;
    await server.stop();

    const again = await startServer({ dataDir: server.dataDir });
    try {
      const moved = Object.assign(Object.create(Object.getPrototypeOf(first)), first, { baseUrl: again.baseUrl }) as Phone;
      assert.equal((await moved.hello()).serverKey, key);
      const pulled = await moved.call("POST", "/api/sync", { since: 0, batches: [] });
      assert.equal((pulled.json.changes as unknown[]).length, 1);
    } finally {
      await again.close();
    }
  });

  it("holds nothing anyone could read: no name, no value, no file", async () => {
    await withServer(async (server) => {
      const { first, second } = await household(server);
      const secrets = ["Kitchen behind the boiler 4417", "Alarm code 7392-0018"];
      const fileBytes = Buffer.from("%PDF-1.7 electricity bill account 55512345");
      await first.call("POST", "/api/sync", { since: 0, batches: [first.batchOf(secrets)] });
      const fileKey = randomBytes(32);
      const fileId = randomBytes(16).toString("hex");
      await first.call("PUT", `/api/files/${fileId}/0`, seal(fileKey, fileBytes, `${fileId} 0 last`));
      await second.call("POST", "/api/sync", { since: 0, batches: [] });

      const everything = Buffer.concat(listFiles(server.dataDir).map((path) => readFileSync(path)));
      for (const secret of [...secrets, fileBytes.toString()]) {
        assert.equal(everything.includes(Buffer.from(secret)), false, `found "${secret}" on the server`);
      }
      assert.equal(everything.includes(first.household?.key as Buffer), false, "found the household key on the server");
    });
  });
});

async function uploadHouse(phone: Phone, contents: string, through = 0, schema = 41): Promise<string> {
  const bytes = seal(dataKey(phone.household as never), Buffer.from(contents), "copy");
  const uploaded = await phone.call("PUT", `/api/copy?epoch=${phone.household?.epoch}&schema=${schema}&through=${through}`, bytes);
  assert.equal(uploaded.status, 200);
  const activated = await phone.call("POST", "/api/copy/activate", { copyId: uploaded.json.copyId });
  assert.equal(activated.status, 200);
  return uploaded.json.copyId as string;
}

function listFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? listFiles(path) : [path];
  });
}

// The server keeps what the phones sign, as it
// came, and serves it back. It checks none of it: the phones do.
describe("signed key changes", () => {
  it("keeps each phone's signing key and how it came in, and lists them", async () => {
    await withServer(async (server) => {
      const { first, second } = await household(server);
      const phones = (await first.call("GET", "/api/phones")).json.phones as {
        phoneId: string;
        signingKey: string;
        door: Record<string, unknown> | null;
      }[];
      const listedFirst = phones.find((phone) => phone.phoneId === first.id);
      const listedSecond = phones.find((phone) => phone.phoneId === second.id);
      assert.equal(listedFirst?.signingKey, first.signing.publicKey.toString("base64url"));
      // The phone that set the server up came in by no door.
      assert.equal(listedFirst?.door, null);
      assert.equal(listedSecond?.signingKey, second.signing.publicKey.toString("base64url"));
      assert.deepEqual(Object.keys(listedSecond?.door ?? {}).sort(), ["arrival", "arrivalOwn", "by", "epoch", "id", "key", "vouch"]);
      assert.equal(listedSecond?.door?.by, first.id);
      assert.equal(listedSecond?.door?.epoch, 1);
    });
  });

  it("keeps a key change's statement as it was signed, and serves it with the wrap, the join and hello", async () => {
    await withServer(async (server) => {
      const { first, second } = await household(server);
      const hello = await first.hello();
      assert.equal(hello.keyChangedBy, null);
      assert.equal(hello.movedBy, null);

      const next = { id: first.household?.id as string, key: randomBytes(32), epoch: 2 };
      const copy = await first.call("PUT", "/api/copy?epoch=2&schema=41&through=0", seal(dataKey(next), Buffer.from("house"), "copy"));
      const signed = first.signedChange({ epoch: 2, key: next.key, roster: [first.entry(), second.entry()] });
      const changed = await first.call("POST", "/api/key", {
        epoch: 2,
        copyId: copy.json.copyId,
        rekeyProof: randomBytes(32).toString("base64url"),
        ...signed,
        wraps: [Phone.wrapFor({ phoneId: second.id, phoneKey: second.publicKey }, next)],
      });
      assert.equal(changed.status, 200);
      first.household = next;

      const wrap = await second.call("GET", "/api/key?epoch=2");
      assert.equal(wrap.json.statement, signed.statement);
      assert.equal(wrap.json.signature, signed.signature);
      assert.equal((await first.hello()).keyChangedBy, first.id);
      const joined = await new Phone(server.baseUrl).join(await first.invite(), first.serverKey as Buffer);
      const keyChanges = joined.json.keyChanges as { epoch: number; statement: string; signature: string; rekeyProof: string }[];
      assert.deepEqual(
        keyChanges.map((change) => [change.epoch, change.statement, change.signature]),
        [[2, signed.statement, signed.signature]],
      );
      assert.equal((joined.json.phones as unknown[]).length, 3);
    });
  });

  it("keeps a move's signed statement, and hello names the phone that moved the household there", async () => {
    await withServer(async (server) => {
      const mover = new Phone(server.baseUrl);
      const claimed = await mover.claim(server.setupCode(), "Mover", {
        householdId: randomBytes(16).toString("base64url"),
        epoch: 4,
        rekeyProof: randomBytes(32),
      });
      assert.equal(claimed.status, 200);
      const hello = await mover.hello();
      assert.equal(hello.movedBy, mover.id);
      assert.equal(hello.keyChangedBy, mover.id);
      const joined = await new Phone(server.baseUrl).join(await mover.invite(), mover.serverKey as Buffer);
      const [move] = joined.json.keyChanges as { epoch: number; statement: string }[];
      assert.equal(move?.epoch, 4);
      assert.equal((JSON.parse(move?.statement ?? "{}") as { kind: string }).kind, "move");
    });
  });

  it("refuses a claim, an invite, a join or a key change without what protocol 2 signs", async () => {
    await withServer(async (server) => {
      assert.equal((await new Phone(server.baseUrl).hello()).protocol, 2);
      const { first } = await household(server);
      // An invite with no vouch.
      const invite = await first.call("POST", "/api/invites", {
        inviteId: randomBytes(16).toString("base64url"),
        sealedVerifier: randomBytes(60).toString("base64url"),
        packet: randomBytes(60).toString("base64url"),
        expiresInMs: 60_000,
      });
      assert.equal(invite.status, 400);
      // A key change with no statement.
      const next = { id: first.household?.id as string, key: randomBytes(32), epoch: 2 };
      const copy = await first.call("PUT", "/api/copy?epoch=2&schema=41&through=0", seal(dataKey(next), Buffer.from("house"), "copy"));
      const unsigned = await first.call("POST", "/api/key", {
        epoch: 2,
        copyId: copy.json.copyId,
        rekeyProof: randomBytes(32).toString("base64url"),
        wraps: [],
      });
      assert.equal(unsigned.status, 400);
      assert.equal((await first.hello()).epoch, 1);
    });
  });

  it("adds the signing keys to a server folder made before them", () => {
    const dir = mkdtempSync(join(tmpdir(), "hc-old-folder-"));
    const old = new DatabaseSync(join(dir, "household.db"));
    old.exec(`CREATE TABLE phone (
      id TEXT PRIMARY KEY NOT NULL, public_key BLOB NOT NULL UNIQUE, name_blob BLOB NOT NULL,
      kind TEXT NOT NULL CHECK (kind IN ('phone', 'paper')), joined_at TEXT NOT NULL,
      last_seen_at TEXT, removed_at TEXT);
      CREATE TABLE invite (id TEXT PRIMARY KEY NOT NULL, verifier BLOB NOT NULL, packet BLOB NOT NULL,
      created_by TEXT NOT NULL, expires_at INTEGER NOT NULL, failures INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE rekey (epoch INTEGER PRIMARY KEY NOT NULL, proof BLOB NOT NULL);`);
    old.prepare("INSERT INTO phone (id, public_key, name_blob, kind, joined_at) VALUES ('p', x'01', x'02', 'phone', 'then')").run();
    old.prepare("INSERT INTO rekey (epoch, proof) VALUES (2, x'03')").run();
    old.close();
    const store = new Store(dir);
    assert.equal(store.findPhone("p")?.signing_key, null);
    assert.equal(store.findPhone("p")?.door, null);
    // A folder from before browsers were told apart lists its members as phones.
    assert.equal(store.findPhone("p")?.device, null);
    assert.equal(store.findRekey(2)?.statement, null);
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
});
