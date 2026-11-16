# HomeCubbie household server

A small program a household runs on a computer that's always on at home, so
everyone's phones see the same house.

- **It can't read the house.** Every change, copy, file and phone name arrives
  encrypted on the phone, under a key the server never holds. **One exception: a browser.** A
  browser that joins runs the web app this server serves it, so someone who
  takes over this computer could change that page, and read the house the
  next time the browser opens it. Phones aren't exposed to this, because
  their app comes from the store.
- **It never contacts anyone.** No update check, no telemetry, no time server.
  `__tests__/no-outgoing-calls.test.ts` fails the build if that changes.
- **It depends on nothing outside Node.** No `npm install`, nothing to trust but
  Node itself. The same test fails if a dependency is added.
- **It isn't ours.** It runs on the household's computer, and nothing about it
  is known to HomeCubbie.

## Getting it

It's published in three places, none of them run by HomeCubbie. The app's own
guide, Settings › Sharing › How to set up a server, gives the same commands.

- **npm**, for a Mac or a PC with Node 22.18 or later:

  ```sh
  npx homecubbie-server@0.1.2
  ```

- **GitHub's container registry**, for a NAS, a Raspberry Pi, or another Linux
  computer with Docker. The image is built for amd64 and arm64:

  ```sh
  docker run -d --name homecubbie --restart unless-stopped --network host -v homecubbie:/data ghcr.io/homecubbie/homecubbie-server:0.1.2
  ```

- **The code**, at <https://github.com/homecubbie/homecubbie-server>. It's
  copied there from the app's own repository at each server release.

It is source available, not open source: the PolyForm Noncommercial License
1.0.0, in `LICENSE`. The licence's own text says what it allows.

## Running it from the source

Node 22.18 or later, or Docker.

```sh
# From this folder, with Node:
npm start

# With Docker:
docker build -t homecubbie-server .
docker run -d --name homecubbie --restart unless-stopped --network host -v homecubbie:/data homecubbie-server
```

| Setting | Default | |
|---|---|---|
| `HOMECUBBIE_DATA` | `./homecubbie-data` (`/data` in Docker) | the folder that holds everything |
| `HOMECUBBIE_PORT` | `5007` | |
| `HOMECUBBIE_HOSTS` | none | comma-separated names it may be reached by, such as `mac-mini.local`. It always answers to IP addresses and `localhost` |
| `HOMECUBBIE_HTTPS_CERT`, `HOMECUBBIE_HTTPS_KEY` | none | a certificate and key: given both, it also listens over HTTPS on port 5008 (below) |
| `HOMECUBBIE_ALLOW_ANY_ADDRESS` | off | `1` to answer any address. Otherwise it closes a connection from anything but this computer and a home network's address ranges: `10.x`, `172.16`–`172.31`, `192.168.x`, link-local, `100.64/10` (Tailscale's), and IPv6's private and link-local ranges |

**It answers only the home network, even if a router would let the internet
in.** A computer's IPv6 address is often public, and not every router blocks
strangers from it. A café's Wi-Fi uses home ranges too, so stop the server
when its laptop leaves home.

**In Docker, run it on the host's network** (`--network host`, or "host" in a
NAS's container app), never behind a published port. Docker publishes `-p` on
the computer's IPv6 addresses too, and hands those connections to the
container from its own bridge, a private address, so the server can't tell a
stranger from a phone at home. On the host's network it sees the real address.
Host networking is for Linux: a NAS or a Pi. On a Mac or a PC, run it with
Node instead.

## The web app

The server also serves HomeCubbie itself, for a laptop's browser.

- **On the server's own computer,** open `http://localhost:5007`. There is
  nothing to set up: browsers trust `localhost`, and nothing sent to it crosses
  the Wi-Fi. `http://127.0.0.1:5007` is sent to `localhost`, so the computer
  joins once, not twice.
- **On any other computer it needs HTTPS.** A browser won't run the web app
  from a plain `http://` address on the Wi-Fi, and it wouldn't be safe if it
  did: someone on the Wi-Fi could swap the page. The household supplies it
  by one of the two ways below.
- **A browser joins like a phone:** with an invite code typed from a phone that
  has already joined.

The web app is the files in `web/`, beside `src/`. They are written from the
app's own folder by `npm run export:server-web`, which runs when the package
is packed, and must be there before `docker build`. The npm package and the
image carry them; the public repository doesn't, because they're built from
the app's code. Without `web/`, the server
answers phones only, and says so when it starts. It reads the folder once, at
start, and serves only the files it found there: a request is looked up in that
list, never turned into a path on disk.

### HTTPS for another computer

**A reverse proxy in front of the server,** which holds the certificate.
`tailscale serve` is one: on the server's computer, with Tailscale set up, it
gives the server an https name inside the household's own private network and
makes the certificate itself.

```sh
tailscale serve 5007
```

- Put the name the browser uses in `HOMECUBBIE_HOSTS`, and start the server
  again.
- Serve it at the root of a name, never under a path: every request's proof
  covers its path.
- Pass on the name the browser used. nginx sends its own address unless
  told otherwise (its default is `proxy_set_header Host $proxy_host;`), and
  the server then takes the page for one asked of it at `127.0.0.1`, which it
  sends to `localhost`: the browser's own computer, not this one. Set
  `proxy_set_header Host $host;`.
- Raise the proxy's upload limit. nginx allows 1 MB unless told otherwise
  (`client_max_body_size`), and a full copy of a house is far more:
  `client_max_body_size 300m;`.
- A private network such as Tailscale also makes the server reachable away
  from home. That is the household's own choice.

**A certificate and key the server is given,** for a household that has one
for a name it owns:

| Setting | |
|---|---|
| `HOMECUBBIE_HTTPS_CERT` | the certificate file, PEM |
| `HOMECUBBIE_HTTPS_KEY` | its private key, PEM |

Given both, the server also listens over HTTPS on port 5008; the phones keep
5007. Given one without the other, it doesn't start. It says the certificate's
last day when it starts, reads both files again when they change (a renewal
needs no restart), and sends no HSTS, which would hold for the name on every
port and break other things on that computer. Put the name in
`HOMECUBBIE_HOSTS`. With Docker, mount the files and add `-p 5008:5008`.

**Never:**

- forward a router port to reach it from outside;
- click through a certificate warning. Someone on the Wi-Fi can show the same
  warning. Install the certificate's authority on the computer instead;
- make a certificate authority of your own for this. Whoever has its root key
  can pose as any website to every computer that trusts it. Whoever makes one
  anyway keeps that key off the server's computer.

**Before retiring the server,** sign out of HomeCubbie in each browser, so
nothing that answers at that address later can read what the browser kept.

## Setting it up

The first time it starts, the server prints a **setup code** in its own log:
the terminal it was started from, or `docker logs homecubbie`, or the Logs tab
in Docker Desktop. The code is never shown over the network.

In HomeCubbie on the phone that has the house, go to Settings › Sharing ›
Share this house, and type the server's address and the code. That phone takes
the server, and the code stops working. Five wrong codes print a new one.

Other phones join with an invite from a phone that has already joined. There is
no password.

On the host's network, the address the server prints is the computer's own.
If it prints one starting `172.`, the container isn't on the host's network:
start it again with `--network host`.

## Keeping it safe

- **Never forward a router port to it, and never put it on a public address.**
  It's meant to be reached on the home Wi-Fi only. Reaching it from away, over
  a private network, is planned for later.
- **Back up the data folder.** Stop the server and copy the folder, or the
  Docker volume. The phones notice a restored folder that is missing changes,
  and "Reset sharing from this phone", on the phone whose house is right,
  puts it back.
- **The folder holds the server's private key** (`server-key`). Someone who
  copies it could pose as the server, or refuse and delete data. They still
  couldn't read anything, or add a change any phone would accept.

## Starting again

Stop the server and delete its data folder. It makes a new key and a new setup
code on the next start, and the phone that has the house sets it up again.

A folder set up before every key change was signed (protocol 2) has phones no member can trace. Start again in a new
folder: sharing hadn't shipped before it.

## Moving to a new server

When the server's computer dies or its folder is lost, start a new server in a
new folder, and on the phone that synced last use Settings › Sharing › Move to
a new server, with the new server's setup code. The household keeps its id and takes a new key,
and every other phone joins the new server again with an invite.

- **Delete the old folder, and never start the old server again.** Phones
  that haven't joined the new one would carry on with the old one, and lose
  what they did there when they join the new one.
- **Destroy the old recovery code,** printed or saved. The phone that moved
  the household makes a new one. A phone that held the household's key
  refuses a server no member it knew moved the household to, but the
  old server started again with the old code would still take a phone that
  never heard of the move.
- **Clear the site's data in any browser that used the old server**, in the
  browser's own settings for its address. Its page no longer loads, so its
  Sign out can't run, and what it stored stays until then.

## What it keeps

`household.db`, plus `copies/` and `files/`, all in the data folder:

| | In clear | Encrypted on the phone |
|---|---|---|
| Phones | a random id, public key, signing key, the door it came in by with its maker's vouch and its arrival's signatures, when joined and last seen, whether removed | the phone's name |
| Key changes | epoch, which phone made it, its proof, and its statement as signed: the new key's hash, its kind, the phone it removed, and the roster's public keys | the new key, wrapped for each phone |
| Changes | arrival number, which phone, its batch number, key epoch, schema version | the change itself |
| Full copies | key epoch, schema version, which change it runs to, size | the house |
| Files | a random id, how many pieces | every piece |
| Invites | a random id, expiry | the household key, sealed under the invite's secret |

## Its tests

```sh
npm run typecheck
npm test
```

Both run in the app's `npm run verify` as `test:server`. The tests start real
servers on a spare port and talk to them with stand-in phones
(`__tests__/phone.ts`), which implement the phone's half of the protocol with
`node:crypto`. The app's own client must agree with that file byte for byte.
