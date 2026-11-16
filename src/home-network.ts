/**
 * Which addresses the server answers: this computer,
 * and the address ranges a home network uses. Started with
 * `HOMECUBBIE_ALLOW_ANY_ADDRESS=1`, it answers any.
 *
 * It listens on every network its computer is on, because it can't know
 * which one is home. Most home routers stop strangers on the internet
 * reaching it, but not all, above all for IPv6, where a computer's own
 * address is often public. The Mac's own firewall is off by default. So a
 * connection from any other address is closed before a byte of it is read:
 * the internet can't reach the server even where a router would let it.
 *
 * What it doesn't stop:
 * - Another network that uses the same ranges, a café's Wi-Fi say. That stays
 *   open in this version, and the README tells a laptop's household to stop
 *   the server when it leaves home.
 * - Anything behind Docker's port mapping. A published port (`-p`) hands its
 *   IPv6 connections to the container from Docker's own bridge, a private
 *   address, so this check would pass them. That's why every guide starts
 *   the container on the host's network (`--network host`), where it sees
 *   the real address.
 */
import { isIP, type Server, type Socket } from "node:net";

/** Every address, or only home ones, and where a refusal is said. */
export interface AddressRule {
  anyAddress?: boolean;
  log?: { info(line: string): void };
}

/**
 * True for this computer and the private ranges, false for anything else:
 * - IPv4: `127/8`, `10/8`, `172.16/12`, `192.168/16`, link-local `169.254/16`,
 *   and `100.64/10`, which is never routed on the internet (Tailscale's
 *   addresses are in it, for reaching home from away).
 * - IPv6: `::1`, link-local `fe80::/10`, unique-local `fc00::/7` (Tailscale's
 *   too), and an IPv4 address written as IPv6 by the IPv4 rules.
 */
export function isHomeAddress(address: string | undefined): boolean {
  if (address === undefined) return false;
  const bare = address.replace(/%.*$/, "");
  const kind = isIP(bare);
  if (kind === 4) return homeIpv4(ipv4Parts(bare));
  if (kind !== 6) return false;
  const groups = ipv6Groups(bare);
  const group = (at: number): number => groups[at] ?? 0;
  const mapped = groups.slice(0, 5).every((value) => value === 0) && group(5) === 0xffff;
  if (mapped) return homeIpv4([group(6) >> 8, group(6) & 0xff, group(7) >> 8, group(7) & 0xff]);
  if (groups.slice(0, 7).every((value) => value === 0) && group(7) === 1) return true;
  return (group(0) & 0xffc0) === 0xfe80 || (group(0) & 0xfe00) === 0xfc00;
}

/**
 * Closes, before anything is read, every connection from outside the home
 * ranges. It goes first among the server's connection listeners, so the
 * HTTP or TLS side never sees one. The first refusal is logged, with how to
 * allow any address; the ones after aren't, so a scan can't fill the log.
 */
export function answerHomeOnly(server: Server, rule: AddressRule): void {
  if (rule.anyAddress === true) return;
  let told = false;
  server.prependListener("connection", function refuseOutsideHome(socket: Socket) {
    if (isHomeAddress(socket.remoteAddress)) return;
    socket.destroy();
    if (told) return;
    told = true;
    rule.log?.info(
      `refused a connection from ${socket.remoteAddress ?? "an unknown address"}, which isn't this computer or a home network's address. ` +
        "To answer any address, start the server with HOMECUBBIE_ALLOW_ANY_ADDRESS=1.",
    );
  });
}

type Ipv4 = [number, number, number, number];

function ipv4Parts(address: string): Ipv4 {
  const [a = 0, b = 0, c = 0, d = 0] = address.split(".").map(Number);
  return [a, b, c, d];
}

function homeIpv4([a, b]: Ipv4): boolean {
  return (
    a === 127 ||
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

/** An IPv6 address, already checked by `isIP`, as its eight 16-bit groups. */
function ipv6Groups(address: string): number[] {
  let text = address;
  let tail: number[] = [];
  const dotted = /(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (dotted !== null) {
    const quad = dotted[1] ?? "";
    const [a, b, c, d] = ipv4Parts(quad);
    tail = [(a << 8) | b, (c << 8) | d];
    text = text.slice(0, text.length - quad.length);
    if (!text.endsWith("::")) text = text.slice(0, -1);
  }
  const groupsOf = (part: string): number[] => (part === "" ? [] : part.split(":").map((group) => parseInt(group, 16)));
  const gap = text.indexOf("::");
  if (gap === -1) return [...groupsOf(text), ...tail];
  const head = groupsOf(text.slice(0, gap));
  const rest = groupsOf(text.slice(gap + 2));
  const zeros = new Array<number>(8 - tail.length - head.length - rest.length).fill(0);
  return [...head, ...zeros, ...rest, ...tail];
}
