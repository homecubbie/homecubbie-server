/**
 * HTTPS for a browser on a computer that isn't the server's: the household hands the server a certificate and key for a name it owns, and the server
 * also listens on port 5008 over HTTPS. The phones keep port 5007.
 *
 * `node:https`'s `createServer`, and nothing else from it: the server still
 * starts no connection of its own, and renewing a certificate is the
 * household's job or its proxy's, never this server's
 * (`__tests__/no-outgoing-calls.test.ts`).
 *
 * - **It reads the files again when they change,** so a renewed certificate
 *   is served from the next connection on, with no restart. Polled rather
 *   than watched: a renewal that swaps a symbolic link, as certbot's does,
 *   changes no file an event watcher is looking at.
 * - **It says the certificate's last day,** at start and at each change, so a
 *   household notices before browsers start warning.
 * - **No HSTS.** It would hold for the whole name on every port, and break
 *   other things on that computer.
 */
import { X509Certificate } from "node:crypto";
import { readFileSync, unwatchFile, watchFile } from "node:fs";
import { createServer, type Server } from "node:https";
import type { Household, Logger } from "./household.ts";
import { answerHomeOnly } from "./home-network.ts";
import { householdRequestListener, type ServerOptions } from "./http-server.ts";

/** The port a browser on another computer uses, beside the phones' 5007. */
export const HTTPS_PORT = 5008;

/** How often the certificate and key are looked at for a change. */
export const RELOAD_POLL_MS = 1000;

export interface CertificateFiles {
  certFile: string;
  keyFile: string;
}

/**
 * The certificate and key the household gave, from the environment: both, or
 * neither and no HTTPS listener at all, or "half", which `start.ts` refuses to
 * start with rather than guess.
 */
export function certificateFilesFrom(env: Record<string, string | undefined>): CertificateFiles | null | "half" {
  const certFile = env.HOMECUBBIE_HTTPS_CERT ?? "";
  const keyFile = env.HOMECUBBIE_HTTPS_KEY ?? "";
  if (certFile === "" && keyFile === "") return null;
  if (certFile === "" || keyFile === "") return "half";
  return { certFile, keyFile };
}

export interface HouseholdHttpsServer {
  server: Server;
  /** Stops watching the files. The caller closes `server`. */
  stopWatching(): void;
}

/**
 * Says when the certificate runs out, and whether it already has. Null when
 * the file isn't a certificate, which is said instead.
 */
export function certificateLastDay(cert: Buffer): Date | null {
  try {
    return new Date(new X509Certificate(cert).validTo);
  } catch {
    return null;
  }
}

function describeLastDay(cert: Buffer, now: number): string {
  const lastDay = certificateLastDay(cert);
  if (lastDay === null) return "the certificate file isn't a certificate this server can read";
  const day = lastDay.toISOString().slice(0, 10);
  return lastDay.getTime() < now ? `the certificate ran out on ${day}. Browsers will warn: renew it` : `the certificate runs out on ${day}`;
}

export function createHouseholdHttpsServer(
  household: Household,
  files: CertificateFiles,
  options: ServerOptions & { log: Logger },
): HouseholdHttpsServer {
  const read = () => ({ cert: readFileSync(files.certFile), key: readFileSync(files.keyFile) });
  const first = read();
  options.log.info(describeLastDay(first.cert, household.clock.now()));
  const server = createServer(first, householdRequestListener(household, options));
  answerHomeOnly(server, options);

  const reload = (current: { mtimeMs: number }, previous: { mtimeMs: number }) => {
    if (current.mtimeMs === previous.mtimeMs) return;
    try {
      const next = read();
      server.setSecureContext(next);
      options.log.info(`read the certificate again: ${describeLastDay(next.cert, household.clock.now())}`);
    } catch (error) {
      // Half-written, or a key that doesn't match the certificate yet: keep
      // serving the one in use, and take the pair at the next change.
      options.log.info(`couldn't use the changed certificate yet, so the one before stays: ${String(error)}`);
    }
  };
  watchFile(files.certFile, { interval: RELOAD_POLL_MS }, reload);
  watchFile(files.keyFile, { interval: RELOAD_POLL_MS }, reload);

  return {
    server,
    stopWatching: () => {
      unwatchFile(files.certFile, reload);
      unwatchFile(files.keyFile, reload);
    },
  };
}
