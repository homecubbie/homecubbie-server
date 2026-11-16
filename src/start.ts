/**
 * Starts the household server. `main.ts` loads this once Node's SQLite
 * warning is dropped, because importing it loads `node:sqlite`.
 *
 *   HOMECUBBIE_DATA   the folder that holds everything (default ./homecubbie-data)
 *   HOMECUBBIE_PORT   the port (default 5007)
 *   HOMECUBBIE_HOSTS  comma-separated names it may be reached by, besides IP addresses
 *   HOMECUBBIE_ALLOW_ANY_ADDRESS
 *                     1 to answer any address. Otherwise it answers only this computer
 *                     and the home network's address ranges (`home-network.ts`).
 *   HOMECUBBIE_HTTPS_CERT, HOMECUBBIE_HTTPS_KEY
 *                     a certificate and key for a name in HOMECUBBIE_HOSTS: given both,
 *                     it also listens over HTTPS on port 5008, for a browser on another
 *                     computer. The phones keep the plain port.
 *
 * It listens on the home network and makes no outgoing connection of any kind:
 * no update check, no telemetry, no time server. `__tests__/no-outgoing-calls.test.ts`
 * keeps it that way.
 *
 * It serves the web app from the `web` folder beside `src` and `dist`, when the
 * package was made with one (`npm run export:server-web` in the app).
 */
import { networkInterfaces } from "node:os";
import { join, resolve } from "node:path";
import { Household } from "./household.ts";
import { createHouseholdServer } from "./http-server.ts";
import { certificateFilesFrom, createHouseholdHttpsServer, HTTPS_PORT, type HouseholdHttpsServer } from "./https-listener.ts";
import { loadWebApp } from "./web-app.ts";

const dataDir = resolve(process.env.HOMECUBBIE_DATA ?? "homecubbie-data");
const port = Number(process.env.HOMECUBBIE_PORT ?? "5007");
const hostNames = (process.env.HOMECUBBIE_HOSTS ?? "")
  .split(",")
  .map((name) => name.trim())
  .filter((name) => name.length > 0);

const log = { info: (line: string) => console.log(`homecubbie-server: ${line}`) };
const certificate = certificateFilesFrom(process.env);
if (certificate === "half") {
  console.error("homecubbie-server: HTTPS needs both HOMECUBBIE_HTTPS_CERT and HOMECUBBIE_HTTPS_KEY, or neither.");
  process.exit(1);
}

const household = new Household(dataDir, { log });
const web = loadWebApp(join(import.meta.dirname, "..", "web"));
const options = {
  hostNames,
  webApp: "app" in web ? web.app : null,
  anyAddress: process.env.HOMECUBBIE_ALLOW_ANY_ADDRESS === "1",
  log,
};
const server = createHouseholdServer(household, options);
const secure: HouseholdHttpsServer | null =
  certificate === null ? null : createHouseholdHttpsServer(household, certificate, { ...options, log });
secure?.server.listen(HTTPS_PORT, () => {
  for (const name of hostNames) log.info(`listening over HTTPS at https://${name}:${HTTPS_PORT}`);
  if (hostNames.length === 0) log.info(`listening over HTTPS on port ${HTTPS_PORT}. Put the certificate's name in HOMECUBBIE_HOSTS.`);
});

server.listen(port, () => {
  log.info(`keeping the household's data in ${dataDir}`);
  if (options.anyAddress) log.info("answering any address (HOMECUBBIE_ALLOW_ANY_ADDRESS=1).");
  for (const address of homeAddresses()) log.info(`listening at http://${address}:${port}`);
  if ("app" in web) {
    log.info(`the web app, for database version ${web.app.schemaVersion}, is at http://localhost:${port} on this computer.`);
    log.info("On another computer it needs HTTPS: see the server's README.");
  } else {
    log.info(`${web.missing}, so this server answers phones only.`);
  }
  if (household.isSetUp()) {
    log.info("set up. Phones join with an invite from a phone that has already joined.");
  } else {
    log.info("not set up yet. In HomeCubbie, go to Settings › Sharing › Share this house, and type:");
    household.printSetupCode();
    log.info("Nobody from HomeCubbie will ever ask you for this code.");
  }
});

function shutdown(): void {
  secure?.stopWatching();
  secure?.server.close();
  server.close(() => {
    household.close();
    process.exit(0);
  });
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

/**
 * The private IPv4 addresses this computer has. In a container on the host's
 * network they're the computer's own; behind Docker's bridge they would
 * be the container's, which is why the setup guide also names the computer's
 * address itself.
 */
function homeAddresses(): string[] {
  const found: string[] = [];
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === "IPv4" && !entry.internal) found.push(entry.address);
    }
  }
  return found.length > 0 ? found : ["localhost"];
}
