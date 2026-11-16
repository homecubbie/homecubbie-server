import { mkdtempSync, rmSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Household, type Clock } from "../src/household.ts";
import { createHouseholdServer } from "../src/http-server.ts";
import type { WebApp } from "../src/web-app.ts";

export interface Running {
  baseUrl: string;
  household: Household;
  dataDir: string;
  logged: string[];
  setupCode(): string;
  /** Stops the server and closes its database, keeping the folder. */
  stop(): Promise<void>;
  /** Stops it and deletes the folder. */
  close(): Promise<void>;
}

export async function startServer(
  options: { dataDir?: string; clock?: Clock; hostNames?: string[]; webApp?: WebApp } = {},
): Promise<Running> {
  const dataDir = options.dataDir ?? mkdtempSync(join(tmpdir(), "homecubbie-server-"));
  const logged: string[] = [];
  const household = new Household(dataDir, { clock: options.clock, log: { info: (line) => logged.push(line) } });
  const server = createHouseholdServer(household, { hostNames: options.hostNames, webApp: options.webApp });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const stop = () =>
    new Promise<void>((resolve) => {
      server.closeAllConnections();
      server.close(() => {
        household.close();
        resolve();
      });
    });
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    household,
    dataDir,
    logged,
    setupCode: () => {
      const code = household.setupCode();
      if (code === null) throw new Error("Already set up.");
      return code;
    },
    stop,
    close: async () => {
      await stop();
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
}
