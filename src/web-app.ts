/**
 * The web app, as the household's own server serves it:
 * HomeCubbie's web build, the same app the phones run, at the address the
 * phones use.
 *
 * **Every file comes from a list read once at start.** The folder is walked
 * when the server starts and each file is held in memory under the path a
 * browser asks for. A request is looked up in that list and never turned into
 * a path on disk, so no request can name a file outside it, however it is
 * spelled. A route that takes an id is matched against the export's own page
 * names, with `[id].html` (or any `[name]`) standing for one part of the path.
 *
 * **The folder is made by `npm run export:server-web`** in the app, which
 * writes the export and a `homecubbie-web.json` saying which database version
 * it is (`scripts/export-server-web.mjs`). A folder without that file, or
 * without a page carrying the export's Content-Security-Policy, isn't served:
 * the server answers phones only and says why at start.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join } from "node:path";

/** What `scripts/export-server-web.mjs` writes beside the export. */
export const MANIFEST = "homecubbie-web.json";

const TYPES: Readonly<Record<string, string>> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".ttf": "font/ttf",
  ".otf": "font/otf",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".wasm": "application/wasm",
  ".txt": "text/plain; charset=utf-8",
};

/** Expo names every bundle and asset by a 32-character hash of its contents. */
const HASHED = /[0-9a-f]{32}/;

export interface WebFile {
  bytes: Buffer;
  type: string;
  /** Named by its contents' hash, so it can be kept for a year: a new build is a new name. */
  hashed: boolean;
}

/** A page whose path has a part that stands for any one part: `/home/thing/[id]`. */
interface PagePattern {
  parts: readonly (string | null)[];
  wildcards: number;
  file: WebFile;
}

export interface WebApp {
  /** The database version the build was made at, from its manifest. */
  schemaVersion: number;
  /** The export's own policy, as its pages carry it in a `<meta>`, with what only a header can say added. */
  contentSecurityPolicy: string;
  /** How many files the list holds, for the log. */
  fileCount: number;
  /** The file for a browser's path, already decoded, or null. */
  find(pathname: string): WebFile | null;
  /** The app's own page for an address it doesn't have. */
  notFound: WebFile | null;
}

export type WebAppLoad = { app: WebApp } | { missing: string };

/**
 * Reads the web build in `folder` into memory, once. Says what is missing
 * instead when there isn't a build there to serve.
 */
export function loadWebApp(folder: string): WebAppLoad {
  let manifest: { app?: unknown; schemaVersion?: unknown };
  try {
    manifest = JSON.parse(readFileSync(join(folder, MANIFEST), "utf8")) as typeof manifest;
  } catch {
    return { missing: `no web app in ${folder}` };
  }
  if (manifest.app !== "homecubbie" || !Number.isInteger(manifest.schemaVersion)) {
    return { missing: `${join(folder, MANIFEST)} isn't a HomeCubbie web build's` };
  }

  const files = new Map<string, WebFile>();
  for (const path of listFiles(folder, "")) {
    if (path === `/${MANIFEST}`) continue;
    const name = path.slice(path.lastIndexOf("/") + 1);
    files.set(path, {
      bytes: readFileSync(join(folder, path)),
      type: TYPES[extname(name).toLowerCase()] ?? "application/octet-stream",
      hashed: HASHED.test(name),
    });
  }

  const index = files.get("/index.html");
  const policy = index === undefined ? null : exportPolicy(index.bytes.toString("utf8"));
  if (policy === null) return { missing: `${folder} has no page carrying the export's Content-Security-Policy` };

  const patterns: PagePattern[] = [];
  for (const [path, file] of files) {
    if (!path.endsWith(".html")) continue;
    const parts = path.slice(1, -".html".length).split("/").map((part) => (/^\[[^\]/]+\]$/.test(part) ? null : part));
    const wildcards = parts.filter((part) => part === null).length;
    if (wildcards > 0) patterns.push({ parts, wildcards, file });
  }
  // The most literal page wins: `/records/year/[year]` before anything looser.
  patterns.sort((a, b) => a.wildcards - b.wildcards);

  return {
    app: {
      schemaVersion: manifest.schemaVersion as number,
      contentSecurityPolicy: `${policy}; frame-ancestors 'none'`,
      fileCount: files.size,
      notFound: files.get("/+not-found.html") ?? null,
      find(pathname) {
        const exact = pathname.endsWith("/") ? files.get(`${pathname}index.html`) : files.get(pathname);
        if (exact !== undefined) return exact;
        const page = files.get(`${pathname}.html`) ?? files.get(`${pathname}/index.html`);
        if (page !== undefined) return page;
        const asked = pathname.slice(1).split("/");
        const match = patterns.find(
          (pattern) =>
            pattern.parts.length === asked.length &&
            pattern.parts.every((part, index) => part === null ? (asked[index] ?? "") !== "" : part === asked[index]),
        );
        return match?.file ?? null;
      },
    },
  };
}

/** Every file under `folder`, as the path a browser asks for. Names starting with a dot are left out. */
function listFiles(folder: string, under: string): string[] {
  const found: string[] = [];
  for (const name of readdirSync(join(folder, under)).sort()) {
    if (name.startsWith(".")) continue;
    const path = `${under}/${name}`;
    const stat = statSync(join(folder, path));
    if (stat.isDirectory()) found.push(...listFiles(folder, path));
    else if (stat.isFile()) found.push(path);
  }
  return found;
}

/**
 * The policy the export writes into its pages' `<meta>` (`src/app/+html.tsx`),
 * read back from the page so the header is always the build's own and never a
 * second copy to keep in step. Null when there isn't one, or when it holds
 * anything that couldn't be a header.
 */
export function exportPolicy(page: string): string | null {
  const meta = /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"/i.exec(page);
  if (meta === null) return null;
  const policy = (meta[1] as string)
    .replace(/&#x27;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, "&");
  return /^[\x20-\x7e]+$/.test(policy) && policy.includes("default-src") ? policy : null;
}
