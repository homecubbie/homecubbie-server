#!/usr/bin/env node
/**
 * `homecubbie-server`: starts the household server (`start.ts`).
 *
 * Node's warning about `node:sqlite` is dropped first, and only then is the
 * server loaded, because loading it loads SQLite (`quiet-warnings.ts`).
 * Every other warning still prints.
 */
import { withoutSqliteWarning } from "./quiet-warnings.ts";

process.emitWarning = withoutSqliteWarning(process.emitWarning);
await import("./start.ts");
