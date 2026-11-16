/**
 * Drops Node's one warning about `node:sqlite` and passes every other warning
 * on.
 *
 * Node prints "ExperimentalWarning: SQLite is an experimental feature and
 * might change at any time" when `node:sqlite` loads. It's the first thing a
 * household would read from `npx homecubbie-server`, and it says nothing about
 * the server. The Dockerfile and the scripts pass
 * `--disable-warning=ExperimentalWarning`, but the npm package's `bin` starts
 * from a `#!/usr/bin/env node` line, which can't carry a flag on every
 * platform. So `main.ts` puts this in front of `process.emitWarning`, which
 * Node's own experimental warnings go through, before it loads anything that
 * loads SQLite.
 */

type EmitWarning = typeof process.emitWarning;

/** True for the SQLite warning and nothing else. */
export function isSqliteExperimentalWarning(warning: string | Error, typeOrOptions?: unknown): boolean {
  const text = typeof warning === "string" ? warning : warning.message;
  const type =
    typeof typeOrOptions === "string"
      ? typeOrOptions
      : typeof typeOrOptions === "object" && typeOrOptions !== null && "type" in typeOrOptions
        ? String(typeOrOptions.type)
        : warning instanceof Error
          ? warning.name
          : "Warning";
  return type === "ExperimentalWarning" && /\bSQLite\b/.test(text);
}

/** `emit`, without the SQLite warning. */
export function withoutSqliteWarning(emit: EmitWarning): EmitWarning {
  return function emitWarning(this: unknown, warning: string | Error, ...rest: unknown[]): void {
    if (isSqliteExperimentalWarning(warning, rest[0])) return;
    (emit as (warning: string | Error, ...rest: unknown[]) => void).call(process, warning, ...rest);
  } as EmitWarning;
}
