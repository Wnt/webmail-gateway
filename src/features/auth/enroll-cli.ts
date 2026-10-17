import type { Writable } from "node:stream";
import { getAccountByEmail, normalizeEmail } from "../../core/accounts.js";
import type { AppContext, CliCommand } from "../../types.js";
import { audit } from "./audit.js";
import { createEnrollToken, TEMP_PASSKEY_DEFAULT_TTL_MS, TEMP_PASSKEY_MAX_TTL_MS, TEMP_PASSKEY_MIN_TTL_MS } from "./enroll.js";
import { passkeyName } from "./webauthn.js";

const USAGE =
  "usage: enroll <email> [--ttl <duration>] [--label <name>] [--json]\n" +
  "  mints a single-use enrollment link (valid 15 min) for a TEMPORARY passkey of an existing account:\n" +
  "  the passkey stops working <duration> after it is created (default 4h, 1m to 24h; e.g. 90m, 4h, 3600s),\n" +
  "  and its sessions cannot manage passkeys. --label names the passkey (1-64 characters).\n" +
  "  stdout: only the link, or with --json one line {url, linkExpiresAt, passkeyTtlSeconds, label}; status goes to stderr.";

/** `4h`, `90m`, `3600s` or `3600` (seconds) to milliseconds; null if malformed. */
export function parseDuration(raw: string): number | null {
  const m = /^(\d{1,6})([smh]?)$/.exec(raw.trim());
  if (!m) return null;
  return Number(m[1]) * { "": 1000, s: 1000, m: 60_000, h: 3600_000 }[m[2] as "" | "s" | "m" | "h"];
}

export interface EnrollIo {
  stdout: Writable;
  stderr: Writable;
}

/** Exit codes: 0 ok, 2 usage, bad TTL, not allowlisted or no such account. The link goes to stdout only, never to a log. */
export async function runEnroll(args: string[], ctx: AppContext, io: EnrollIo, now: () => number = Date.now): Promise<number> {
  const positional: string[] = [];
  let ttlMs = TEMP_PASSKEY_DEFAULT_TTL_MS;
  let label: string | null = null;
  let json = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--json") json = true;
    else if (a === "--ttl" || a === "--label") {
      const v = args[++i];
      if (v === undefined) return usage(io);
      if (a === "--ttl") {
        const d = parseDuration(v);
        if (d === null) return usage(io, `bad --ttl ${JSON.stringify(v)}`);
        ttlMs = d;
      } else {
        label = passkeyName(v, "");
        if (!label) return usage(io, "empty --label");
      }
    } else if (a.startsWith("--")) return usage(io, `unknown option ${a}`);
    else positional.push(a);
  }
  if (positional.length !== 1) return usage(io);
  if (ttlMs < TEMP_PASSKEY_MIN_TTL_MS || ttlMs > TEMP_PASSKEY_MAX_TTL_MS) {
    return usage(io, `--ttl must be between ${TEMP_PASSKEY_MIN_TTL_MS / 60_000}m and ${TEMP_PASSKEY_MAX_TTL_MS / 3600_000}h`);
  }
  const email = normalizeEmail(positional[0]!);
  if (!ctx.config.allowedEmails.includes(email)) {
    io.stderr.write(`enroll: ${email} is not in ALLOWED_EMAILS\n`);
    return 2;
  }
  const account = await getAccountByEmail(ctx, email);
  if (!account) {
    io.stderr.write(`enroll: no account for ${email} (run bootstrap first)\n`);
    return 2;
  }
  const t = now();
  const { token, expiresAt } = await createEnrollToken(ctx, account.id, t, { ttlMs, label });
  await audit(ctx, { event: "enroll.temporary", accountId: account.id, details: { ttlSeconds: ttlMs / 1000, label } }, t);
  const url = `${ctx.config.publicBaseUrl}/auth/enroll/${token}`;
  io.stderr.write(
    `enroll: single-use link for a temporary passkey (lives ${ttlMs / 1000} s from creation), valid until ${expiresAt.toISOString()}\n`,
  );
  io.stdout.write(
    json
      ? `${JSON.stringify({ url, linkExpiresAt: expiresAt.toISOString(), passkeyTtlSeconds: ttlMs / 1000, label })}\n`
      : `${url}\n`,
  );
  return 0;
}

function usage(io: EnrollIo, why?: string): number {
  io.stderr.write(`${why ? `enroll: ${why}\n` : ""}${USAGE}\n`);
  return 2;
}

export const enrollCommand: CliCommand = (args, ctx) => runEnroll(args, ctx, { stdout: process.stdout, stderr: process.stderr });
