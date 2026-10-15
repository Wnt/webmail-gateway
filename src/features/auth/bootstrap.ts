import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";
import { normalizeEmail, setGandiPassword, upsertAccount } from "../../core/accounts.js";
import type { AppContext, CliCommand } from "../../types.js";
import { audit } from "./audit.js";
import { createEnrollToken } from "./enroll.js";
import { SessionStore } from "./sessions.js";
import { TokenStore } from "./tokens.js";
import { deleteAllPasskeys } from "./webauthn.js";
import { createAuthState } from "./state.js";

export interface BootstrapIo {
  stdin: Readable & { isTTY?: boolean };
  stdout: Writable;
  stderr: Writable;
}

const USAGE = "usage: bootstrap <email> [--reset]\n  reads the mailbox password from the terminal (or stdin when piped)";

/** Exit codes: 0 ok, 1 error, 2 usage or not allowlisted, 3 password rejected by legacy-proxy. */
export async function runBootstrap(args: string[], ctx: AppContext, io: BootstrapIo, now: () => number = Date.now): Promise<number> {
  const reset = args.includes("--reset");
  const positional = args.filter((a) => !a.startsWith("--"));
  const unknown = args.filter((a) => a.startsWith("--") && a !== "--reset");
  if (positional.length !== 1 || unknown.length) {
    io.stderr.write(`${USAGE}\n`);
    return 2;
  }
  const email = normalizeEmail(positional[0]!);
  if (!ctx.config.allowedEmails.includes(email)) {
    io.stderr.write(`bootstrap: ${email} is not in ALLOWED_EMAILS\n`);
    return 2;
  }

  const password = await readPassword(io);
  if (!password) {
    io.stderr.write("bootstrap: empty password\n");
    return 2;
  }

  // The same probe core/legacy uses to re-login: legacy-proxy opens IMAP with
  // these credentials and creates its account. Nothing is stored before it passes.
  const basic = Buffer.from(`${email}:${password}`, "utf8").toString("base64");
  let status: number;
  try {
    const res = await ctx.fetch(`${ctx.config.legacyProxyUrl}/jmap/session`, {
      headers: { authorization: `Basic ${basic}` },
      signal: AbortSignal.timeout(30_000),
    });
    status = res.status;
    await res.body?.cancel().catch(() => {});
  } catch (err) {
    io.stderr.write(`bootstrap: legacy-proxy unreachable: ${(err as Error).message}\n`);
    return 1;
  }
  if (status === 401 || status === 403) {
    io.stderr.write("bootstrap: legacy-proxy rejected the password\n");
    return 3;
  }
  if (status < 200 || status >= 300) {
    io.stderr.write(`bootstrap: legacy-proxy answered ${status}\n`);
    return 1;
  }

  const account = await upsertAccount(ctx, { email, legacySlug: `${ctx.config.legacyProvider}:${email}` });
  await setGandiPassword(ctx, account.id, password);

  if (reset) {
    const s = createAuthState(ctx, now);
    const passkeys = await deleteAllPasskeys(s, account.id);
    const sessions = await new SessionStore(ctx, now).deleteAccount(account.id);
    const grants = await new TokenStore(ctx, now).revokeAccount(account.id, "bootstrap_reset");
    io.stdout.write(`reset: ${passkeys} passkey(s), ${sessions} session(s), ${grants} grant(s) revoked\n`);
  }

  const { token, expiresAt } = await createEnrollToken(ctx, account.id, now());
  await audit(ctx, { event: "bootstrap", accountId: account.id, details: { reset } }, now());
  io.stdout.write(`Enrollment link (valid until ${expiresAt.toISOString()}, single use):\n${ctx.config.publicBaseUrl}/auth/enroll/${token}\n`);
  return 0;
}

/** From the terminal without echo, or the whole of a piped stdin (one trailing newline trimmed). */
async function readPassword(io: BootstrapIo): Promise<string> {
  if (io.stdin.isTTY) {
    return new Promise((resolve) => {
      const rl = createInterface({ input: io.stdin, output: io.stderr, terminal: true });
      io.stderr.write("Mailbox password: ");
      // Echo is suppressed: readline's output hook writes nothing for the typed characters.
      (rl as unknown as { _writeToOutput: (s: string) => void })._writeToOutput = () => {};
      rl.question("", (answer) => {
        rl.close();
        io.stderr.write("\n");
        resolve(answer);
      });
    });
  }
  const chunks: Buffer[] = [];
  for await (const chunk of io.stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
}

export const bootstrapCommand: CliCommand = (args, ctx) =>
  runBootstrap(args, ctx, { stdin: process.stdin, stdout: process.stdout, stderr: process.stderr });
