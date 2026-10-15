import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";
import { normalizeEmail, upsertAccount } from "../../core/accounts.js";
import { getUpstream } from "../../core/upstream/index.js";
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

const USAGE =
  "usage: bootstrap <email> [--reset]\n" +
  "  reads the upstream credential from the terminal (or stdin when piped):\n" +
  "  UPSTREAM_KIND=legacy: the mailbox (Gandi) password; UPSTREAM_KIND=jmap: the upstream API token (or password with UPSTREAM_AUTH=basic)";

/** Exit codes: 0 ok, 1 error, 2 usage or not allowlisted, 3 credential rejected by the upstream or not this mailbox's. */
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

  const upstream = getUpstream(ctx);
  const what = upstream.credentialPrompt.endsWith("token") ? "API token" : "password";
  const secret = await readSecret(io, upstream.credentialPrompt);
  if (!secret) {
    io.stderr.write(`bootstrap: empty ${what}\n`);
    return 2;
  }

  // legacy: legacy-proxy opens IMAP with the password and creates its account
  // (the re-login probe). jmap: the upstream session must answer to the token
  // and be this mailbox. Nothing is stored before the check passes.
  const who = upstream.kind === "legacy" ? "legacy-proxy" : "the upstream";
  const v = await upstream.verifyCredential(email, secret);
  if (!v.ok) {
    if (v.reason === "rejected") io.stderr.write(`bootstrap: ${who} rejected the ${what}\n`);
    else if (v.reason === "mismatch") io.stderr.write(`bootstrap: the ${what} is not ${email}'s mailbox: ${v.detail ?? ""}\n`);
    else if (v.reason === "unreachable") io.stderr.write(`bootstrap: ${who} unreachable: ${v.detail ?? ""}\n`);
    else io.stderr.write(`bootstrap: ${v.detail ?? `${who} failed`}\n`);
    return v.reason === "rejected" || v.reason === "mismatch" ? 3 : 1;
  }

  const account = await upsertAccount(ctx, { email, legacySlug: `${ctx.config.legacyProvider}:${email}` });
  await upstream.storeCredential(account, secret);

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
async function readSecret(io: BootstrapIo, prompt: string): Promise<string> {
  if (io.stdin.isTTY) {
    return new Promise((resolve) => {
      const rl = createInterface({ input: io.stdin, output: io.stderr, terminal: true });
      io.stderr.write(`${prompt}: `);
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
