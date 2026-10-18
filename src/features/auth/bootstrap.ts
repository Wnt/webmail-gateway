import type { Readable, Writable } from "node:stream";
import { StringDecoder } from "node:string_decoder";
import { normalizeEmail, upsertAccount } from "../../core/accounts.js";
import { getUpstream } from "../../core/upstream/index.js";
import type { AppContext, CliCommand } from "../../types.js";
import { audit } from "./audit.js";
import { createEnrollToken } from "./enroll.js";
import { resetAccountAuth } from "./generation.js";
import { createAuthState } from "./state.js";

export interface BootstrapIo {
  stdin: Readable & { isTTY?: boolean; setRawMode?: (mode: boolean) => unknown };
  stdout: Writable;
  stderr: Writable;
}

const USAGE =
  "usage: bootstrap <email> [--reset]\n" +
  "  reads the upstream credential from the terminal (or stdin when piped):\n" +
  "  UPSTREAM_KIND=legacy: the mailbox (Gandi) password; UPSTREAM_KIND=jmap: the upstream API token (or password with UPSTREAM_AUTH=basic)";

/** Exit codes: 0 ok, 1 error, 2 usage or not allowlisted, 3 credential rejected by the upstream or not this mailbox's, 130 cancelled at the prompt. */
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
  const secret = await readSecret(io, upstream.credentialPrompt, what);
  if (secret === null) {
    io.stderr.write("bootstrap: cancelled\n");
    return 130;
  }
  if (!secret) {
    io.stderr.write(`bootstrap: empty ${what}\n`);
    return 2;
  }

  // legacy: legacy-proxy opens IMAP with the password and creates its account
  // (the re-login probe). jmap: the upstream session must answer to the token
  // and be this mailbox. Nothing is stored before the check passes.
  const who = upstream.kind === "legacy" ? "legacy-proxy" : "the upstream";
  io.stderr.write(`bootstrap: checking the ${what} with ${who}...\n`);
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
    // Also ends earlier enrollment links, unused codes, pending ceremonies and
    // push subscriptions, and bumps the auth generation (see generation.ts).
    const { passkeys, sessions, grants } = await resetAccountAuth(createAuthState(ctx, now), account.id);
    io.stdout.write(`reset: ${passkeys} passkey(s), ${sessions} session(s), ${grants} grant(s) revoked\n`);
  }

  const { token, expiresAt } = await createEnrollToken(ctx, account.id, now());
  await audit(ctx, { event: "bootstrap", accountId: account.id, details: { reset } }, now());
  io.stdout.write(`Enrollment link (valid until ${expiresAt.toISOString()}, single use):\n${ctx.config.publicBaseUrl}/auth/enroll/${token}\n`);
  return 0;
}

/**
 * From the terminal without echo, or the whole of a piped stdin (one trailing
 * newline trimmed). null: cancelled at the prompt (Ctrl-C, or the terminal went
 * away before Enter). The secret is never written anywhere.
 */
export async function readSecret(io: BootstrapIo, prompt: string, what = "secret"): Promise<string | null> {
  if (io.stdin.isTTY) return readHidden(io, prompt);
  io.stderr.write(`bootstrap: reading the ${what} from stdin until end of input\n`);
  const chunks: Buffer[] = [];
  for await (const chunk of io.stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
}

/**
 * Reads one line from a terminal in raw mode, so the terminal echoes nothing,
 * and writes the prompt once to stderr. readline is not used: its prompt()
 * moves the cursor to column 0 and clears the line (ESC[1G ESC[0J), which
 * erased the prompt and left an empty line that looked like a hang.
 * Enter or Ctrl-D ends the input; Backspace and Ctrl-U edit it; Ctrl-C cancels;
 * escape sequences (arrow keys and the like) and other control characters are
 * dropped. Raw mode is switched off again however the read ends.
 */
function readHidden(io: BootstrapIo, prompt: string): Promise<string | null> {
  const { stdin, stderr } = io;
  if (typeof stdin.setRawMode !== "function") {
    // A terminal whose echo cannot be switched off would show the secret.
    stderr.write("bootstrap: cannot hide input on this terminal; pipe the secret on stdin instead\n");
    return Promise.resolve(null);
  }
  const setRawMode = stdin.setRawMode.bind(stdin);
  return new Promise((resolve) => {
    const decoder = new StringDecoder("utf8");
    let secret = "";
    let esc: 0 | 1 | 2 | 3 = 0; // 1: after ESC, 2: inside a CSI sequence (ESC [ ... final), 3: after ESC O
    let done = false;
    const finish = (value: string | null) => {
      if (done) return;
      done = true;
      stdin.off("data", onData);
      stdin.off("end", onEnd);
      stdin.off("close", onEnd);
      setRawMode(false);
      stdin.pause();
      stderr.write("\n");
      resolve(value);
    };
    const onEnd = () => finish(null);
    const onData = (chunk: Buffer | string) => {
      for (const ch of typeof chunk === "string" ? chunk : decoder.write(chunk)) {
        if (esc === 1) {
          esc = ch === "[" ? 2 : ch === "O" ? 3 : 0;
          continue;
        }
        if (esc === 2) {
          if (ch >= "@" && ch <= "~") esc = 0;
          continue;
        }
        if (esc === 3) {
          esc = 0;
          continue;
        }
        if (ch === "\r" || ch === "\n" || ch === "\u0004") return finish(secret);
        if (ch === "\u0003") return finish(null);
        if (ch === "\u007f" || ch === "\b") secret = Array.from(secret).slice(0, -1).join("");
        else if (ch === "\u0015") secret = "";
        else if (ch === "\u001b") esc = 1;
        else if (ch >= " ") secret += ch;
      }
    };
    setRawMode(true);
    stderr.write(`${prompt} (typing is not shown): `);
    stdin.on("data", onData);
    stdin.once("end", onEnd);
    stdin.once("close", onEnd);
    stdin.resume();
  });
}

export const bootstrapCommand: CliCommand = (args, ctx) =>
  runBootstrap(args, ctx, { stdin: process.stdin, stdout: process.stdout, stderr: process.stderr });
