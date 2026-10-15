import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import type { AuthState } from "./state.js";
import { asBuffer, b64url } from "./util.js";

export const CHALLENGE_TTL_MS = 120_000;
/** Ed25519, ES256, RS256: what passkey providers ship today. Pinned so the library does not probe the runtime for PQC algorithms. */
export const SUPPORTED_ALGORITHMS = [-8, -7, -257];
export type ChallengeKind = "login" | "enroll" | "add";

export interface Passkey {
  /** Raw credential id. */
  id: Buffer;
  accountId: string;
  publicKey: Buffer;
  counter: number;
  transports: string[];
  aaguid: string | null;
  backedUp: boolean;
  name: string;
  createdAt: Date;
  lastUsedAt: Date | null;
}

interface Row {
  id: Uint8Array;
  account_id: string;
  public_key: Uint8Array;
  counter: string | number;
  transports: string;
  aaguid: string | null;
  backed_up: boolean;
  name: string;
  created_at: Date;
  last_used_at: Date | null;
}

const COLS = "id, account_id, public_key, counter, transports, aaguid, backed_up, name, created_at, last_used_at";
const toPasskey = (r: Row): Passkey => ({
  id: asBuffer(r.id)!,
  accountId: r.account_id,
  publicKey: asBuffer(r.public_key)!,
  counter: Number(r.counter),
  transports: r.transports ? r.transports.split(" ") : [],
  aaguid: r.aaguid,
  backedUp: r.backed_up,
  name: r.name,
  createdAt: r.created_at,
  lastUsedAt: r.last_used_at,
});

/** Verification failures are uniform to the browser; the detail goes to the audit log only. */
export class CeremonyError extends Error {
  constructor(
    readonly reason: string,
    readonly status = 400,
  ) {
    super(reason);
    this.name = "CeremonyError";
  }
}

// --- challenges ------------------------------------------------------------

/** Store a ceremony's challenge; the returned row id travels in a sealed cookie. */
export async function storeChallenge(s: AuthState, kind: ChallengeKind, challenge: string, accountId: string | null): Promise<string> {
  const { rows } = await s.ctx.db.query<{ id: string }>(
    "INSERT INTO auth_challenge (kind, challenge, account_id, expires_at) VALUES ($1, $2, $3, $4) RETURNING id",
    [kind, challenge, accountId, new Date(s.now() + CHALLENGE_TTL_MS)],
  );
  return rows[0]!.id;
}

/** Single use: the row is deleted as it is read, so a concurrent second verify finds nothing. */
export async function consumeChallenge(
  s: AuthState,
  id: string | undefined,
  kind: ChallengeKind,
): Promise<{ challenge: string; accountId: string | null } | null> {
  if (!id || !/^[0-9a-f-]{36}$/i.test(id)) return null;
  const { rows } = await s.ctx.db.query<{ challenge: string; account_id: string | null }>(
    "DELETE FROM auth_challenge WHERE id = $1 AND kind = $2 AND expires_at > $3 RETURNING challenge, account_id",
    [id, kind, new Date(s.now())],
  );
  return rows[0] ? { challenge: rows[0].challenge, accountId: rows[0].account_id } : null;
}

// --- passkey rows ----------------------------------------------------------

export async function listPasskeys(s: AuthState, accountId: string): Promise<Passkey[]> {
  const { rows } = await s.ctx.db.query<Row>(`SELECT ${COLS} FROM passkey WHERE account_id = $1 ORDER BY created_at, id`, [accountId]);
  return rows.map(toPasskey);
}

export async function getPasskey(s: AuthState, id: Buffer): Promise<Passkey | null> {
  const { rows } = await s.ctx.db.query<Row>(`SELECT ${COLS} FROM passkey WHERE id = $1`, [id]);
  return rows[0] ? toPasskey(rows[0]) : null;
}

export async function renamePasskey(s: AuthState, accountId: string, id: Buffer, name: string): Promise<boolean> {
  const res = await s.ctx.db.query("UPDATE passkey SET name = $3 WHERE id = $1 AND account_id = $2", [id, accountId, name]);
  return (res.rowCount ?? 0) > 0;
}

/** Refuses to delete the last passkey (`last_passkey`): recovery is the CLI, not an empty account. */
export async function deletePasskey(s: AuthState, accountId: string, id: Buffer): Promise<"deleted" | "not_found" | "last_passkey"> {
  return s.ctx.db.transaction(async (tx) => {
    const { rows } = await tx.query<{ id: Uint8Array }>("SELECT id FROM passkey WHERE account_id = $1 FOR UPDATE", [accountId]);
    if (!rows.some((r) => asBuffer(r.id)!.equals(id))) return "not_found";
    if (rows.length <= 1) return "last_passkey";
    await tx.query("DELETE FROM passkey WHERE id = $1 AND account_id = $2", [id, accountId]);
    return "deleted";
  });
}

export async function deleteAllPasskeys(s: AuthState, accountId: string): Promise<number> {
  const res = await s.ctx.db.query("DELETE FROM passkey WHERE account_id = $1", [accountId]);
  return res.rowCount ?? 0;
}

export const passkeyName = (raw: unknown, fallback: string): string => {
  const name = typeof raw === "string" ? raw.trim().replace(/\s+/g, " ") : "";
  return name ? name.slice(0, 64) : fallback;
};

// --- ceremonies ------------------------------------------------------------

/** Registration options for `email`; `excludeCredentials` keeps an authenticator from enrolling twice. */
export async function registrationOptions(s: AuthState, account: { id: string; email: string }): Promise<PublicKeyCredentialCreationOptionsJSON> {
  const existing = await listPasskeys(s, account.id);
  return generateRegistrationOptions({
    rpName: s.ctx.config.auth.rpName,
    rpID: s.rpId,
    userID: Buffer.from(account.id.replace(/-/g, ""), "hex"),
    userName: account.email,
    userDisplayName: account.email,
    timeout: CHALLENGE_TTL_MS,
    attestationType: "none",
    excludeCredentials: existing.map((p) => ({ id: b64url.encode(p.id), transports: p.transports })),
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    supportedAlgorithmIDs: SUPPORTED_ALGORITHMS,
  });
}

export async function verifyRegistration(
  s: AuthState,
  input: { response: RegistrationResponseJSON; challenge: string; accountId: string; name: string },
): Promise<Passkey> {
  let result: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    result = await verifyRegistrationResponse({
      response: input.response,
      expectedChallenge: input.challenge,
      expectedOrigin: s.origin,
      expectedRPID: s.rpId,
      requireUserVerification: true,
      supportedAlgorithmIDs: SUPPORTED_ALGORITHMS,
    });
  } catch (err) {
    throw new CeremonyError(`registration: ${(err as Error).message}`);
  }
  if (!result.verified) throw new CeremonyError("registration: not verified");
  const info = result.registrationInfo;
  const id = b64url.decode(info.credential.id);
  const t = s.now();
  try {
    await s.ctx.db.query(
      `INSERT INTO passkey (id, account_id, public_key, counter, transports, aaguid, backed_up, name, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        id,
        input.accountId,
        Buffer.from(info.credential.publicKey),
        info.credential.counter,
        (info.credential.transports ?? []).join(" "),
        info.aaguid === "00000000-0000-0000-0000-000000000000" ? null : info.aaguid,
        info.credentialBackedUp,
        input.name,
        new Date(t),
      ],
    );
  } catch (err) {
    // Same credential id again (excludeCredentials ignored): not a new passkey.
    if ((err as { code?: string }).code === "23505" || /duplicate key/i.test((err as Error).message)) {
      throw new CeremonyError("registration: credential already registered", 409);
    }
    throw err;
  }
  return (await getPasskey(s, id))!;
}

/** Discoverable-credential request: no `allowCredentials`, user verification required. */
export async function authenticationOptions(s: AuthState): Promise<PublicKeyCredentialRequestOptionsJSON> {
  return generateAuthenticationOptions({ rpID: s.rpId, userVerification: "required", timeout: CHALLENGE_TTL_MS });
}

/**
 * Verify an assertion against the passkey named by `response.id`, check that
 * the `userHandle` names the same account, and bump the counter. Returns the
 * passkey (with its account) on success.
 */
export async function verifyAuthentication(
  s: AuthState,
  input: { response: AuthenticationResponseJSON; challenge: string },
): Promise<Passkey> {
  const r = input.response;
  if (!b64url.is(r?.id) || r.id.length > 1400) throw new CeremonyError("assertion: bad credential id");
  const passkey = await getPasskey(s, b64url.decode(r.id));
  if (!passkey) throw new CeremonyError("assertion: unknown credential");
  const expectedHandle = Buffer.from(passkey.accountId.replace(/-/g, ""), "hex");
  if (!r.response?.userHandle || !b64url.decode(r.response.userHandle).equals(expectedHandle)) {
    throw new CeremonyError("assertion: user handle mismatch");
  }
  let result: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
  try {
    result = await verifyAuthenticationResponse({
      response: r,
      expectedChallenge: input.challenge,
      expectedOrigin: s.origin,
      expectedRPID: s.rpId,
      credential: { id: r.id, publicKey: new Uint8Array(passkey.publicKey), counter: passkey.counter, transports: passkey.transports },
      requireUserVerification: true,
    });
  } catch (err) {
    const msg = (err as Error).message;
    throw new CeremonyError(/counter/i.test(msg) ? `assertion: counter regression (${msg})` : `assertion: ${msg}`);
  }
  if (!result.verified) throw new CeremonyError("assertion: not verified");
  await s.ctx.db.query("UPDATE passkey SET counter = $2, last_used_at = $3, backed_up = $4 WHERE id = $1", [
    passkey.id,
    result.authenticationInfo.newCounter,
    new Date(s.now()),
    result.authenticationInfo.credentialBackedUp,
  ]);
  return { ...passkey, counter: result.authenticationInfo.newCounter };
}
