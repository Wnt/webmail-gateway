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
import type { Queryable } from "../../db/pool.js";
import { audit } from "./audit.js";
import { holdAuth, holdSession, holdStepUp, lockAccountForRevocation } from "./generation.js";
import type { AuthState } from "./state.js";
import { asBuffer, b64url } from "./util.js";

export const CHALLENGE_TTL_MS = 120_000;
/** Ed25519, ES256, RS256: what passkey providers ship today. Pinned so the library does not probe the runtime for PQC algorithms. */
export const SUPPORTED_ALGORITHMS = [-8, -7, -257];
/** `reauth`: the step-up assertion on the management page (account-bound, like `enroll` and `add`). */
export type ChallengeKind = "login" | "enroll" | "add" | "reauth";

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
  /** A temporary passkey (CLI `enroll --ttl`) stops working at this time; null: an ordinary passkey. */
  expiresAt: Date | null;
}

/** A temporary passkey that has reached its expiry. */
export const passkeyExpired = (p: Pick<Passkey, "expiresAt">, now: number): boolean =>
  p.expiresAt !== null && p.expiresAt.getTime() <= now;

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
  expires_at: Date | null;
}

const COLS = "id, account_id, public_key, counter, transports, aaguid, backed_up, name, created_at, last_used_at, expires_at";
const P_COLS = COLS.split(", ").map((c) => `p.${c}`).join(", ");
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
  expiresAt: r.expires_at,
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

export async function getPasskey(s: AuthState, id: Buffer, q: Queryable = s.ctx.db): Promise<Passkey | null> {
  const { rows } = await q.query<Row>(`SELECT ${COLS} FROM passkey WHERE id = $1`, [id]);
  return rows[0] ? toPasskey(rows[0]) : null;
}

/** The session asking for a passkey change, as read at the start of the request. */
export interface Requester {
  idHash: Buffer;
  generation: number;
}

/** Rename, if the asking session is still live when the row is written (lock order: account, passkey, session). */
export async function renamePasskey(
  s: AuthState,
  accountId: string,
  id: Buffer,
  name: string,
  by: Requester,
): Promise<"renamed" | "not_found" | "no_session" | "temporary_passkey"> {
  return s.ctx.db.transaction(async (tx) => {
    if (!(await holdAuth(tx, { accountId, generation: by.generation }))) return "no_session";
    const { rows } = await tx.query("SELECT 1 FROM passkey WHERE id = $1 AND account_id = $2 FOR UPDATE", [id, accountId]);
    if (rows.length === 0) return "not_found";
    if (!(await holdSession(tx, accountId, { idHash: by.idHash, now: s.now() }))) return "no_session";
    const temp = await tx.query(
      "SELECT 1 FROM auth_session s JOIN passkey p ON p.id = s.passkey_id WHERE s.id_hash = $1 AND p.expires_at IS NOT NULL",
      [by.idHash],
    );
    if (temp.rows.length > 0) return "temporary_passkey";
    await tx.query("UPDATE passkey SET name = $3 WHERE id = $1 AND account_id = $2", [id, accountId, name]);
    return "renamed";
  });
}

export type DeleteOutcome =
  | { status: "deleted"; sessions: number; grants: number; name: string; temporary: boolean }
  | { status: "not_found" | "last_passkey" | "no_session" | "reauth_required" };

/**
 * Delete a passkey and everything it authorized (audit gateway-auth-2): the
 * gateway sessions it created, its unused codes (by cascade) and its OAuth
 * grants, with their tokens and push subscriptions. Grants from before grants
 * recorded their passkey go too, since any of them may be this one's. Other
 * passkeys' sessions and grants stay. Refuses to delete the last ordinary
 * passkey (`last_passkey`): recovery is the CLI, not an empty account; a
 * temporary passkey can always go, and does not count as a remaining one.
 * A temporary passkey revokes only the grants that recorded it: it was
 * enrolled long after grants started recording their passkey (migration
 * 101), so the owner's older grants and push are not its. `by`: the
 * session asking, rechecked under lock (`no_session` if it was reset or
 * revoked meanwhile), which must also hold a step-up authorization
 * (`reauth_required`); null for callers that are not a session (the sweeper).
 */
export async function deletePasskey(
  s: AuthState,
  accountId: string,
  id: Buffer,
  by: Requester | null,
  reason: "passkey_deleted" | "passkey_expired" = "passkey_deleted",
): Promise<DeleteOutcome> {
  const out = await s.ctx.db.transaction(async (tx) => {
    const generation = await lockAccountForRevocation(tx, accountId);
    if (by && generation !== by.generation) return { status: "no_session" as const };
    const { rows } = await tx.query<{ id: Uint8Array; name: string; expires_at: Date | null }>(
      "SELECT id, name, expires_at FROM passkey WHERE account_id = $1 FOR UPDATE",
      [accountId],
    );
    if (by && !(await holdSession(tx, accountId, { idHash: by.idHash, now: s.now() }))) return { status: "no_session" as const };
    if (by && !(await holdStepUp(tx, { idHash: by.idHash, accountId }, s.now()))) return { status: "reauth_required" as const };
    const target = rows.find((r) => asBuffer(r.id)!.equals(id));
    if (!target) return { status: "not_found" as const };
    const temporary = target.expires_at !== null;
    if (!temporary && rows.filter((r) => r.expires_at === null).length <= 1) return { status: "last_passkey" as const };
    const sessions = await tx.query("DELETE FROM auth_session WHERE passkey_id = $1 AND account_id = $2", [id, accountId]);
    const revoked = await s.store.revokeIn(tx, { accountId, passkeyId: id, ...(temporary ? { exact: true } : {}) }, reason);
    await tx.query("DELETE FROM passkey WHERE id = $1 AND account_id = $2", [id, accountId]);
    return { status: "deleted" as const, sessions: sessions.rowCount ?? 0, revoked, name: target.name, temporary };
  });
  if (out.status !== "deleted") return out;
  await s.store.announce(out.revoked, reason);
  return { status: "deleted", sessions: out.sessions, grants: out.revoked.length, name: out.name, temporary: out.temporary };
}

/**
 * Housekeeping (the auth plugin runs it every minute): delete expired
 * temporary passkeys with the same cascade as a manual deletion, and audit
 * each expiry. Nothing depends on it for enforcement: everything from an
 * expired passkey is refused at use already.
 */
export async function sweepExpiredPasskeys(s: AuthState): Promise<number> {
  const { rows } = await s.ctx.db.query<{ id: Uint8Array; account_id: string; expires_at: Date }>(
    "SELECT id, account_id, expires_at FROM passkey WHERE expires_at <= $1 ORDER BY expires_at LIMIT 100",
    [new Date(s.now())],
  );
  let n = 0;
  for (const r of rows) {
    const out = await deletePasskey(s, r.account_id, asBuffer(r.id)!, null, "passkey_expired");
    if (out.status !== "deleted") continue;
    n++;
    await audit(
      s.ctx,
      {
        event: "passkey.expired",
        accountId: r.account_id,
        details: { passkey: out.name, expiredAt: r.expires_at.toISOString(), sessions: out.sessions, grants: out.grants },
      },
      s.now(),
    );
  }
  return n;
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

/** A registration response that verified; `storePasskey` writes it. */
export type NewCredential = NonNullable<Awaited<ReturnType<typeof verifyRegistrationResponse>>["registrationInfo"]>;

/** Verify a registration response (no database writes). */
export async function verifyRegistration(
  s: AuthState,
  input: { response: RegistrationResponseJSON; challenge: string },
): Promise<NewCredential> {
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
  return result.registrationInfo;
}

/** Store a verified credential for `accountId`; call inside the issuing transaction, after `holdAuth`. */
export async function storePasskey(
  s: AuthState,
  q: Queryable,
  input: { info: NewCredential; accountId: string; name: string; expiresAt?: Date | null },
): Promise<Passkey> {
  const { info } = input;
  const id = b64url.decode(info.credential.id);
  const t = s.now();
  try {
    await q.query(
      `INSERT INTO passkey (id, account_id, public_key, counter, transports, aaguid, backed_up, name, created_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
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
        input.expiresAt ?? null,
      ],
    );
  } catch (err) {
    // Same credential id again (excludeCredentials ignored): not a new passkey.
    if ((err as { code?: string }).code === "23505" || /duplicate key/i.test((err as Error).message)) {
      throw new CeremonyError("registration: credential already registered", 409);
    }
    throw err;
  }
  return (await getPasskey(s, id, q))!;
}

/**
 * Login: a discoverable-credential request, no `allowCredentials`. Step-up:
 * `allow` lists the account's passkeys, so the browser offers only those.
 * User verification is required either way.
 */
export async function authenticationOptions(s: AuthState, allow?: Passkey[]): Promise<PublicKeyCredentialRequestOptionsJSON> {
  return generateAuthenticationOptions({
    rpID: s.rpId,
    userVerification: "required",
    timeout: CHALLENGE_TTL_MS,
    ...(allow ? { allowCredentials: allow.map((p) => ({ id: b64url.encode(p.id), transports: p.transports })) } : {}),
  });
}

/**
 * Verify an assertion against the passkey named by `response.id`, check that
 * the `userHandle` names the same account, and bump the counter. Returns the
 * passkey (with its account) and the account's auth generation as read with
 * it, for the issuer's `holdAuth`. `accountId` (step-up, where the request
 * listed the account's credentials): the passkey must be that account's, and
 * the authenticator may then omit `userHandle`; login always requires it.
 */
export async function verifyAuthentication(
  s: AuthState,
  input: { response: AuthenticationResponseJSON; challenge: string; accountId?: string },
): Promise<{ passkey: Passkey; generation: number }> {
  const r = input.response;
  if (!b64url.is(r?.id) || r.id.length > 1400) throw new CeremonyError("assertion: bad credential id");
  const { rows } = await s.ctx.db.query<Row & { auth_generation: number }>(
    `SELECT ${P_COLS}, a.auth_generation FROM passkey p JOIN account a ON a.id = p.account_id WHERE p.id = $1`,
    [b64url.decode(r.id)],
  );
  if (!rows[0]) throw new CeremonyError("assertion: unknown credential");
  const passkey = toPasskey(rows[0]);
  const generation = rows[0].auth_generation;
  if (input.accountId !== undefined && passkey.accountId !== input.accountId) throw new CeremonyError("step-up: another account's passkey");
  // A temporary passkey past its expiry signs nobody in (it may not be swept yet).
  if (passkeyExpired(passkey, s.now())) throw new CeremonyError("assertion: temporary passkey expired");
  const expectedHandle = Buffer.from(passkey.accountId.replace(/-/g, ""), "hex");
  const handle = r.response?.userHandle;
  if (handle ? !b64url.decode(handle).equals(expectedHandle) : input.accountId === undefined) {
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
  return { passkey: { ...passkey, counter: result.authenticationInfo.newCounter }, generation };
}
