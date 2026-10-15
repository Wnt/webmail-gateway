import type { FastifyRequest } from "fastify";
import type { AppContext } from "../../types.js";

export interface AuditEntry {
  event: string;
  accountId?: string | null;
  clientId?: string | null;
  ip?: string | null;
  userAgent?: string | null;
  /** Never tokens, secrets or passwords. */
  details?: Record<string, unknown>;
}

/** Client address and user agent of a request, for the audit log and session rows. */
export function requestMeta(req: FastifyRequest): { ip: string; userAgent: string | null } {
  const ua = req.headers["user-agent"];
  return { ip: req.ip, userAgent: typeof ua === "string" ? ua.slice(0, 256) : null };
}

/** Append one audit row. Never throws: a failed audit write is logged, the request goes on. */
export async function audit(
  ctx: Pick<AppContext, "db" | "log">,
  entry: AuditEntry,
  now: number = Date.now(),
): Promise<void> {
  try {
    await ctx.db.query(
      "INSERT INTO auth_audit (at, event, account_id, client_id, ip, user_agent, details) VALUES ($1, $2, $3, $4, $5, $6, $7)",
      [
        new Date(now),
        entry.event,
        entry.accountId ?? null,
        entry.clientId ?? null,
        entry.ip ?? null,
        entry.userAgent ?? null,
        JSON.stringify(entry.details ?? {}),
      ],
    );
  } catch (err) {
    ctx.log.error({ err, event: entry.event }, "audit write failed");
  }
}
