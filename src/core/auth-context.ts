import type { FastifyRequest } from "fastify";

/** The authenticated caller. `via` says how: password-mode Basic, or an OAuth access token. */
export type Principal = {
  accountId: string;
  email: string;
  scopes: string[];
  via: "basic" | "oauth";
};

/** Return a Principal if this authenticator recognises the credentials on `req`, else null (never throw for "not mine"). */
export type Authenticator = (req: FastifyRequest) => Promise<Principal | null>;

const authenticators: Authenticator[] = [];

/** Register an authenticator (tried in registration order). Returns an unregister function. */
export function registerAuthenticator(fn: Authenticator): () => void {
  authenticators.push(fn);
  return () => {
    const i = authenticators.indexOf(fn);
    if (i >= 0) authenticators.splice(i, 1);
  };
}

/** First non-null result of the registered authenticators, or null. */
export async function authenticate(req: FastifyRequest): Promise<Principal | null> {
  for (const fn of [...authenticators]) {
    const p = await fn(req);
    if (p) return p;
  }
  return null;
}

/** Test helper: drop all registered authenticators. */
export function resetAuthenticators(): void {
  authenticators.length = 0;
}
