// Session object rewrite (design/jmap.md section 4). The public URLs come from
// fixed templates on PUBLIC_BASE_URL, whatever the upstream's own templates are
// (core/upstream maps each public request onto them); IDs and state pass
// through unchanged (P2).

export const CORE = "urn:ietf:params:jmap:core";
/**
 * Capabilities that do not work through the gateway, so they are never
 * advertised: WebSocket (not proxied), and emailpush (PushSubscription is
 * answered by the gateway's push feature, which does not implement it, D5).
 */
export const UNSUPPORTED_CAPABILITIES: ReadonlySet<string> = new Set([
  "urn:ietf:params:jmap:websocket",
  "urn:ietf:params:jmap:emailpush",
]);

/** The public URL templates. They equal legacy-proxy's; if a legacy upgrade changes those, `templateDrift` reports it. */
export const TEMPLATES = {
  apiUrl: "/jmap",
  downloadUrl: "/jmap/download/{accountId}/{blobId}/{type}/{name}",
  uploadUrl: "/jmap/upload/{accountId}",
  eventSourceUrl: "/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}",
} as const;

export interface RewriteOptions {
  publicBaseUrl: string;
  email: string;
  maxSizeUpload: number;
  maxSizeRequest: number;
  maxCallsInRequest: number;
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);

/** True when `s` looks like a JMAP Session object. */
export function isSession(s: unknown): s is Obj {
  return isObj(s) && isObj(s["capabilities"]) && isObj(s["accounts"]) && typeof s["apiUrl"] === "string";
}

/** The URL fields whose path differs from what this gateway forwards. */
export function templateDrift(s: Obj): string[] {
  const drift: string[] = [];
  for (const [k, path] of Object.entries(TEMPLATES)) {
    const v = s[k];
    if (typeof v !== "string") continue;
    let p: string;
    try {
      const u = new URL(v, "http://x");
      p = decodeURI(u.pathname) + decodeURI(u.search);
    } catch {
      drift.push(k);
      continue;
    }
    if (p !== path) drift.push(k);
  }
  return drift;
}

const clamp = (v: unknown, max: number): number => (typeof v === "number" && v > 0 ? Math.min(v, max) : max);

export function rewriteSession(s: Obj, o: RewriteOptions): Obj {
  const out: Obj = { ...s };
  out["apiUrl"] = o.publicBaseUrl + TEMPLATES.apiUrl;
  out["downloadUrl"] = o.publicBaseUrl + TEMPLATES.downloadUrl;
  out["uploadUrl"] = o.publicBaseUrl + TEMPLATES.uploadUrl;
  out["eventSourceUrl"] = o.publicBaseUrl + TEMPLATES.eventSourceUrl;
  out["username"] = o.email;

  const caps: Obj = { ...(s["capabilities"] as Obj) };
  for (const c of UNSUPPORTED_CAPABILITIES) delete caps[c];
  const core: Obj = isObj(caps[CORE]) ? { ...caps[CORE] } : {};
  core["maxSizeUpload"] = clamp(core["maxSizeUpload"], o.maxSizeUpload);
  core["maxSizeRequest"] = clamp(core["maxSizeRequest"], o.maxSizeRequest);
  core["maxCallsInRequest"] = clamp(core["maxCallsInRequest"], o.maxCallsInRequest);
  caps[CORE] = core;
  out["capabilities"] = caps;

  const accounts: Obj = {};
  for (const [id, a] of Object.entries(s["accounts"] as Obj)) {
    if (!isObj(a)) {
      accounts[id] = a;
      continue;
    }
    const out: Obj = { ...a };
    // Shared accounts (isPersonal: false, e.g. on Fastmail) keep their own names.
    if (a["isPersonal"] !== false) out["name"] = o.email;
    if (isObj(a["accountCapabilities"])) {
      const ac: Obj = { ...a["accountCapabilities"] };
      for (const c of UNSUPPORTED_CAPABILITIES) delete ac[c];
      out["accountCapabilities"] = ac;
    }
    accounts[id] = out;
  }
  out["accounts"] = accounts;
  return out;
}
