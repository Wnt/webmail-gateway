// RFC 6570 level 1 (simple string expansion) for JMAP session URL templates
// (RFC 8620 section 2: downloadUrl, uploadUrl, eventSourceUrl).

export type TemplateVars = Readonly<Record<string, string | undefined>>;

/** Percent-encoding as Bulwark applies it (encodeURIComponent), so legacy-proxy sees byte-identical paths. */
const enc = (v: string): string => encodeURIComponent(v);
const VAR = /\{([A-Za-z0-9_]+)\}/g;

/**
 * Expand `{name}` variables with percent-encoded values. In the query, a
 * `key={var}` pair whose variable is undefined is dropped (a client that did not
 * send `ping` gets the server's default instead of `ping=`); elsewhere an
 * undefined variable expands to the empty string, as RFC 6570 says.
 */
export function expandTemplate(template: string, vars: TemplateVars): string {
  const q = template.indexOf("?");
  const path = q < 0 ? template : template.slice(0, q);
  const query = q < 0 ? null : template.slice(q + 1);
  const sub = (s: string) => s.replace(VAR, (_m, name: string) => enc(vars[name] ?? ""));
  let out = sub(path);
  if (query !== null) {
    const pairs = query
      .split("&")
      .filter((pair) => {
        const m = /^[^=]*=\{([A-Za-z0-9_]+)\}$/.exec(pair);
        return !(m && vars[m[1]!] === undefined);
      })
      .map(sub);
    if (pairs.length) out += `?${pairs.join("&")}`;
  }
  return out;
}

/** Append an already-encoded query string (no leading `?`). */
export function appendQuery(url: string, query: string | undefined): string {
  if (!query) return url;
  return url + (url.includes("?") ? "&" : "?") + query;
}

/** Variable names used in a template. */
export function templateVars(template: string): string[] {
  return [...template.matchAll(VAR)].map((m) => m[1]!);
}
