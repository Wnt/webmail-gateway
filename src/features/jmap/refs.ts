// RFC 8620 back-references, resolved in the gateway when a batch is split
// (design/jmap.md section 6). Semantics follow legacy-proxy's src/jmap/refs.ts
// so a reference behaves the same whichever side resolves it:
//  - section 3.7 result references: a top-level `#key` whose value is
//    `{resultOf, name, path}`; JSON Pointer with the `*` array extension.
//  - section 5.3 creation references: a string `#tempId`, or a nested object
//    key `#tempId`, replaced by the id created earlier in the request.

export type Json = unknown;
export type Args = Record<string, Json>;
export type MethodResponse = [string, Args, string];

/** Earlier responses by call id. One id can carry several responses (side responses). */
export type Prior = Map<string, MethodResponse[]>;
export type CreatedIds = Map<string, string>;

export class RefError extends Error {
  readonly type = "invalidResultReference";
}

function isResultRef(v: Json): v is { resultOf: string; name: string; path: string } {
  return (
    !!v &&
    typeof v === "object" &&
    typeof (v as Args)["resultOf"] === "string" &&
    typeof (v as Args)["name"] === "string" &&
    typeof (v as Args)["path"] === "string"
  );
}

function lookup(prior: Prior, ref: { resultOf: string; name: string; path: string }): Json {
  const responses = prior.get(ref.resultOf);
  if (!responses || responses.length === 0) throw new RefError(`no prior call with id "${ref.resultOf}"`);
  const r = responses.find(([name]) => name === ref.name);
  if (!r) throw new RefError(`call "${ref.resultOf}" did not produce "${ref.name}"`);
  const out = jsonPointer(r[1], ref.path);
  if (out === undefined) throw new RefError(`path "${ref.path}" did not resolve in call "${ref.resultOf}"`);
  return out;
}

export interface ResolveOptions {
  /** Result references to these call ids are left untouched (the upstream resolves them). */
  keepResultOf?: ReadonlySet<string>;
  /** Resolve creation references (`#tempId`). Off when forwarding: legacy resolves them from `createdIds`. */
  creation?: CreatedIds;
}

/** Resolve the references in one call's arguments. Throws `RefError`. */
export function resolveArgs(args: Args, prior: Prior, opts: ResolveOptions = {}): Args {
  return resolveInner(args, prior, opts, true) as Args;
}

function resolveInner(v: Json, prior: Prior, opts: ResolveOptions, top: boolean): Json {
  if (typeof v === "string") {
    if (opts.creation && v.length > 1 && v.startsWith("#")) {
      const real = opts.creation.get(v.slice(1));
      if (real !== undefined) return real;
    }
    return v;
  }
  if (v === null || typeof v !== "object") return v;
  if (Array.isArray(v)) return v.map((x) => resolveInner(x, prior, opts, false));
  const out: Args = {};
  for (const [k, val] of Object.entries(v as Args)) {
    if (top && k.startsWith("#") && isResultRef(val)) {
      if (opts.keepResultOf?.has(val.resultOf)) {
        out[k] = val;
      } else {
        out[k.slice(1)] = lookup(prior, val);
      }
      continue;
    }
    let key = k;
    if (!top && opts.creation && k.startsWith("#")) {
      const real = opts.creation.get(k.slice(1));
      if (real !== undefined) key = real;
    }
    out[key] = resolveInner(val, prior, opts, false);
  }
  return out;
}

/** Collect `created` ids from a `Foo/set`, `Foo/copy` or `Email/import` response. */
export function harvestCreatedIds(into: CreatedIds, name: string, result: Json): void {
  if (!(name.endsWith("/set") || name.endsWith("/copy") || name === "Email/import")) return;
  const created = result && typeof result === "object" ? (result as Args)["created"] : undefined;
  if (!created || typeof created !== "object") return;
  for (const [tempId, obj] of Object.entries(created as Args)) {
    const id = obj && typeof obj === "object" ? (obj as Args)["id"] : undefined;
    if (typeof id === "string") into.set(tempId, id);
  }
}

/** RFC 6901 JSON Pointer with RFC 8620 section 3.7's `*` (map over an array, flattening arrays). */
export function jsonPointer(input: Json, pointer: string): Json {
  if (pointer === "" || pointer === "/") return input;
  const parts = pointer
    .replace(/^\//, "")
    .split("/")
    .map((s) => s.replaceAll("~1", "/").replaceAll("~0", "~"));
  return walk(input, parts, 0);
}

function walk(here: Json, parts: string[], i: number): Json {
  if (i >= parts.length) return here;
  const seg = parts[i]!;
  if (seg === "*") {
    if (!Array.isArray(here)) return undefined;
    if (i === parts.length - 1) return here;
    const out: Json[] = [];
    for (const el of here) {
      const got = walk(el, parts, i + 1);
      if (Array.isArray(got)) out.push(...got);
      else if (got !== undefined) out.push(got);
    }
    return out;
  }
  if (Array.isArray(here)) return /^\d+$/.test(seg) ? walk(here[Number(seg)], parts, i + 1) : undefined;
  if (here && typeof here === "object" && Object.hasOwn(here, seg)) return walk((here as Args)[seg], parts, i + 1);
  return undefined;
}
