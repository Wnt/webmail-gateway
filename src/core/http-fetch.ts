// The gateway's outgoing HTTP client for `ctx.fetch`: the undici pinned in
// package.json, not Node's global `fetch`. Node bundles its own undici, which
// moves only with the Node base image; every Node 24 release so far bundles an
// undici affected by GHSA-xjj6-f33q-929c and GHSA-qrxm-fqhp-jwvm (a malicious
// or broken HTTPS responder could crash the process), fixed in undici 8.12.2.
// Push services and the summary model are such responders.
//
// The dispatcher is this module's own Agent, never the global one: Node's
// bundled undici registers its Agent as the global dispatcher (under the same
// symbols the pinned package reads) once anything has used the global fetch,
// and the connection-level fixes live in the dispatcher.
// The upstream JMAP pool (core/upstream) already uses its own Agents too.
import { Agent, fetch as undiciFetch } from "undici";

/** The Agent every `httpFetch` request goes through. */
export const httpDispatcher = new Agent();

/** Same contract as the global `fetch`; tests inject their own through `AppDeps.fetch`. */
export const httpFetch = ((input: Parameters<typeof fetch>[0], init?: RequestInit) =>
  undiciFetch(
    input as Parameters<typeof undiciFetch>[0],
    { ...init, dispatcher: httpDispatcher } as Parameters<typeof undiciFetch>[1],
  )) as unknown as typeof fetch;
