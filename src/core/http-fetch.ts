// The gateway's outgoing HTTP client for `ctx.fetch`: the undici pinned in
// package.json, not Node's global `fetch`. Node bundles its own undici, which
// moves only with the Node base image; every Node 24 release so far bundles an
// undici affected by GHSA-xjj6-f33q-929c and GHSA-qrxm-fqhp-jwvm (a malicious
// or broken HTTPS responder could crash the process), fixed in undici 8.12.2.
// Push services and the summary model are such responders.
// The upstream JMAP pool (core/upstream) already uses this package's Agent.
import { fetch as undiciFetch } from "undici";

/** Same contract as the global `fetch`; tests inject their own through `AppDeps.fetch`. */
export const httpFetch = undiciFetch as unknown as typeof fetch;
