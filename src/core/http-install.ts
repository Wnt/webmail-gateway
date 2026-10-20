// Side-effect module, imported first by the entry points (src/server.ts,
// src/cli.ts): the process's global fetch, Headers, Request, Response, … are
// the pinned undici's (its documented `install()`), and its global dispatcher
// is httpDispatcher. So libraries that call the global fetch themselves - such
// as @simplewebauthn/server's certificate revocation (CRL) download during
// passkey registration - also run on the pinned, fixed undici rather than the
// copy bundled inside Node (see core/http-fetch.ts). Tests build the app
// without it and keep Node's globals.
import { install, setGlobalDispatcher } from "undici";
import { httpDispatcher } from "./http-fetch.js";

install();
setGlobalDispatcher(httpDispatcher);
