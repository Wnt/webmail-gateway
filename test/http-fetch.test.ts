import { execFile } from "node:child_process";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { httpDispatcher, httpFetch } from "../src/core/http-fetch.js";

const root = fileURLToPath(new URL("..", import.meta.url));

describe("ctx.fetch default (core/http-fetch)", () => {
  it("goes through its own Agent of the pinned undici, even after the global fetch ran", async () => {
    expect(httpFetch).not.toBe(globalThis.fetch);
    const server = createServer((_req, res) => res.end("ok"));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      // The global fetch installs Node's bundled dispatcher as the global one.
      expect(await (await globalThis.fetch(origin)).text()).toBe("ok");
      const res = await httpFetch(`${origin}/x`, { headers: new Headers({ "x-test": "1" }), signal: AbortSignal.timeout(5_000) });
      expect(await res.text()).toBe("ok");
      expect(Object.keys(httpDispatcher.stats)).toContain(origin);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  // GHSA-xjj6-f33q-929c: an over-encoded response that closes early left a
  // body stream whose error killed the process, even with the fetch rejection
  // caught. A child process keeps that from killing Vitest; the only socket is
  // a loopback test server.
  it("survives an over-encoded response that closes early", async () => {
    const moduleUrl = pathToFileURL(join(root, "src/core/http-fetch.ts")).href;
    const child = await promisify(execFile)(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `
        import { createServer } from "node:http";
        const { httpFetch } = await import(${JSON.stringify(moduleUrl)});
        const server = createServer((_req, res) => {
          res.writeHead(200, {
            "content-encoding": "gzip, gzip, gzip, gzip, gzip, gzip",
            "content-length": "10",
            connection: "close",
          });
          res.end();
        });
        await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
        try {
          await httpFetch("http://127.0.0.1:" + server.address().port + "/push");
        } catch {
          // Callers catch fetch failures; that must be enough.
        }
        await new Promise((resolve) => setTimeout(resolve, 50));
        await new Promise((resolve) => server.close(resolve));
        console.log("survived");
        `,
      ],
      { cwd: root, timeout: 10_000 },
    ).then(
      ({ stdout, stderr }) => ({ code: 0, stdout, stderr }),
      (error: { code?: number; stdout?: string; stderr?: string }) => ({ code: error.code, stdout: error.stdout, stderr: error.stderr }),
    );
    expect(child, child.stderr).toMatchObject({ code: 0, stdout: "survived\n" });
  });

  // Libraries that call the global fetch themselves: @simplewebauthn/server
  // downloads certificate revocation lists (CRLs) during passkey registration
  // through its helpers/fetch.js, i.e. globalThis.fetch.
  it("with the pinned undici installed, a library's own global fetch call survives the same response", async () => {
    const fetchModuleUrl = pathToFileURL(join(root, "src/core/http-fetch.ts")).href;
    const libFetchUrl = pathToFileURL(join(root, "node_modules/@simplewebauthn/server/esm/helpers/fetch.js")).href;
    const child = await promisify(execFile)(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `
        import { createServer } from "node:http";
        const undici = await import("undici");
        const { httpDispatcher } = await import(${JSON.stringify(fetchModuleUrl)});
        // What core/http-install.ts does (its wiring is checked in-process below).
        undici.install();
        undici.setGlobalDispatcher(httpDispatcher);
        const { fetch: libraryFetch } = await import(${JSON.stringify(libFetchUrl)});
        const server = createServer((_req, res) => {
          res.writeHead(200, {
            "content-encoding": "gzip, gzip, gzip, gzip, gzip, gzip",
            "content-length": "10",
            connection: "close",
          });
          res.end();
        });
        await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
        try {
          const res = await libraryFetch("http://127.0.0.1:" + server.address().port + "/root.crl");
          await res.arrayBuffer();
        } catch {
          // The library catches fetch failures; that must be enough.
        }
        await new Promise((resolve) => setTimeout(resolve, 50));
        await new Promise((resolve) => server.close(resolve));
        console.log("survived");
        `,
      ],
      { cwd: root, timeout: 10_000 },
    ).then(
      ({ stdout, stderr }) => ({ code: 0, stdout, stderr }),
      (error: { code?: number; stdout?: string; stderr?: string }) => ({ code: error.code, stdout: error.stdout, stderr: error.stderr }),
    );
    expect(child, child.stderr).toMatchObject({ code: 0, stdout: "survived\n" });
  });

  it("the entry points install it before anything else is imported", async () => {
    for (const entry of ["src/server.ts", "src/cli.ts"]) {
      const firstImport = (await readFile(join(root, entry), "utf8")).split("\n").find((l) => l.startsWith("import "));
      expect(firstImport, entry).toBe('import "./core/http-install.js";');
    }
  });

  it("is the only way src/ reaches the network over fetch", async () => {
    const files = (await readdir(join(root, "src"), { recursive: true }))
      .filter((f) => f.endsWith(".ts") && f !== join("core", "http-fetch.ts") && f !== join("core", "http-install.ts"));
    const offenders: string[] = [];
    for (const file of files) {
      const lines = (await readFile(join(root, "src", file), "utf8")).split("\n");
      lines.forEach((line, i) => {
        const code = line.replace(/\/\/.*$/, "");
        if (/\?\?\s*fetch\b|[{,]\s*fetch\s*[,}]|globalThis\.fetch|(^|[^.\w])fetch\s*\(/.test(code)) offenders.push(`${file}:${i + 1}`);
      });
    }
    expect(offenders).toEqual([]);
  });

  // Last in this file: it replaces this worker's globals.
  it("core/http-install puts the pinned undici's fetch and classes on globalThis, with httpDispatcher", async () => {
    const undici = await import("undici");
    await import("../src/core/http-install.js");
    expect(globalThis.fetch).toBe(undici.fetch);
    expect(globalThis.Headers).toBe(undici.Headers);
    expect(globalThis.Response).toBe(undici.Response);
    expect(globalThis.Request).toBe(undici.Request);
    expect(undici.getGlobalDispatcher()).toBe(httpDispatcher);
  });
});
