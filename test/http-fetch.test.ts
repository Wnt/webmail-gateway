import { execFile } from "node:child_process";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { fetch as undiciFetch } from "undici";
import { describe, expect, it } from "vitest";
import { httpFetch } from "../src/core/http-fetch.js";

const root = fileURLToPath(new URL("..", import.meta.url));

describe("ctx.fetch default (core/http-fetch)", () => {
  it("is the pinned undici's fetch, not Node's bundled one", () => {
    expect(httpFetch).toBe(undiciFetch);
    expect(httpFetch).not.toBe(globalThis.fetch);
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

  it("is the only way src/ reaches the network over fetch", async () => {
    const files = (await readdir(join(root, "src"), { recursive: true }))
      .filter((f) => f.endsWith(".ts") && f !== join("core", "http-fetch.ts"));
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
});
