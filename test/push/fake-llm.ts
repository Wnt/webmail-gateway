import { createServer, type IncomingHttpHeaders, type Server } from "node:http";

/** A fake OpenAI-compatible chat-completions server (`POST /v1/chat/completions`). */

export interface LlmRequest {
  path: string;
  headers: IncomingHttpHeaders;
  body: {
    model: string;
    messages: { role: string; content: string }[];
    max_tokens?: number;
    temperature?: number;
    stream?: boolean;
    response_format?: { type: string; json_schema?: { name: string; schema: unknown } };
    chat_template_kwargs?: Record<string, unknown>;
  };
}

export type LlmAnswer =
  /** `choices[0].message.content` */
  | { content: string; delayMs?: number }
  /** a raw HTTP answer */
  | { status: number; text: string; delayMs?: number }
  /** never answers (until the client gives up or the server closes) */
  | { hang: true };

export interface FakeLlm {
  /** Base URL including `/v1`, as SUMMARY_API_URL. */
  url: string;
  requests: LlmRequest[];
  /** Decides the answer per request; default: a fixed summary. */
  answer: (req: LlmRequest) => LlmAnswer | Promise<LlmAnswer>;
  /** Requests whose client went away before the answer (aborted). */
  aborted: number;
  close(): Promise<void>;
}

export const DEFAULT_SUMMARY = "Alice asks whether you can join the planning meeting on Friday.";

/** A model answer in the shape the response_format schema forces: `{"ai_instructions": …, "summary": …}`. */
export const json = (summary: string, aiInstructions = false): string => JSON.stringify({ ai_instructions: aiInstructions, summary });

export async function startFakeLlm(): Promise<FakeLlm> {
  const fake: FakeLlm = {
    url: "",
    requests: [],
    answer: () => ({ content: json(DEFAULT_SUMMARY) }),
    aborted: 0,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", async () => {
      if (req.method !== "POST" || req.url !== "/v1/chat/completions") {
        res.writeHead(404).end("{}");
        return;
      }
      const r: LlmRequest = { path: req.url, headers: req.headers, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) };
      fake.requests.push(r);
      let gone = false;
      res.on("close", () => {
        if (!res.writableEnded) {
          gone = true;
          fake.aborted++;
        }
      });
      const a = await fake.answer(r);
      if ("hang" in a) return;
      if (a.delayMs) await new Promise((t) => setTimeout(t, a.delayMs));
      if (gone) return;
      if ("content" in a) {
        res.writeHead(200, { "content-type": "application/json" }).end(
          JSON.stringify({
            id: "chatcmpl-1",
            object: "chat.completion",
            model: r.body.model,
            choices: [{ index: 0, message: { role: "assistant", content: a.content }, finish_reason: "stop" }],
          }),
        );
      } else {
        res.writeHead(a.status, { "content-type": "application/json" }).end(a.text);
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const addr = server.address();
  fake.url = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}/v1`;
  return fake;
}
