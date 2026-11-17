// Vercel serverless function: POST /agent (+ GET /health via api/health).
// Same handler as the long-running server — the AgentContext is built
// lazily once per instance and cached (src/context.ts). The raw request
// body is read verbatim from the stream so the HMAC can be verified over
// exactly the bytes the platform sent.
import type { IncomingMessage, ServerResponse } from "node:http";
import { getAgentContext } from "../src/context";
import { handleAgentRequest } from "../src/handler";

const MAX_BODY_BYTES = 1_000_000;

function readRawBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error("request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export default async function handler(
  req: IncomingMessage,
  res: ServerResponse
): Promise<void> {
  if (req.method !== "POST") {
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
    return;
  }
  try {
    const ctx = await getAgentContext();
    const rawBody = await readRawBody(req);
    const result = await handleAgentRequest(
      rawBody,
      req.headers["x-agent-games-signature"],
      ctx
    );
    res.writeHead(result.status, result.headers);
    res.end(result.body);
  } catch (err) {
    console.error("[agent] error:", (err as Error).message);
    if (!res.headersSent) {
      res.writeHead(500, { "content-type": "application/json" });
    }
    res.end(JSON.stringify({ error: "internal_error" }));
  }
}
