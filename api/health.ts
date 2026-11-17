// Vercel serverless function: GET /health.
// Same payload as the long-running server's /health. Building the context
// also warms the instance (circuit download + init) so the first real
// task afterwards is fast.
import type { IncomingMessage, ServerResponse } from "node:http";
import { getAgentContext } from "../src/context";

export default async function handler(
  req: IncomingMessage,
  res: ServerResponse
): Promise<void> {
  if (req.method !== "GET") {
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
    return;
  }
  try {
    const ctx = await getAgentContext();
    const body = JSON.stringify({
      ok: true,
      protocolVersion: "v1",
      mode: ctx.config.kurierApiKey ? "kurier" : "local-only",
      uptimeSec: Math.floor(process.uptime()),
      proofsRecorded: ctx.store.count,
    });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(body);
  } catch (err) {
    console.error("[health] error:", (err as Error).message);
    if (!res.headersSent) {
      res.writeHead(500, { "content-type": "application/json" });
    }
    res.end(JSON.stringify({ error: "internal_error" }));
  }
}
