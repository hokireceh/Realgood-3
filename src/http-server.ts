// HTTP(S) server: one public route (POST /agent) plus a health check.
// The raw request body is captured verbatim so the HMAC can be verified
// over exactly the bytes the platform sent.
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import type { AgentContext } from "./handler";
import { handleAgentRequest } from "./handler";

const MAX_BODY_BYTES = 1_000_000;

function readRawBody(req: http.IncomingMessage): Promise<Buffer> {
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

export function createServer(ctx: AgentContext): http.Server | https.Server {
  const cfg = ctx.config;

  const requestListener = async (
    req: http.IncomingMessage,
    res: http.ServerResponse
  ) => {
    try {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

      if (req.method === "GET" && url.pathname === "/health") {
        const body = JSON.stringify({
          ok: true,
          protocolVersion: "v1",
          mode: cfg.kurierApiKey ? "kurier" : "local-only",
          uptimeSec: Math.floor(process.uptime()),
          proofsRecorded: ctx.store.count,
        });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(body);
        return;
      }

      if (req.method === "POST" && url.pathname === "/agent") {
        const rawBody = await readRawBody(req);
        const result = await handleAgentRequest(
          rawBody,
          req.headers["x-agent-games-signature"],
          ctx
        );
        res.writeHead(result.status, result.headers);
        res.end(result.body);
        return;
      }

      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
    } catch (err) {
      console.error("[server] unhandled error:", (err as Error).message);
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
      }
      res.end(JSON.stringify({ error: "internal_error" }));
    }
  };

  let server: http.Server | https.Server;
  if (cfg.tlsKeyPath && cfg.tlsCertPath) {
    server = https.createServer(
      {
        key: fs.readFileSync(cfg.tlsKeyPath),
        cert: fs.readFileSync(cfg.tlsCertPath),
      },
      requestListener
    );
  } else {
    server = http.createServer(requestListener);
  }

  // Hard socket timeout: the platform deadline is 60s; never hold a
  // connection open far beyond it.
  server.timeout = cfg.responseDeadlineMs + 10_000;
  server.keepAliveTimeout = 5_000;
  return server;
}
