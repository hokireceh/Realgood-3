// Proof Gatekeeper agent — entrypoint (long-running server).
// Startup (fail fast) lives in ./context so the Vercel serverless
// functions (api/agent.ts, api/health.ts) share the exact same init.
import { getAgentContext } from "./context";
import { createServer } from "./http-server";

async function main(): Promise<void> {
  console.log("[gatekeeper] starting…");
  const ctx = await getAgentContext();

  const server = createServer(ctx);
  await new Promise<void>((resolve) => {
    server.listen(ctx.config.port, ctx.config.host, () => resolve());
  });
  const scheme = ctx.config.tlsKeyPath ? "https" : "http";
  console.log(
    `[gatekeeper] listening on ${scheme}://${ctx.config.host}:${ctx.config.port} ` +
      `(POST /agent, GET /health) — strict finalized mode: ${ctx.config.requireKurierFinalized}`
  );

  const shutdown = () => {
    console.log("[gatekeeper] shutting down…");
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5_000).unref();
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((err) => {
  console.error("[gatekeeper] fatal startup error:", (err as Error).message);
  process.exit(1);
});
