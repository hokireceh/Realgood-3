// Shared HTTP response helper: a signed JSON result for POST /agent.
// (Moved out of handler.ts so the Steal track can use the identical
// signing behaviour without a handler <-> steal-handler import cycle.)
import type { Config } from "./config";
import { signBody, SIGNATURE_HEADER } from "./hmac";

export interface HttpResult {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
}

export function jsonResult(
  status: number,
  obj: unknown,
  cfg: Config,
  sign: boolean
): HttpResult {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (sign) {
    headers[SIGNATURE_HEADER] = signBody(cfg.hmacSecret, cfg.hmacAlgorithm, body);
  }
  return { status, headers, body };
}
