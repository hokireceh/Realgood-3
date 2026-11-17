// HMAC signing / verification for the Agent Games platform.
// The HMAC is computed over the RAW request/response body and compared with
// the x-agent-games-signature header BEFORE any JSON is parsed.
// Algorithm: HMAC-SHA256, hex-encoded (configurable via HMAC_ALGORITHM).
import crypto from "node:crypto";

export const SIGNATURE_HEADER = "x-agent-games-signature";

/** Hex HMAC of the raw body. */
export function signBody(secret: string, algorithm: string, rawBody: Buffer): string {
  return crypto.createHmac(algorithm, secret).update(rawBody).digest("hex");
}

/**
 * Timing-safe verification of the platform's signature header.
 * Accepts a bare hex digest, or one prefixed with "<algo>=" (e.g. "sha256=…").
 * Any mismatch, malformed value, or missing header => false.
 */
export function verifySignature(
  secret: string,
  algorithm: string,
  rawBody: Buffer,
  headerValue: string | string[] | undefined
): boolean {
  if (typeof headerValue !== "string" || headerValue.length === 0) return false;
  let provided = headerValue.trim();
  const prefix = `${algorithm}=`;
  if (provided.toLowerCase().startsWith(prefix)) provided = provided.slice(prefix.length);
  if (!/^[0-9a-fA-F]+$/.test(provided)) return false;

  const expected = signBody(secret, algorithm, rawBody);
  const a = Buffer.from(provided.toLowerCase(), "utf8");
  const b = Buffer.from(expected.toLowerCase(), "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
