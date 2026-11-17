// Configuration: environment variables only. Secrets are never hardcoded.
// The process fails fast at startup if a required secret is missing.
import path from "node:path";
import dotenv from "dotenv";

dotenv.config();

function required(name: string): string {
  const v = process.env[name];
  if (!v || v.trim() === "") {
    throw new Error(
      `Missing required environment variable ${name}. ` +
        `Copy .env.example to .env and fill it in (never commit .env).`
    );
  }
  return v.trim();
}

function optional(name: string, fallback: string): string {
  const v = process.env[name];
  return v && v.trim() !== "" ? v.trim() : fallback;
}

function optionalBool(name: string, fallback: boolean): boolean {
  const v = process.env[name];
  if (v === undefined || v.trim() === "") return fallback;
  return v.trim().toLowerCase() === "true" || v.trim() === "1";
}

function optionalInt(name: string, fallback: number): number {
  const v = process.env[name];
  if (v === undefined || v.trim() === "") return fallback;
  const n = Number.parseInt(v.trim(), 10);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`Invalid ${name}: expected a positive integer, got ${JSON.stringify(v)}`);
  }
  return n;
}

export interface Config {
  port: number;
  host: string;
  hmacSecret: string;
  hmacAlgorithm: string;
  agentId: string | null;
  gatekeeperVkHash: string;
  kurierApiKey: string | null;
  kurierApiUrl: string;
  kurierVkRegistered: boolean;
  requireKurierFinalized: boolean;
  kurierFinalizeTimeoutMs: number;
  kurierPollIntervalMs: number;
  responseDeadlineMs: number;
  timestampSkewMs: number;
  circuitsDir: string;
  dataDir: string;
  tlsKeyPath: string | null;
  tlsCertPath: string | null;
  skipSelfTest: boolean;
  /** Steal-the-VFY strategy params (raw env string; parsed at startup). */
  stealParamsRaw: string;
  /** Steal salt (decimal or 0x-hex); null = the Steal track is disabled. */
  stealSalt: string | null;
}

function loadConfig(): Config {
  const root = process.cwd();
  const cfg: Config = {
    port: optionalInt("PORT", 3000),
    host: optional("HOST", "0.0.0.0"),
    hmacSecret: required("AGENT_GAMES_HMAC_SECRET"),
    hmacAlgorithm: optional("HMAC_ALGORITHM", "sha256"),
    agentId: process.env.AGENT_ID?.trim() || null,
    gatekeeperVkHash: optional(
      "GATEKEEPER_VK_HASH",
      "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"
    ).toLowerCase(),
    kurierApiKey: process.env.KURIER_API_KEY?.trim() || null,
    kurierApiUrl: optional("KURIER_API_URL", "https://api.kurier.xyz/api/v1").replace(
      /\/$/,
      ""
    ),
    kurierVkRegistered: optionalBool("KURIER_VK_REGISTERED", true),
    requireKurierFinalized: optionalBool("REQUIRE_KURIER_FINALIZED", true),
    kurierFinalizeTimeoutMs: optionalInt("KURIER_FINALIZE_TIMEOUT_MS", 40_000),
    kurierPollIntervalMs: optionalInt("KURIER_POLL_INTERVAL_MS", 5_000),
    responseDeadlineMs: optionalInt("RESPONSE_DEADLINE_MS", 60_000),
    timestampSkewMs: optionalInt("TIMESTAMP_SKEW_MS", 300_000),
    circuitsDir: path.resolve(root, optional("CIRCUITS_DIR", "./circuits")),
    dataDir: path.resolve(root, optional("DATA_DIR", "./data")),
    tlsKeyPath: process.env.TLS_KEY_PATH?.trim() || null,
    tlsCertPath: process.env.TLS_CERT_PATH?.trim() || null,
    skipSelfTest: optionalBool("SKIP_SELF_TEST", false),
    stealParamsRaw: optional("STEAL_VFY_PARAMS", "8,18,8,0,0,0,0,0"),
    stealSalt: process.env.STEAL_VFY_SALT?.trim() || null,
  };

  if (!/^0x[0-9a-f]{64}$/.test(cfg.gatekeeperVkHash)) {
    throw new Error(
      `Invalid GATEKEEPER_VK_HASH: expected a 0x-prefixed 32-byte hex hash, got ${cfg.gatekeeperVkHash}`
    );
  }
  if (!["sha256", "sha512"].includes(cfg.hmacAlgorithm)) {
    throw new Error(
      `Invalid HMAC_ALGORITHM: expected "sha256" or "sha512", got ${cfg.hmacAlgorithm}`
    );
  }
  if ((cfg.tlsKeyPath === null) !== (cfg.tlsCertPath === null)) {
    throw new Error("TLS_KEY_PATH and TLS_CERT_PATH must be set together or not at all.");
  }
  if (cfg.kurierApiKey === null) {
    console.warn(
      "[config] KURIER_API_KEY is not set — Kurier submission is disabled. " +
        (cfg.requireKurierFinalized
          ? "In strict mode (REQUIRE_KURIER_FINALIZED=true) every APPROVE will flip to REJECT. "
          : "") +
        "Set a Kurier API key for scored rounds."
    );
  }
  return cfg;
}

export const config: Config = loadConfig();
