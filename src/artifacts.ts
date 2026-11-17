// Circuit artifacts — fetched, not committed.
//
// The binary proving artifacts (*.wasm, *_final.zkey) are NOT stored in git:
// the GitHub connector used to publish this repo cannot push binary files,
// and the platform serves the exact same bytes at stable URLs. Instead the
// service downloads any missing (or hash-mismatched) artifact at startup
// from https://agentgames.zkverify.io/circuits/ and verifies its SHA-256
// against the pinned hashes below — verified byte-identical against the
// platform downloads on 2026-11-16. A failed download or a hash mismatch
// is fatal: the process must not serve tasks with untrusted artifacts.
//
// The *.vk.json files ARE committed (plain JSON text) — the service needs
// them for Kurier VK registration and local proof verification.
//
// Manual fetch: `npm run fetch-circuits` (or `npx tsx src/artifacts.ts`).
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const BASE_URL = "https://agentgames.zkverify.io/circuits";

export interface CircuitArtifact {
  file: string;
  sha256: string;
}

/** Binary artifacts, with SHA-256 pinned to the verified platform downloads. */
export const CIRCUIT_ARTIFACTS: CircuitArtifact[] = [
  {
    file: "gatekeeper.wasm",
    sha256:
      "be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f",
  },
  {
    file: "gatekeeper_final.zkey",
    sha256:
      "adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d",
  },
  {
    file: "vfy-policy.wasm",
    sha256:
      "bc0998250d2baf75b89deef5306867ffa7085a08d4f7d2caf0dd63a060b134d2",
  },
  {
    file: "vfy-policy_final.zkey",
    sha256:
      "f9666a1655279ef27f7fee6d535ac8aa9e39286ac40ff6279fea87c21ab6ce41",
  },
];

function sha256File(p: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
}

async function download(url: string, destTmp: string): Promise<void> {
  let lastErr: unknown = null;
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const buf = Buffer.from(await res.arrayBuffer());
      fs.writeFileSync(destTmp, buf);
      return;
    } catch (err) {
      lastErr = err;
      console.warn(
        `[artifacts] download attempt ${attempt} failed for ${url}: ${(err as Error).message}`
      );
    }
  }
  throw new Error(
    `Failed to download ${url} after 2 attempts: ${(lastErr as Error).message}`
  );
}

/**
 * Ensure every binary circuit artifact exists in `circuitsDir` and matches
 * its pinned SHA-256. Downloads + verifies any missing or mismatched file.
 * Throws on any failure (fail-closed: never run with untrusted artifacts).
 */
export async function ensureCircuits(circuitsDir: string): Promise<void> {
  fs.mkdirSync(circuitsDir, { recursive: true });
  for (const art of CIRCUIT_ARTIFACTS) {
    const dest = path.join(circuitsDir, art.file);
    if (fs.existsSync(dest) && sha256File(dest) === art.sha256) continue;
    if (fs.existsSync(dest)) {
      console.warn(
        `[artifacts] ${art.file} hash mismatch — re-downloading from platform`
      );
    } else {
      console.log(`[artifacts] ${art.file} missing — downloading from platform`);
    }
    const tmp = `${dest}.tmp-${process.pid}`;
    try {
      await download(`${BASE_URL}/${art.file}`, tmp);
      if (sha256File(tmp) !== art.sha256) {
        throw new Error(
          `SHA-256 mismatch for downloaded ${art.file} (expected ${art.sha256})`
        );
      }
      fs.renameSync(tmp, dest);
      console.log(`[artifacts] ${art.file} verified (sha256 ${art.sha256.slice(0, 12)}…)`);
    } finally {
      if (fs.existsSync(tmp)) fs.unlinkSync(tmp);
    }
  }
}

// CLI: `npx tsx src/artifacts.ts [circuits-dir]` (default: ./circuits).
// (CommonJS build, so no import.meta — detect direct invocation by argv.)
const invokedAsCli =
  !!process.argv[1] && /(^|\/)artifacts\.(ts|js)$/.test(process.argv[1]);
if (invokedAsCli) {
  const dir = path.resolve(process.argv[2] ?? "./circuits");
  ensureCircuits(dir)
    .then(() => console.log(`[artifacts] all ${CIRCUIT_ARTIFACTS.length} artifacts verified in ${dir}`))
    .catch((err) => {
      console.error("[artifacts] fatal:", (err as Error).message);
      process.exit(1);
    });
}
