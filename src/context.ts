// AgentContext builder — shared by the long-running server
// (src/server-main.ts) locally and the Vercel functions (api/agent.ts,
// api/health.ts). Built lazily once per process and cached; a failed
// build is retried on the next call (no poisoned cache).
//
// Serverless note: on Vercel, CIRCUITS_DIR / DATA_DIR point at /tmp (set
// via dashboard env). Binary artifacts are downloaded there at cold start
// by ensureCircuits (SHA-256 verified); the *.vk.json files ship with the
// function bundle (vercel.json includeFiles) and are copied into the
// circuits dir when missing. The proof store + Steal response cache are
// per-instance (ephemeral) on serverless — replay protection still holds
// within an instance; cross-instance replays rely on the platform's own
// task_id idempotency (same task_id => same deterministic decision). See
// AGENTS.md.
import fs from "node:fs";
import path from "node:path";
import { config } from "./config";
import { ensureCircuits } from "./artifacts";
import { Prover, STEAL_ARTIFACTS } from "./prover";
import { ProofStore } from "./store";
import { KurierClient } from "./kurier";
import { loadVkJson, type AgentContext } from "./handler";
import { parseStrategyParams } from "./policy";
import {
  buildStealCircuitInput,
  computeCommitment,
  encodeMatchId,
  parseSalt,
  STEAL_ACTION_CODE,
  STEAL_CIRCUIT_VERSION,
} from "./steal-circuit";
import type { StealContext } from "./steal-handler";
// Bundled copies of circuits/*.vk.json (same bytes, kept in sync — the VKs
// are registered on mainnet and never change). Statically imported so the
// Vercel bundler includes them in the function; written into circuitsDir
// at init when missing (on Vercel the binaries live in /tmp, the vk.json
// files do not ship with them).
import gatekeeperVkJson from "./gatekeeper.vk.json";
import vfyPolicyVkJson from "./vfy-policy.vk.json";

const VK_JSON_FILES = [
  { file: "gatekeeper.vk.json", json: gatekeeperVkJson },
  { file: "vfy-policy.vk.json", json: vfyPolicyVkJson },
] as const;

/**
 * Make sure the *.vk.json files exist in `circuitsDir`. Locally they are
 * committed next to the binaries; on Vercel the binaries are downloaded
 * to /tmp at runtime, so the bundled vk.json copies are written there
 * when missing.
 */
function ensureVkJson(circuitsDir: string): void {
  for (const { file, json } of VK_JSON_FILES) {
    const dest = path.join(circuitsDir, file);
    if (fs.existsSync(dest)) continue;
    fs.writeFileSync(dest, JSON.stringify(json, null, 2));
    console.log(`[gatekeeper] wrote bundled ${file} into ${circuitsDir}`);
  }
}

let ctxPromise: Promise<AgentContext> | null = null;

export function getAgentContext(): Promise<AgentContext> {
  if (!ctxPromise) {
    ctxPromise = buildAgentContext().catch((err) => {
      ctxPromise = null;
      throw err;
    });
  }
  return ctxPromise;
}

async function buildAgentContext(): Promise<AgentContext> {
  // Binary circuit artifacts are fetched (not committed) — download any
  // missing/mismatched file from the platform and verify its SHA-256.
  await ensureCircuits(config.circuitsDir);
  ensureVkJson(config.circuitsDir);

  const prover = new Prover(config.circuitsDir);
  const store = new ProofStore(config.dataDir);
  console.log(`[gatekeeper] proof store: ${store.count} prior record(s) loaded`);

  if (!config.skipSelfTest) {
    const t0 = Date.now();
    await prover.selfTest();
    console.log(`[gatekeeper] prover self-test passed (${Date.now() - t0}ms)`);
  } else {
    console.warn("[gatekeeper] SKIP_SELF_TEST=1 — prover self-test skipped");
  }

  const vkJson = loadVkJson(config.circuitsDir);

  // Steal-the-VFY: optional track. When STEAL_VFY_SALT is set, the
  // strategy is validated, the commitment is computed, and a second
  // prover (vfy-policy artifacts) runs its own self-test. The commitment
  // hex printed here is what gets registered in the dashboard — changing
  // params or salt afterwards requires re-registration.
  let steal: StealContext | null = null;
  if (config.stealSalt !== null) {
    const params = parseStrategyParams(config.stealParamsRaw);
    const salt = parseSalt(config.stealSalt);
    const commitment = await computeCommitment(params, salt);
    const stealProver = new Prover(config.circuitsDir, STEAL_ARTIFACTS);
    if (!config.skipSelfTest) {
      const t0 = Date.now();
      const selfTestInput = buildStealCircuitInput({
        commitment: BigInt(commitment.decimal),
        matchId: encodeMatchId("00000000-0000-0000-0000-000000000001"),
        turnNumber: 1n,
        selfBalance: 100n,
        opponentBalance: 100n,
        action: STEAL_ACTION_CODE.EXTRACT,
        amount: params[0],
        circuitVersion: STEAL_CIRCUIT_VERSION,
        salt,
        strategyParams: params,
      });
      await stealProver.selfTest(selfTestInput, (signals) => {
        if (signals[6] !== "2" || signals[8] !== "1") {
          throw new Error(
            "vfy-policy self-test failed: expected an EXTRACT proof (action 2, circuitVersion 1)."
          );
        }
      });
      console.log(`[steal] prover self-test passed (${Date.now() - t0}ms)`);
    } else {
      console.warn("[steal] SKIP_SELF_TEST=1 — vfy-policy self-test skipped");
    }
    console.log(`[steal] strategy commitment (register in dashboard): ${commitment.hex}`);
    console.log(`[steal] params: ${params.join(",")} — changing them requires a new commitment + re-registration`);
    steal = {
      params,
      salt,
      commitmentHex: commitment.hex,
      commitmentDecimal: commitment.decimal,
      prover: stealProver,
    };
  } else {
    console.warn(
      "[steal] STEAL_VFY_SALT is not set — Steal-the-VFY turns will return 503. " +
        "Set STEAL_VFY_SALT (+ optionally STEAL_VFY_PARAMS) to enable the track."
    );
  }

  let kurier: KurierClient | null = null;
  let kurierVkHash = config.gatekeeperVkHash;
  if (config.kurierApiKey !== null) {
    kurier = new KurierClient(config.kurierApiUrl, config.kurierApiKey);
    if (!config.kurierVkRegistered) {
      console.log("[gatekeeper] registering verification key with Kurier…");
      kurierVkHash = await kurier.registerVk(vkJson);
      console.log(`[gatekeeper] Kurier vkHash: ${kurierVkHash}`);
    } else {
      console.log(`[gatekeeper] Kurier enabled (vk already registered): ${kurierVkHash}`);
    }
  } else {
    console.warn("[gatekeeper] Kurier disabled — proofs are local-only");
  }

  return {
    config,
    prover,
    store,
    kurier,
    kurierVkHash,
    vkJson,
    steal,
    stealResponses: new Map(),
  };
}
