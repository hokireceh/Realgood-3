// Local Groth16 proving with snarkjs (wasm + zkey on disk).
// No network, no model: the proof is generated here and verified locally
// against the exported verification key before anything is returned.
import fs from "node:fs";
import path from "node:path";
import * as snarkjs from "snarkjs";
import type { CircuitInputs } from "./circuit";

export interface Groth16Proof {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
  protocol: string;
  curve: string;
}

export interface ProveResult {
  proof: Groth16Proof;
  publicSignals: string[];
}

export interface ProverArtifacts {
  wasm: string;
  zkey: string;
  vk: string;
  label: string;
}

export const GATEKEEPER_ARTIFACTS: ProverArtifacts = {
  wasm: "gatekeeper.wasm",
  zkey: "gatekeeper_final.zkey",
  vk: "gatekeeper.vk.json",
  label: "gatekeeper",
};

export const STEAL_ARTIFACTS: ProverArtifacts = {
  wasm: "vfy-policy.wasm",
  zkey: "vfy-policy_final.zkey",
  vk: "vfy-policy.vk.json",
  label: "vfy-policy",
};

/** The gatekeeper self-test input: an all-pass task (decision = 1). */
export const GATEKEEPER_SELF_TEST_INPUT: CircuitInputs = {
  minimum: 1000n,
  publicBalance: 1460n,
  expiryBlock: 8430000n,
  currentBlock: 8420000n,
  recipient: 3728908033n,
  conditionRecipient: 3728908033n,
  amount: 500n,
  maxTransfer: 1000n,
  taskId: 12345n,
  decision: 1,
  salt: 999n,
  registeredVkHash: BigInt(
    "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"
  ),
  proofVkHash: BigInt(
    "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"
  ),
};

/**
 * Convert a circuit input object to the plain JSON snarkjs expects:
 * bigints become decimal strings, arrays (e.g. strategyParams[8]) stay
 * arrays of decimal strings, everything else becomes a string.
 */
export function stringifyCircuitInput(input: object): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(input)) {
    if (typeof v === "bigint") {
      out[k] = v.toString();
    } else if (Array.isArray(v)) {
      out[k] = v.map((e) => (typeof e === "bigint" ? e.toString() : String(e)));
    } else {
      out[k] = String(v);
    }
  }
  return out;
}

export class Prover {
  private readonly wasmPath: string;
  private readonly zkeyPath: string;
  private readonly vkPath: string;
  private readonly label: string;
  private vk: Record<string, unknown> | null = null;

  constructor(circuitsDir: string, artifacts: ProverArtifacts = GATEKEEPER_ARTIFACTS) {
    this.wasmPath = path.join(circuitsDir, artifacts.wasm);
    this.zkeyPath = path.join(circuitsDir, artifacts.zkey);
    this.vkPath = path.join(circuitsDir, artifacts.vk);
    this.label = artifacts.label;
    for (const [label, p] of [
      ["wasm", this.wasmPath],
      ["zkey", this.zkeyPath],
      ["verification key", this.vkPath],
    ] as const) {
      if (!fs.existsSync(p)) {
        throw new Error(
          `Missing ${this.label} ${label} at ${p}. Download it from https://agentgames.zkverify.io/build (see README).`
        );
      }
    }
  }

  private loadVk(): Record<string, unknown> {
    if (!this.vk) {
      this.vk = JSON.parse(fs.readFileSync(this.vkPath, "utf8")) as Record<
        string,
        unknown
      >;
    }
    return this.vk;
  }

  /** Generate a Groth16 proof for the given circuit inputs. */
  async prove(input: object): Promise<ProveResult> {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      stringifyCircuitInput(input),
      this.wasmPath,
      this.zkeyPath
    );
    return { proof: proof as Groth16Proof, publicSignals: publicSignals as string[] };
  }

  /** Verify a proof locally against the exported verification key. */
  async verifyLocally(proof: Groth16Proof, publicSignals: string[]): Promise<boolean> {
    const vk = this.loadVk();
    return snarkjs.groth16.verify(vk, publicSignals, proof);
  }

  /**
   * Startup self-test: prove + verify a known-good input. If this fails,
   * the artifacts are broken and the process must not serve tasks.
   * Defaults to the gatekeeper all-pass input (decision public signal
   * must be 1); pass a different input + signal check for other circuits.
   */
  async selfTest(
    input: object = GATEKEEPER_SELF_TEST_INPUT,
    signalCheck: (signals: string[]) => void = (signals) => {
      if (signals[11] !== "1") {
        throw new Error(
          `${this.label} self-test failed: decision public signal is not 1.`
        );
      }
    }
  ): Promise<void> {
    const { proof, publicSignals } = await this.prove(input);
    const ok = await this.verifyLocally(proof, publicSignals);
    if (!ok) {
      throw new Error(`${this.label} self-test failed: proof did not verify locally.`);
    }
    signalCheck(publicSignals);
  }
}
