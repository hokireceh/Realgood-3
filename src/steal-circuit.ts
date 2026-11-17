// Steal-the-VFY circuit — facts verified empirically against the shipped
// artifacts (vfy-policy.wasm / vfy-policy_final.zkey), NOT assumed.
//
//   * Groth16 / BN128, Circom 2.x. Verification key hash (from
//     https://agentgames.zkverify.io/api/circuit-info, mainnet):
//     0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047
//   * 10 input signals (found by probing the wasm's FNV signal map — the
//     same method that found the gatekeeper's 13):
//       matchId, turnNumber, action, amount, selfBalance, opponentBalance,
//       commitment, circuitVersion, salt, strategyParams[8]
//     Only `salt` and `strategyParams` are private. Everything else is a
//     public input.
//   * 9 public signals, in order (read back from computed witnesses):
//       [0]  binding          = Poseidon(matchId, turnNumber, circuitVersion)
//       [1]  commitment       = Poseidon(strategyParams[0..7], salt)
//       [2]  matchId          (UUID hex, hyphens stripped, as a field element)
//       [3]  turnNumber
//       [4]  selfBalance
//       [5]  opponentBalance
//       [6]  action           (0 = HOLD, 1 = FORTIFY, 2 = EXTRACT)
//       [7]  amount
//       [8]  circuitVersion   (1; the circuit does NOT constrain it — the
//                              platform checks it against the registration)
//   * Constraints (verified by witness experiments, 2026-11-16; assert line
//     numbers are from the Circom template VfyPolicyProof_154):
//       - commitment == Poseidon(strategyParams, salt)      (line 72)
//       - params[4..7] == 0                                 (lines 75-78)
//       - params[0] in 1..10                                (lines 90, 95)
//       - params[3] in {0, 1}                               (line 98)
//       - policy (line 140): the action MUST be the one the policy selects:
//           selfBalance < params[1]  -> FORTIFY
//           opponentBalance <= params[2] -> HOLD   (INCLUSIVE — a strict
//             `<` here is wrong; see src/policy.ts)
//           params[3] == 1           -> HOLD (never extract)
//           otherwise                -> EXTRACT
//       - EXTRACT amount == params[0]                       (line 149)
//       - HOLD / FORTIFY amount == 0                        (line 153)
//     params[1] and params[2] have no circuit range check (any
//     non-negative field element proves); the policy module validates
//     them to a sane range anyway.
//   * The binding does NOT depend on the salt, the commitment, the
//     balances, or the action — only (matchId, turnNumber, circuitVersion).
//     It is a per-turn identifier: one valid proof slot per
//     (match, turn, version). A replayed turn produces the identical
//     proof, so the agent answers retries with the identical response
//     (deterministic idempotency key) and lets the platform dedupe.
//
// The publicInputsHash in the response is keccak256 over 8 x 32-byte
// big-endian words — commitment, matchId, turnNumber, selfBalance,
// opponentBalance, action, amount, circuitVersion — in that order. That
// formula comes from a working third-party implementation
// (DaddyUnikii/zkverify-agent, whose proofs verify against this circuit);
// the platform has not published the formula, so it is an auxiliary audit
// pointer only — the proof + public_signals are the primary verification.
import { buildPoseidon } from "circomlibjs";
import { ethers } from "ethers";
import { FIELD_PRIME, toField } from "./circuit";

export const STEAL_VK_HASH =
  "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047";

export const STEAL_CIRCUIT_VERSION = 1n;
export const STEAL_POLICY_PROOF_VERSION = "v1";
export const STEAL_EVENT_ID = "steal-the-vfy";

export const STEAL_PUBLIC_SIGNAL_COUNT = 9;

/** Public-signal layout, by index. Index 6 is the action. */
export const STEAL_PUBLIC_SIGNAL_LAYOUT = [
  "binding",
  "commitment",
  "matchId",
  "turnNumber",
  "selfBalance",
  "opponentBalance",
  "action",
  "amount",
  "circuitVersion",
] as const;

export const STEAL_BINDING_SIGNAL_INDEX = 0;
export const STEAL_ACTION_SIGNAL_INDEX = 6;

export const STEAL_ACTION_CODE = {
  HOLD: 0n,
  FORTIFY: 1n,
  EXTRACT: 2n,
} as const;

export type StealActionType = keyof typeof STEAL_ACTION_CODE;

let poseidonPromise: Promise<Awaited<ReturnType<typeof buildPoseidon>>> | null = null;

function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

/**
 * The strategy commitment: Poseidon over the 8 strategy parameters plus
 * the private salt. This is the value registered in the dashboard
 * ("Commitment hash"). It hides the parameters while binding the agent
 * to them — the circuit re-derives it from the private inputs.
 */
export async function computeCommitment(
  params: readonly bigint[],
  salt: bigint
): Promise<{ decimal: string; hex: string }> {
  if (params.length !== 8) {
    throw new Error(`computeCommitment: expected 8 strategy params, got ${params.length}`);
  }
  const poseidon = await getPoseidon();
  const hash = poseidon.F.toObject(poseidon([...params, salt]));
  return {
    decimal: hash.toString(),
    hex: ethers.toBeHex(hash, 32),
  };
}

/** The per-turn binding (public signal 0). */
export async function computeBinding(
  matchId: bigint,
  turnNumber: bigint,
  circuitVersion: bigint = STEAL_CIRCUIT_VERSION
): Promise<bigint> {
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([matchId, turnNumber, circuitVersion]));
}

/**
 * Canonical encoding of a match id to a field element: strip a 0x prefix
 * and any hyphens (UUID form), then interpret the remaining hex.
 * Fails closed if the value does not fit in the BN128 scalar field.
 */
export function encodeMatchId(matchId: string): bigint {
  const hex = matchId.replace(/^0x/i, "").replace(/-/g, "");
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`Invalid matchId: expected hex or UUID, got ${JSON.stringify(matchId)}`);
  }
  const value = BigInt("0x" + hex);
  if (value >= FIELD_PRIME) {
    throw new Error(
      `Invalid matchId: value does not fit in the BN128 scalar field (${matchId})`
    );
  }
  return value;
}

/**
 * Parse the strategy salt from env: decimal digits or a 0x-prefixed hex
 * value. Must be non-zero and fit in the BN128 scalar field. The salt is
 * the private randomness that hides the strategy parameters inside the
 * commitment — it must be unpredictable and must never be shared.
 */
export function parseSalt(raw: string): bigint {
  const v = raw.trim();
  let salt: bigint;
  if (/^0x[0-9a-fA-F]+$/.test(v)) {
    salt = BigInt(v);
  } else if (/^\d+$/.test(v)) {
    salt = BigInt(v);
  } else {
    throw new Error(
      `Invalid STEAL_VFY_SALT: expected decimal digits or 0x-hex, got ${JSON.stringify(raw)}`
    );
  }
  if (salt === 0n) {
    throw new Error("Invalid STEAL_VFY_SALT: must be non-zero");
  }
  if (salt >= FIELD_PRIME) {
    throw new Error("Invalid STEAL_VFY_SALT: does not fit in the BN128 scalar field");
  }
  return salt;
}

export interface StealCircuitInputs {
  commitment: bigint;
  matchId: bigint;
  turnNumber: bigint;
  selfBalance: bigint;
  opponentBalance: bigint;
  action: bigint;
  amount: bigint;
  circuitVersion: bigint;
  salt: bigint;
  strategyParams: bigint[];
}

/** Build the exact input object snarkjs fullProve expects. */
export function buildStealCircuitInput(args: StealCircuitInputs): StealCircuitInputs {
  if (args.strategyParams.length !== 8) {
    throw new Error(
      `buildStealCircuitInput: expected 8 strategy params, got ${args.strategyParams.length}`
    );
  }
  return { ...args };
}

/** Typed view of the 9 public signals, in circuit order. */
export interface StealPublicSignals {
  binding: string;
  commitment: string;
  matchId: string;
  turnNumber: string;
  selfBalance: string;
  opponentBalance: string;
  action: string;
  amount: string;
  circuitVersion: string;
}

export function parseStealPublicSignals(signals: string[]): StealPublicSignals {
  if (!Array.isArray(signals) || signals.length !== STEAL_PUBLIC_SIGNAL_COUNT) {
    throw new Error(
      `Expected ${STEAL_PUBLIC_SIGNAL_COUNT} public signals, got ${signals?.length}`
    );
  }
  const [
    binding,
    commitment,
    matchId,
    turnNumber,
    selfBalance,
    opponentBalance,
    action,
    amount,
    circuitVersion,
  ] = signals;
  return {
    binding,
    commitment,
    matchId,
    turnNumber,
    selfBalance,
    opponentBalance,
    action,
    amount,
    circuitVersion,
  };
}

/**
 * Auxiliary audit hash for the response (see the header comment): keccak256
 * over 8 x 32-byte big-endian words in public-signal order (minus the
 * binding). The platform computes this independently from the game state;
 * a mismatch is its signal that the agent's public inputs diverged.
 */
export function computePublicInputsHash(args: {
  commitment: bigint;
  matchId: bigint;
  turnNumber: bigint;
  selfBalance: bigint;
  opponentBalance: bigint;
  action: bigint;
  amount: bigint;
  circuitVersion: bigint;
}): string {
  const words = [
    args.commitment,
    args.matchId,
    args.turnNumber,
    args.selfBalance,
    args.opponentBalance,
    args.action,
    args.amount,
    args.circuitVersion,
  ];
  return ethers.keccak256(ethers.concat(words.map((w) => ethers.toBeHex(toField(w), 32))));
}
