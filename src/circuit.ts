// Gatekeeper circuit — facts verified empirically against the shipped
// artifacts (gatekeeper.wasm / gatekeeper_final.zkey), NOT assumed:
//
//   * Groth16 / BN128, Circom 2.x. Verification key hash (registered on
//     zkVerify mainnet):
//     0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
//   * 13 input signals (found by probing the wasm's FNV signal map):
//       minimum, publicBalance, expiryBlock, currentBlock, recipient,
//       conditionRecipient, amount, maxTransfer, taskId, decision, salt,
//       registeredVkHash, proofVkHash
//   * Only `salt` is private. Everything else is a public input.
//   * 13 public signals, in order (read back from a computed witness):
//       [0]  binding            = Poseidon(salt, taskId)   (circuit output)
//       [1]  registeredVkHash   (mod FIELD_PRIME)
//       [2]  proofVkHash        (mod FIELD_PRIME)
//       [3]  minimum
//       [4]  publicBalance
//       [5]  expiryBlock
//       [6]  currentBlock
//       [7]  recipient          (address as a field element)
//       [8]  conditionRecipient (address as a field element)
//       [9]  amount
//       [10] maxTransfer
//       [11] decision           (1 = APPROVE, 0 = REJECT)
//       [12] taskId
//   * Constraints (verified by witness experiments): decision = 1 is only
//     provable when ALL of these hold —
//       publicBalance >= minimum,
//       recipient == conditionRecipient,
//       amount <= maxTransfer,
//       currentBlock <= expiryBlock,
//       proofVkHash == registeredVkHash.
//     decision = 0 is always provable, whatever the other values are.
//   * The binding (public signal 0) is the proof reference: it uniquely
//     binds one proof to one task + one salt. A reused binding = replay.
//
// The ONE assumption in this file is how a string task_id maps to the
// `taskId` field element: keccak256(utf8(task_id)) mod FIELD_PRIME — the
// standard EVM-world string-to-field encoding (the platform's own docs use
// keccak256 + viem for the same purpose). If the platform ever documents a
// different encoding, change ONLY `encodeTaskId` below.
import crypto from "node:crypto";
import { ethers } from "ethers";

export const FIELD_PRIME: bigint = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

export const GATEKEEPER_CIRCUIT = "gatekeeper";
export const GATEKEEPER_PROTOCOL = "groth16";
export const GATEKEEPER_CURVE = "bn128";

/** Public-signal layout, by index. Index 11 is the decision. */
export const PUBLIC_SIGNAL_LAYOUT = [
  "binding",
  "registeredVkHash",
  "proofVkHash",
  "minimum",
  "publicBalance",
  "expiryBlock",
  "currentBlock",
  "recipient",
  "conditionRecipient",
  "amount",
  "maxTransfer",
  "decision",
  "taskId",
] as const;

export const PUBLIC_SIGNAL_COUNT = PUBLIC_SIGNAL_LAYOUT.length;
export const DECISION_SIGNAL_INDEX = 11;
export const BINDING_SIGNAL_INDEX = 0;

/** Reduce an arbitrary bigint into the BN128 scalar field (as snarkjs does). */
export function toField(value: bigint): bigint {
  const r = value % FIELD_PRIME;
  return r < 0n ? r + FIELD_PRIME : r;
}

/**
 * Canonical encoding of a string task_id to a field element.
 * See the header comment: this is the single encoding assumption.
 */
export function encodeTaskId(taskId: string): bigint {
  const digest = ethers.keccak256(ethers.toUtf8Bytes(taskId));
  return toField(BigInt(digest));
}

/** An Ethereum address as a field element (checksummed, then BigInt). */
export function encodeAddress(address: string): bigint {
  return BigInt(ethers.getAddress(address));
}

/** A 0x-prefixed 32-byte hash (e.g. a vk hash) as a field element. */
export function encodeVkHash(hash: string): bigint {
  if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) {
    throw new Error(`Invalid 32-byte hash: ${hash}`);
  }
  return toField(BigInt(hash));
}

/** A fresh, unpredictable private salt (one per task, never reused). */
export function freshSalt(): bigint {
  let s = 0n;
  while (s === 0n) {
    s = toField(BigInt("0x" + crypto.randomBytes(32).toString("hex")));
  }
  return s;
}

export interface CircuitInputs {
  minimum: bigint;
  publicBalance: bigint;
  expiryBlock: bigint;
  currentBlock: bigint;
  recipient: bigint;
  conditionRecipient: bigint;
  amount: bigint;
  maxTransfer: bigint;
  taskId: bigint;
  decision: 0 | 1;
  salt: bigint;
  registeredVkHash: bigint;
  proofVkHash: bigint;
}

/** Build the exact input object snarkjs fullProve expects. */
export function buildCircuitInput(args: {
  minimum: bigint;
  publicBalance: bigint;
  expiryBlock: bigint;
  currentBlock: bigint;
  recipient: bigint;
  conditionRecipient: bigint;
  amount: bigint;
  maxTransfer: bigint;
  taskId: bigint;
  decision: 0 | 1;
  salt: bigint;
  registeredVkHash: bigint;
  proofVkHash: bigint;
}): CircuitInputs {
  return { ...args };
}

/** Typed view of the 13 public signals, in circuit order. */
export interface PublicSignals {
  binding: string;
  registeredVkHash: string;
  proofVkHash: string;
  minimum: string;
  publicBalance: string;
  expiryBlock: string;
  currentBlock: string;
  recipient: string;
  conditionRecipient: string;
  amount: string;
  maxTransfer: string;
  decision: string;
  taskId: string;
}

export function parsePublicSignals(signals: string[]): PublicSignals {
  if (!Array.isArray(signals) || signals.length !== PUBLIC_SIGNAL_COUNT) {
    throw new Error(
      `Expected ${PUBLIC_SIGNAL_COUNT} public signals, got ${signals?.length}`
    );
  }
  const [
    binding,
    registeredVkHash,
    proofVkHash,
    minimum,
    publicBalance,
    expiryBlock,
    currentBlock,
    recipient,
    conditionRecipient,
    amount,
    maxTransfer,
    decision,
    taskId,
  ] = signals;
  return {
    binding,
    registeredVkHash,
    proofVkHash,
    minimum,
    publicBalance,
    expiryBlock,
    currentBlock,
    recipient,
    conditionRecipient,
    amount,
    maxTransfer,
    decision,
    taskId,
  };
}
