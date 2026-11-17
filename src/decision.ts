// Task envelope parsing + the deterministic decision.
// The final call is made HERE, in plain code — never by a language model.
// APPROVE only when EVERY check passes; otherwise REJECT with a reason_code.
import { ethers } from "ethers";
import {
  encodeAddress,
  encodeTaskId,
  encodeVkHash,
  toField,
} from "./circuit";

export const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
export const PREFLIGHT_TYPE = "agent-games.preflight.v1";

export type Decision = "APPROVE" | "REJECT";

export type ReasonCode =
  | "OK"
  | "VK_SUBSTITUTION"
  | "VK_MISMATCH"
  | "BELOW_MINIMUM"
  | "RECIPIENT_MISMATCH"
  | "AMOUNT_EXCEEDS_MAX"
  | "EXPIRED"
  | "TIMESTAMP_INVALID"
  | "TASK_EXPIRED"
  | "TASK_REPLAY"
  | "PROOF_REUSED"
  | "PROOF_FAILED"
  | "KURIER_NOT_FINALIZED"
  | "KURIER_ERROR"
  | "INVALID_TASK"
  | "TIMEOUT"
  | "INTERNAL_ERROR";

export interface GatekeeperInput {
  registered_vk: string;
  proof_vk: string;
  minimum: string;
  public_balance: string;
  expiry_block: number;
  current_block: number;
  recipient: string;
  condition_recipient: string;
  amount: string;
  max_transfer: string;
  proof_tx: string | null;
}

export interface GatekeeperTask {
  type: string;
  task_id: string;
  mode: string;
  issued_at: string | number | null;
  deadline_at: string | number | null;
  input: GatekeeperInput;
}

export interface PreflightRequest {
  type: string;
  agent_id: string | null;
  issued_at: string | number | null;
  nonce: string | null;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function asNonEmptyString(v: unknown): string | null {
  return typeof v === "string" && v.trim() !== "" ? v.trim() : null;
}

function asDecimalString(v: unknown): string | null {
  if (typeof v === "number" && Number.isInteger(v) && v >= 0) return String(v);
  if (typeof v === "string" && /^\d+$/.test(v.trim())) return v.trim();
  return null;
}

function asBlockNumber(v: unknown): number | null {
  if (typeof v === "number" && Number.isInteger(v) && v >= 0) return v;
  if (typeof v === "string" && /^\d+$/.test(v.trim())) {
    const n = Number(v.trim());
    return Number.isSafeInteger(n) ? n : null;
  }
  return null;
}

function asAddress(v: unknown): string | null {
  if (typeof v !== "string") return null;
  try {
    return ethers.getAddress(v.trim());
  } catch {
    return null;
  }
}

function asHash(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const s = v.trim().toLowerCase();
  return /^0x[0-9a-f]{64}$/.test(s) ? s : null;
}

/** Parse + validate a task envelope. Returns null when it is malformed. */
export function parseTaskEnvelope(body: unknown): GatekeeperTask | null {
  if (!isRecord(body)) return null;
  if (body.type !== TASK_TYPE) return null;
  const taskId = asNonEmptyString(body.task_id);
  if (!taskId) return null;
  if (!isRecord(body.input)) return null;
  const input = body.input;

  const registeredVk = asHash(input.registered_vk);
  const proofVk = asHash(input.proof_vk);
  const minimum = asDecimalString(input.minimum);
  const publicBalance = asDecimalString(input.public_balance);
  const expiryBlock = asBlockNumber(input.expiry_block);
  const currentBlock = asBlockNumber(input.current_block);
  const recipient = asAddress(input.recipient);
  const conditionRecipient = asAddress(input.condition_recipient);
  const amount = asDecimalString(input.amount);
  const maxTransfer = asDecimalString(input.max_transfer);
  const proofTx =
    typeof input.proof_tx === "string" && input.proof_tx.trim() !== ""
      ? input.proof_tx.trim()
      : null;

  if (
    !registeredVk ||
    !proofVk ||
    minimum === null ||
    publicBalance === null ||
    expiryBlock === null ||
    currentBlock === null ||
    !recipient ||
    !conditionRecipient ||
    amount === null ||
    maxTransfer === null
  ) {
    return null;
  }

  return {
    type: TASK_TYPE,
    task_id: taskId,
    mode: asNonEmptyString(body.mode) ?? "competition",
    issued_at: (body.issued_at as string | number | null) ?? null,
    deadline_at: (body.deadline_at as string | number | null) ?? null,
    input: {
      registered_vk: registeredVk,
      proof_vk: proofVk,
      minimum,
      public_balance: publicBalance,
      expiry_block: expiryBlock,
      current_block: currentBlock,
      recipient,
      condition_recipient: conditionRecipient,
      amount,
      max_transfer: maxTransfer,
      proof_tx: proofTx,
    },
  };
}

/** Parse + validate a preflight request. Returns null when malformed. */
export function parsePreflight(body: unknown): PreflightRequest | null {
  if (!isRecord(body)) return null;
  if (body.type !== PREFLIGHT_TYPE) return null;
  return {
    type: PREFLIGHT_TYPE,
    agent_id: asNonEmptyString(body.agent_id),
    issued_at: (body.issued_at as string | number | null) ?? null,
    nonce: asNonEmptyString(body.nonce),
  };
}

/** Parse a timestamp that may be an ISO string, epoch ms, or epoch seconds. */
export function parseTimestamp(v: string | number | null): number | null {
  if (v === null || v === undefined) return null;
  if (typeof v === "number") {
    // Heuristic: seconds (< 1e12) vs milliseconds.
    return v < 1e12 ? v * 1000 : v;
  }
  const ms = Date.parse(v);
  return Number.isFinite(ms) ? ms : null;
}

export interface CheckContext {
  /** Expected registered VK hash (lowercase 0x hash). */
  expectedVkHash: string;
  /** Task ids already answered (replay protection). */
  hasTaskId: (taskId: string) => boolean;
  nowMs: number;
  timestampSkewMs: number;
}

export interface CheckResult {
  decision: Decision;
  reasonCode: ReasonCode;
}

/**
 * The deterministic safety checklist, in order. The FIRST failing check
 * decides the rejection reason. Every check is a pure function of the task
 * and the expected VK — no network, no model, no randomness.
 */
export function evaluateChecks(task: GatekeeperTask, ctx: CheckContext): CheckResult {
  const input = task.input;

  // 1. The verification key must be the registered one (VK substitution).
  if (input.registered_vk !== ctx.expectedVkHash) {
    return { decision: "REJECT", reasonCode: "VK_SUBSTITUTION" };
  }
  // 2. The proof's VK must match the registered VK.
  if (input.proof_vk !== input.registered_vk) {
    return { decision: "REJECT", reasonCode: "VK_MISMATCH" };
  }
  // 3. A task id must never be answered twice (replay protection).
  if (ctx.hasTaskId(task.task_id)) {
    return { decision: "REJECT", reasonCode: "TASK_REPLAY" };
  }
  // 4. Task signature timestamp must be fresh and the task not expired.
  const issuedMs = parseTimestamp(task.issued_at);
  const deadlineMs = parseTimestamp(task.deadline_at);
  if (issuedMs !== null && Math.abs(ctx.nowMs - issuedMs) > ctx.timestampSkewMs) {
    return { decision: "REJECT", reasonCode: "TIMESTAMP_INVALID" };
  }
  if (deadlineMs !== null && ctx.nowMs > deadlineMs) {
    return { decision: "REJECT", reasonCode: "TASK_EXPIRED" };
  }
  // 5. Public balance must meet the required threshold.
  if (BigInt(input.public_balance) < BigInt(input.minimum)) {
    return { decision: "REJECT", reasonCode: "BELOW_MINIMUM" };
  }
  // 6. The recipient must be exactly the condition's recipient.
  if (input.recipient.toLowerCase() !== input.condition_recipient.toLowerCase()) {
    return { decision: "REJECT", reasonCode: "RECIPIENT_MISMATCH" };
  }
  // 7. The amount must not exceed the maximum transfer.
  if (BigInt(input.amount) > BigInt(input.max_transfer)) {
    return { decision: "REJECT", reasonCode: "AMOUNT_EXCEEDS_MAX" };
  }
  // 8. The transfer must not be past its expiry block.
  if (input.current_block > input.expiry_block) {
    return { decision: "REJECT", reasonCode: "EXPIRED" };
  }

  return { decision: "APPROVE", reasonCode: "OK" };
}

/**
 * The circuit's own verdict: 1 iff ALL FIVE circuit conditions hold —
 *   publicBalance >= minimum,
 *   recipient == conditionRecipient,
 *   amount <= maxTransfer,
 *   currentBlock <= expiryBlock,
 *   proofVkHash == registeredVkHash.
 * The circuit constrains `decision == expected`, so a valid proof exists
 * ONLY for this decision. This is a pure function of the task, computed
 * here so the handler knows up front whether a proof is even possible.
 * (Non-circuit rejections — VK substitution, timestamps, replay — can
 * therefore carry no proof; the platform's own example response for
 * VK_SUBSTITUTION likewise omits proof and public_signals.)
 */
export function circuitExpectedDecision(task: GatekeeperTask): 0 | 1 {
  const input = task.input;
  const ok =
    BigInt(input.public_balance) >= BigInt(input.minimum) &&
    input.recipient.toLowerCase() === input.condition_recipient.toLowerCase() &&
    BigInt(input.amount) <= BigInt(input.max_transfer) &&
    input.current_block <= input.expiry_block &&
    input.proof_vk === input.registered_vk;
  return ok ? 1 : 0;
}
export function taskToCircuitInput(
  task: GatekeeperTask,
  decision: Decision,
  salt: bigint
) {
  const input = task.input;
  return {
    minimum: BigInt(input.minimum),
    publicBalance: BigInt(input.public_balance),
    expiryBlock: BigInt(input.expiry_block),
    currentBlock: BigInt(input.current_block),
    recipient: encodeAddress(input.recipient),
    conditionRecipient: encodeAddress(input.condition_recipient),
    amount: BigInt(input.amount),
    maxTransfer: BigInt(input.max_transfer),
    taskId: encodeTaskId(task.task_id),
    decision: (decision === "APPROVE" ? 1 : 0) as 0 | 1,
    salt,
    registeredVkHash: encodeVkHash(input.registered_vk),
    proofVkHash: encodeVkHash(input.proof_vk),
  };
}

/** Field-element form of the expected VK hash, for cross-checking proofs. */
export function expectedVkField(expectedVkHash: string): bigint {
  return toField(encodeVkHash(expectedVkHash));
}
