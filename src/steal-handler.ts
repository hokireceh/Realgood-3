// Steal-the-VFY turn handler (POST /agent, eventId "steal-the-vfy").
//
// Flow (fail closed at every step):
//   1. HMAC was already verified by handleAgentRequest, over the raw body.
//   2. Parse + validate the turn envelope. Malformed => 400.
//   3. The policy is deterministic (src/policy.ts): the move is the ONLY
//      one the circuit can prove for this state under the registered
//      parameters. There is no model, no randomness, no game-state cache.
//   4. Generate the Groth16 policy proof locally and verify it against
//      the exported vfy-policy VK before responding. A failed local
//      verification is a 500, never a response with a bad proof.
//   5. Respond with the documented shape: echo matchId + turn, the
//      action (amount OMITTED for HOLD / FORTIFY — the platform rejects
//      the turn if it is present, even as 0), and policyProof with the
//      circuit version, proof, public signals, and the public-inputs
//      hash the platform recomputes from the game state.
//   6. Record the turn in the store for audit. Replays are answered by
//      re-running the deterministic flow: same turn => same proof =>
//      identical response (the idempotency key is a UUID v5 derived from
//      matchId + turn, never random — the platform validates the field
//      as a UUID and rejects a plain string), and the platform dedupes
//      on its side via the binding (public signal 0).
//
// Deliberate differences from a working third-party reference
// implementation (DaddyUnikii/zkverify-agent), each verified against the
// circuit (see src/steal-circuit.ts):
//   - The opponent threshold is INCLUSIVE (opponentBalance <= params[2]
//     -> HOLD). The reference uses a strict `<`, which makes its agent
//     attempt an unprovable EXTRACT at exactly params[2].
//   - params[3] == 1 (never-extract) is implemented; the reference
//     ignores it and would attempt an unprovable EXTRACT.
//   - The commitment used is ALWAYS the locally computed one (from the
//     params + salt that were registered). If the envelope carries a
//     different strategyCommitment hash, it is logged as a warning —
//     using the envelope's hash would make the proof fail outright,
//     because the circuit re-derives the commitment from OUR params.
//   - No Kurier submission on this path: the platform verifies the
//     policy proof itself (offline); proofReference is an optional
//     on-chain audit pointer per the builder guide. The proof is
//     returned in the response, not gated on a chain transaction.
//   - The idempotency key is deterministic per turn, so a platform
//     retry after a network failure receives the identical response
//     instead of a fresh random key.
import type { Config } from "./config";
import type { Prover } from "./prover";
import type { ProofStore } from "./store";
import { jsonResult, type HttpResult } from "./respond";
import {
  buildStealCircuitInput,
  computePublicInputsHash,
  encodeMatchId,
  parseStealPublicSignals,
  STEAL_ACTION_CODE,
  STEAL_CIRCUIT_VERSION,
  STEAL_EVENT_ID,
  STEAL_POLICY_PROOF_VERSION,
  type StealCircuitInputs,
} from "./steal-circuit";
import { decideMove } from "./policy";
import { stealIdempotencyKey } from "./uuidv5";

export interface StealContext {
  params: bigint[];
  salt: bigint;
  commitmentHex: string;
  commitmentDecimal: string;
  prover: Prover;
}

export interface StealTurn {
  matchId: string;
  matchIdField: bigint;
  turn: number;
  selfBalance: bigint;
  opponentBalance: bigint;
  strategyCommitmentHash: string | null;
  deadlineMs: number | null;
}

function parseUint(value: unknown): bigint | null {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) return null;
    return BigInt(value);
  }
  if (typeof value === "string" && /^\d+$/.test(value.trim())) {
    return BigInt(value.trim());
  }
  return null;
}

function parseDeadlineMs(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

/** Validate the turn envelope. Returns null when it cannot be answered. */
export function parseStealEnvelope(body: unknown): StealTurn | null {
  if (body === null || typeof body !== "object") return null;
  const o = body as Record<string, unknown>;
  if (o.eventId !== STEAL_EVENT_ID) return null;
  if (typeof o.matchId !== "string" || o.matchId.trim() === "") return null;
  let matchIdField: bigint;
  try {
    matchIdField = encodeMatchId(o.matchId);
  } catch {
    return null;
  }
  const turnBig = parseUint(o.turn);
  if (turnBig === null || turnBig > 9007199254740991n) return null;
  if (o.state === null || typeof o.state !== "object") return null;
  const state = o.state as Record<string, unknown>;
  const selfBalance = parseUint(state.selfBalance);
  const opponentBalance = parseUint(state.opponentBalance);
  if (selfBalance === null || opponentBalance === null) return null;

  let strategyCommitmentHash: string | null = null;
  if (o.strategyCommitment !== null && typeof o.strategyCommitment === "object") {
    const sc = o.strategyCommitment as Record<string, unknown>;
    if (typeof sc.hash === "string" && sc.hash.trim() !== "") {
      strategyCommitmentHash = sc.hash.trim();
    }
  }
  const deadlineMs =
    parseDeadlineMs(o.deadline_at) ?? parseDeadlineMs(o.deadline) ?? null;

  return {
    matchId: o.matchId,
    matchIdField,
    turn: Number(turnBig),
    selfBalance,
    opponentBalance,
    strategyCommitmentHash,
    deadlineMs,
  };
}

class StealDeadlineExceeded extends Error {
  constructor() {
    super("steal turn deadline exceeded");
  }
}

export async function handleStealTurn(
  body: unknown,
  ctx: {
    config: Config;
    store: ProofStore;
    steal: StealContext | null;
    stealResponses: Map<string, HttpResult>;
  }
): Promise<HttpResult> {
  const cfg = ctx.config;

  if (ctx.steal === null) {
    return jsonResult(503, { error: "steal_not_configured" }, cfg, true);
  }
  const steal = ctx.steal;
  const receivedAtMs = Date.now();

  const turn = parseStealEnvelope(body);
  if (turn === null) {
    return jsonResult(400, { error: "invalid_steal_turn" }, cfg, true);
  }

  // Idempotent replay: a platform retry of an already-answered turn gets
  // the byte-identical response (same proof, same idempotency key, same
  // timestamp) instead of a fresh proof run.
  const cacheKey = `vfy:${turn.matchId}:${turn.turn}`;
  const cached = ctx.stealResponses.get(cacheKey);
  if (cached) return cached;

  // Turn budget: the platform's deadline when present, else the 5-minute
  // turn window from receipt. Keep a 10s reserve to sign and send.
  const deadlineMs = Math.min(
    turn.deadlineMs ?? Number.POSITIVE_INFINITY,
    receivedAtMs + 300_000
  );
  const reserveMs = 10_000;
  const remainingMs = () => deadlineMs - Date.now() - reserveMs;
  const ensureTime = (neededMs: number) => {
    if (remainingMs() < neededMs) throw new StealDeadlineExceeded();
  };

  try {
    if (
      turn.strategyCommitmentHash !== null &&
      turn.strategyCommitmentHash.toLowerCase() !== steal.commitmentHex.toLowerCase()
    ) {
      console.warn(
        `[steal ${turn.matchId}#${turn.turn}] envelope strategyCommitment ` +
          `${turn.strategyCommitmentHash} != registered ${steal.commitmentHex} — ` +
          "using the registered commitment; re-register the strategy if the parameters changed."
      );
    }

    const move = decideMove(
      { selfBalance: turn.selfBalance, opponentBalance: turn.opponentBalance },
      steal.params
    );
    const actionCode = STEAL_ACTION_CODE[move.type];

    ensureTime(5_000);
    const input: StealCircuitInputs = buildStealCircuitInput({
      commitment: BigInt(steal.commitmentDecimal),
      matchId: turn.matchIdField,
      turnNumber: BigInt(turn.turn),
      selfBalance: turn.selfBalance,
      opponentBalance: turn.opponentBalance,
      action: actionCode,
      amount: BigInt(move.amountNum),
      circuitVersion: STEAL_CIRCUIT_VERSION,
      salt: steal.salt,
      strategyParams: steal.params,
    });
    const { proof, publicSignals } = await steal.prover.prove(input);
    const ok = await steal.prover.verifyLocally(proof, publicSignals);
    if (!ok) throw new Error("local policy-proof verification failed");

    // Invariant: the proof must assert the move we are returning.
    const parsed = parseStealPublicSignals(publicSignals);
    if (
      parsed.commitment !== steal.commitmentDecimal ||
      parsed.action !== actionCode.toString() ||
      parsed.amount !== String(move.amountNum) ||
      parsed.circuitVersion !== STEAL_CIRCUIT_VERSION.toString()
    ) {
      throw new Error("policy proof public signals do not match the returned move");
    }

    const publicInputsHash = computePublicInputsHash({
      commitment: BigInt(steal.commitmentDecimal),
      matchId: turn.matchIdField,
      turnNumber: BigInt(turn.turn),
      selfBalance: turn.selfBalance,
      opponentBalance: turn.opponentBalance,
      action: actionCode,
      amount: BigInt(move.amountNum),
      circuitVersion: STEAL_CIRCUIT_VERSION,
    });

    const response = {
      matchId: turn.matchId,
      turn: turn.turn,
      // HOLD and FORTIFY must omit `amount` entirely (the platform
      // rejects the turn if it is present, even as 0).
      action:
        move.type === "EXTRACT"
          ? { type: "EXTRACT", amount: move.amountNum }
          : { type: move.type },
      policyProof: {
        circuitVersion: STEAL_POLICY_PROOF_VERSION,
        proof,
        public_signals: publicSignals,
        publicInputsHash,
      },
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: stealIdempotencyKey(turn.matchId, turn.turn),
    };

    const taskId = `vfy:${turn.matchId}:${turn.turn}`;
    if (!ctx.store.hasTaskId(taskId)) {
      try {
        ctx.store.record({
          taskId,
          binding: parsed.binding,
          decision: move.type,
          reasonCode: "OK",
          salt: "",
          publicSignals,
          proofTx: null,
          kurierJobId: null,
          kurierStatus: null,
          receivedAtMs,
          respondedAtMs: Date.now(),
        });
      } catch (err) {
        console.error(`[store] failed to record ${taskId}:`, (err as Error).message);
      }
    }

    const result = jsonResult(200, response, cfg, true);
    ctx.stealResponses.set(cacheKey, result);
    if (ctx.stealResponses.size > 500) {
      const firstKey = ctx.stealResponses.keys().next().value;
      if (firstKey !== undefined) ctx.stealResponses.delete(firstKey);
    }
    return result;
  } catch (err) {
    if (err instanceof StealDeadlineExceeded) {
      console.error(`[steal ${turn.matchId}#${turn.turn}] deadline exceeded`);
    } else {
      console.error(
        `[steal ${turn.matchId}#${turn.turn}] ${(err as Error).message}`
      );
    }
    // Fail closed with a 500 (the platform records a timeout, -1) rather
    // than returning a move with no/invalid proof (-2).
    return jsonResult(500, { error: "internal_error" }, cfg, true);
  }
}
