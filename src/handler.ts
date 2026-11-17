// Request orchestration for POST /agent.
// Order of operations (fail closed at every step):
//   1. HMAC over the RAW body, before parsing. Mismatch => 401, nothing else.
//   2. Parse JSON + route by `type` (preflight vs proof-gatekeeper task).
//   3. Task: deterministic checks => decision (never a model).
//   4. Generate the Groth16 proof for that decision — but ONLY when the
//      circuit can prove it: the circuit constrains
//      decision == circuitExpectedDecision(task), so a valid proof exists
//      only for that decision. Non-circuit rejections (VK substitution,
//      stale timestamp, replay) carry no proof by design.
//   5. Kurier: submit + poll for Finalized (bounded by the response deadline).
//      APPROVE requires Finalized in strict mode; otherwise the decision
//      flips to REJECT and the proof is regenerated with decision = 0.
//   6. Sign the exact response bytes with x-agent-games-signature and reply.
// Any timeout, error, or uncertainty => REJECT. A proof is included whenever
// one was successfully generated for the returned decision.
import fs from "node:fs";
import path from "node:path";
import type { Config } from "./config";
import { verifySignature } from "./hmac";
import { jsonResult, type HttpResult } from "./respond";
import {
  buildCircuitInput,
  freshSalt,
  parsePublicSignals,
} from "./circuit";
import {
  circuitExpectedDecision,
  evaluateChecks,
  parsePreflight,
  parseTaskEnvelope,
  parseTimestamp,
  taskToCircuitInput,
  PREFLIGHT_TYPE,
  TASK_TYPE,
  type Decision,
  type GatekeeperTask,
  type ReasonCode,
} from "./decision";
import { Prover, type Groth16Proof } from "./prover";
import { KurierClient } from "./kurier";
import type { ProofStore } from "./store";
import { handleStealTurn, type StealContext } from "./steal-handler";
import { STEAL_EVENT_ID } from "./steal-circuit";

export interface AgentContext {
  config: Config;
  prover: Prover;
  store: ProofStore;
  kurier: KurierClient | null;
  /** Effective vk hash used for Kurier submissions (may differ from the
   *  expected hash only when the VK was registered on testnet at startup). */
  kurierVkHash: string;
  vkJson: Record<string, unknown>;
  /** Steal-the-VFY context, or null when the track is not configured
   *  (STEAL_VFY_SALT unset) — Steal turns then answer 503. */
  steal: StealContext | null;
  /** Steal response cache: one entry per (matchId, turn), bounded FIFO.
   *  A platform retry after a network failure receives the byte-identical
   *  response (same proof, same idempotency key, same timestamp). */
  stealResponses: Map<string, HttpResult>;
}

interface AgentResponse {
  decision: Decision;
  reason_code: ReasonCode;
  proof: Groth16Proof | null;
  public_signals: string[] | null;
  proof_tx: string | null;
}

class DeadlineExceeded extends Error {
  constructor() {
    super("deadline exceeded");
  }
}

export async function handleAgentRequest(
  rawBody: Buffer,
  signatureHeader: string | string[] | undefined,
  ctx: AgentContext
): Promise<HttpResult> {
  const cfg = ctx.config;

  // 1. HMAC first — before parsing anything.
  if (!verifySignature(cfg.hmacSecret, cfg.hmacAlgorithm, rawBody, signatureHeader)) {
    return jsonResult(401, { error: "invalid_signature" }, cfg, false);
  }

  let body: unknown;
  try {
    body = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return jsonResult(400, { error: "invalid_json" }, cfg, false);
  }

  if (
    body !== null &&
    typeof body === "object" &&
    (body as Record<string, unknown>).type === PREFLIGHT_TYPE
  ) {
    return handlePreflight(body, ctx);
  }
  if (
    body !== null &&
    typeof body === "object" &&
    (body as Record<string, unknown>).type === TASK_TYPE
  ) {
    return handleTask(body, ctx);
  }
  if (
    body !== null &&
    typeof body === "object" &&
    (body as Record<string, unknown>).eventId === STEAL_EVENT_ID
  ) {
    return handleStealTurn(body, ctx);
  }
  return jsonResult(400, { error: "unknown_type" }, cfg, true);
}

function handlePreflight(body: unknown, ctx: AgentContext): HttpResult {
  const cfg = ctx.config;
  const preflight = parsePreflight(body);
  if (!preflight) {
    return jsonResult(400, { error: "invalid_preflight" }, cfg, true);
  }
  if (cfg.agentId !== null && preflight.agent_id !== null && preflight.agent_id !== cfg.agentId) {
    return jsonResult(401, { error: "agent_mismatch" }, cfg, false);
  }
  return jsonResult(200, { ok: true, protocolVersion: "v1" }, cfg, true);
}

async function handleTask(body: unknown, ctx: AgentContext): Promise<HttpResult> {
  const cfg = ctx.config;
  const receivedAtMs = Date.now();
  const task = parseTaskEnvelope(body);

  // Malformed envelope: reject without a proof (nothing meaningful to prove).
  if (!task) {
    return jsonResult(
      200,
      {
        decision: "REJECT",
        reason_code: "INVALID_TASK",
        proof: null,
        public_signals: null,
        proof_tx: null,
      } satisfies AgentResponse,
      cfg,
      true
    );
  }

  // Hard deadline: the platform's deadline_at, or now + 60s, whichever is
  // sooner. Keep a 2s reserve to sign and send the response.
  const platformDeadline = parseTimestamp(task.deadline_at);
  const deadlineMs = Math.min(
    platformDeadline ?? Number.POSITIVE_INFINITY,
    receivedAtMs + cfg.responseDeadlineMs
  );
  const reserveMs = 2_000;
  const remainingMs = () => deadlineMs - Date.now() - reserveMs;
  const ensureTime = (neededMs: number) => {
    if (remainingMs() < neededMs) throw new DeadlineExceeded();
  };

  let decision: Decision = "REJECT";
  let reasonCode: ReasonCode = "INTERNAL_ERROR";
  let proof: Groth16Proof | null = null;
  let publicSignals: string[] | null = null;
  let proofTx: string | null = null;
  let kurierJobId: string | null = null;
  let kurierStatus: string | null = null;
  let salt: bigint | null = null;

  try {
    // 3. Deterministic checks.
    const checks = evaluateChecks(task, {
      expectedVkHash: cfg.gatekeeperVkHash,
      hasTaskId: (id) => ctx.store.hasTaskId(id),
      nowMs: receivedAtMs,
      timestampSkewMs: cfg.timestampSkewMs,
    });
    decision = checks.decision;
    reasonCode = checks.reasonCode;

    // 4. Prove — but ONLY if a proof can exist for this decision. The
    // circuit constrains decision == circuitExpectedDecision(task): a valid
    // proof exists only for that decision. When my decision (from the full
    // checklist) differs — a non-circuit rejection such as VK substitution,
    // a stale timestamp, or a replay — no proof is possible by design, so
    // respond without one and keep the original reason_code.
    const expected = circuitExpectedDecision(task);
    const proofPossible = (decision === "APPROVE" ? 1 : 0) === expected;

    salt = freshSalt();
    const prove = async (d: Decision) => {
      ensureTime(5_000);
      const input = taskToCircuitInput(task, d, salt as bigint);
      const res = await ctx.prover.prove(buildCircuitInput(input));
      const ok = await ctx.prover.verifyLocally(res.proof, res.publicSignals);
      if (!ok) throw new Error("local proof verification failed");
      return res;
    };

    if (proofPossible) {
      const res = await prove(decision);
      proof = res.proof;
      publicSignals = res.publicSignals;

      // 4b. Proof-reference replay check: the binding (public signal 0)
      // must never have been used before. (A fresh salt makes this
      // ~impossible unless the task itself was replayed — already rejected
      // above.) A flipped REJECT has no proof (circuit expected 1).
      const parsed = parsePublicSignals(publicSignals);
      if (ctx.store.hasBinding(parsed.binding)) {
        decision = "REJECT";
        reasonCode = "PROOF_REUSED";
        proof = null;
        publicSignals = null;
      }
    }

    // 5. Kurier submission + finalization (bounded by the deadline).
    // Only when a proof exists to submit.
    if (ctx.kurier !== null && proof !== null && publicSignals !== null) {
      const submitAndPoll = async (
        p: Groth16Proof,
        sigs: string[],
        pollBudgetMs: number
      ): Promise<{ txHash: string | null; status: string | null; jobId: string | null }> => {
        const sub = await ctx.kurier!.submitProof(
          p,
          sigs,
          ctx.kurierVkHash,
          cfg.kurierVkRegistered
        );
        kurierJobId = sub.jobId;
        kurierStatus = "Submitted";
        if (sub.optimisticVerify !== "success") {
          throw new Error(`Kurier optimisticVerify=${sub.optimisticVerify}`);
        }
        const poll = await ctx.kurier!.pollUntilFinalized(sub.jobId, {
          timeoutMs: Math.max(0, Math.min(pollBudgetMs, remainingMs())),
          intervalMs: cfg.kurierPollIntervalMs,
        });
        kurierStatus = poll.status;
        if (poll.outcome === "finalized") {
          return { txHash: poll.txHash, status: poll.status, jobId: sub.jobId };
        }
        if (poll.outcome === "failed") {
          throw new Error(`Kurier job ${sub.jobId} failed (${poll.status})`);
        }
        return { txHash: null, status: poll.status, jobId: sub.jobId };
      };

      if (decision === "APPROVE") {
        const out = await submitAndPoll(
          proof as Groth16Proof,
          publicSignals as string[],
          cfg.kurierFinalizeTimeoutMs
        );
        if (out.txHash !== null || out.status === "Finalized") {
          proofTx = out.txHash;
          kurierJobId = out.jobId;
          kurierStatus = out.status;
        } else if (cfg.requireKurierFinalized) {
          // Strict fail-closed: no Finalized in budget => do not approve.
          // The flipped REJECT has no proof (the circuit expected 1),
          // so drop the approve proof instead of regenerating one.
          decision = "REJECT";
          reasonCode = "KURIER_NOT_FINALIZED";
          proof = null;
          publicSignals = null;
        } else {
          kurierJobId = out.jobId;
          kurierStatus = out.status;
        }
      } else {
        // REJECT: best-effort submission, never blocking the deadline.
        try {
          ensureTime(8_000);
          const out = await submitAndPoll(
            proof as Groth16Proof,
            publicSignals as string[],
            Math.min(10_000, remainingMs())
          );
          if (out.txHash !== null) proofTx = out.txHash;
          kurierJobId = out.jobId;
          kurierStatus = out.status;
        } catch {
          // Best-effort only.
        }
      }
    }
  } catch (err) {
    if (err instanceof DeadlineExceeded) {
      decision = "REJECT";
      reasonCode = "TIMEOUT";
    } else if (decision === "APPROVE") {
      // A failure after the checks passed (prove / Kurier) => fail closed.
      const msg = (err as Error).message ?? "";
      reasonCode = /kurier/i.test(msg) ? "KURIER_ERROR" : "PROOF_FAILED";
      decision = "REJECT";
    } else {
      reasonCode = "INTERNAL_ERROR";
      decision = "REJECT";
    }
    console.error(`[task ${task.task_id}] ${reasonCode}:`, (err as Error).message);
  }

  // Invariant: a returned proof must assert the returned decision. If the
  // proof on hand was generated for the other decision (e.g. an APPROVE
  // proof flipped to REJECT by a later failure), drop it — a mismatched
  // proof is worse than no proof.
  if (proof !== null && publicSignals !== null) {
    try {
      const parsed = parsePublicSignals(publicSignals);
      const proofDecision = parsed.decision === "1" ? "APPROVE" : "REJECT";
      if (proofDecision !== decision) {
        proof = null;
        publicSignals = null;
      }
    } catch {
      proof = null;
      publicSignals = null;
    }
  }

  // Record for replay protection + disputes (only once per task id).
  try {
    const binding =
      publicSignals !== null
        ? parsePublicSignals(publicSignals).binding
        : `no-proof:${task.task_id}`;
    if (!ctx.store.hasTaskId(task.task_id)) {
      ctx.store.record({
        taskId: task.task_id,
        binding,
        decision,
        reasonCode,
        salt: salt !== null ? salt.toString() : "",
        publicSignals: publicSignals ?? [],
        proofTx,
        kurierJobId,
        kurierStatus,
        receivedAtMs,
        respondedAtMs: Date.now(),
      });
    }
  } catch (err) {
    console.error(`[store] failed to record task ${task.task_id}:`, (err as Error).message);
  }

  const response: AgentResponse = {
    decision,
    reason_code: reasonCode,
    proof,
    public_signals: publicSignals,
    proof_tx: proofTx,
  };
  return jsonResult(200, response, cfg, true);
}

export function loadVkJson(circuitsDir: string): Record<string, unknown> {
  const p = path.join(circuitsDir, "gatekeeper.vk.json");
  return JSON.parse(fs.readFileSync(p, "utf8")) as Record<string, unknown>;
}
