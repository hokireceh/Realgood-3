// Kurier REST client (zkVerify proof verification as a service).
// Docs: https://docs.zkverify.io/overview/getting-started/kurier
//   Mainnet API: https://api.kurier.xyz/api/v1
//   Testnet API: https://api-testnet.kurier.xyz/api/v1
// Flow: [register-vk once] -> submit-proof -> poll job-status until Finalized.
// Job statuses: Queued, Valid, Submitted, IncludedInBlock, Finalized, Failed
// (plus Aggregation* statuses when aggregation is requested — not used here).
import type { Groth16Proof } from "./prover";

export type JobStatus =
  | "Queued"
  | "Valid"
  | "Submitted"
  | "IncludedInBlock"
  | "Finalized"
  | "Failed"
  | "AggregationPending"
  | "Aggregated"
  | "AggregationPublished";

export interface SubmitResult {
  jobId: string;
  optimisticVerify: string;
}

export interface JobStatusResult {
  jobId: string;
  status: JobStatus;
  txHash: string | null;
  raw: Record<string, unknown>;
}

export interface PollOutcome {
  outcome: "finalized" | "failed" | "timeout";
  status: JobStatus | "Timeout";
  txHash: string | null;
}

const TERMINAL_FAILURE: JobStatus[] = ["Failed"];

function withTimeout(ms: number): { signal: AbortSignal; cancel: () => void } {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return {
    signal: controller.signal,
    cancel: () => clearTimeout(timer),
  };
}

async function postJson<T>(
  url: string,
  body: unknown,
  timeoutMs: number
): Promise<T> {
  const { signal, cancel } = withTimeout(timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal,
    });
    const text = await res.text();
    let data: unknown = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      throw new Error(`Kurier returned non-JSON (HTTP ${res.status}): ${text.slice(0, 200)}`);
    }
    if (!res.ok) {
      throw new Error(
        `Kurier POST ${url} failed (HTTP ${res.status}): ${JSON.stringify(data)?.slice(0, 300)}`
      );
    }
    return data as T;
  } finally {
    cancel();
  }
}

async function getJson<T>(url: string, timeoutMs: number): Promise<T> {
  const { signal, cancel } = withTimeout(timeoutMs);
  try {
    const res = await fetch(url, { method: "GET", signal });
    const text = await res.text();
    let data: unknown = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      throw new Error(`Kurier returned non-JSON (HTTP ${res.status}): ${text.slice(0, 200)}`);
    }
    if (!res.ok) {
      throw new Error(
        `Kurier GET ${url} failed (HTTP ${res.status}): ${JSON.stringify(data)?.slice(0, 300)}`
      );
    }
    return data as T;
  } finally {
    cancel();
  }
}

export class KurierClient {
  constructor(
    private readonly apiUrl: string,
    private readonly apiKey: string
  ) {}

  /** Register the verification key once; returns its vkHash. */
  async registerVk(vk: Record<string, unknown>): Promise<string> {
    const data = await postJson<Record<string, unknown>>(
      `${this.apiUrl}/register-vk/${this.apiKey}`,
      {
        proofType: "groth16",
        proofOptions: { library: "snarkjs", curve: "bn128" },
        vk,
      },
      30_000
    );
    const hash =
      (data as { vkHash?: string }).vkHash ??
      (data as { meta?: { vkHash?: string } }).meta?.vkHash;
    if (!hash) {
      throw new Error(`Kurier register-vk returned no vkHash: ${JSON.stringify(data)}`);
    }
    return hash;
  }

  /** Submit a Groth16 proof for verification. */
  async submitProof(
    proof: Groth16Proof,
    publicSignals: string[],
    vkHash: string,
    vkRegistered: boolean
  ): Promise<SubmitResult> {
    const data = await postJson<Record<string, unknown>>(
      `${this.apiUrl}/submit-proof/${this.apiKey}`,
      {
        proofType: "groth16",
        vkRegistered,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: vkHash },
      },
      30_000
    );
    const jobId = (data as { jobId?: string }).jobId;
    const optimisticVerify = (data as { optimisticVerify?: string }).optimisticVerify;
    if (!jobId) {
      throw new Error(`Kurier submit-proof returned no jobId: ${JSON.stringify(data)}`);
    }
    return { jobId, optimisticVerify: optimisticVerify ?? "unknown" };
  }

  /** Fetch the current status of a job. */
  async jobStatus(jobId: string): Promise<JobStatusResult> {
    const data = await getJson<Record<string, unknown>>(
      `${this.apiUrl}/job-status/${this.apiKey}/${jobId}`,
      15_000
    );
    const status = (data as { status?: string }).status as JobStatus;
    const txHash = (data as { txHash?: string | null }).txHash ?? null;
    return { jobId, status, txHash, raw: data };
  }

  /**
   * Poll job-status until Finalized / Failed or the timeout expires.
   * Returns "timeout" (not an error) when the budget runs out — the caller
   * decides whether that flips an APPROVE to REJECT.
   */
  async pollUntilFinalized(
    jobId: string,
    opts: { timeoutMs: number; intervalMs: number }
  ): Promise<PollOutcome> {
    const deadline = Date.now() + opts.timeoutMs;
    let lastStatus: JobStatus = "Queued";
    let lastTxHash: string | null = null;
    for (;;) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        return { outcome: "timeout", status: "Timeout", txHash: lastTxHash };
      }
      try {
        const st = await this.jobStatus(jobId);
        lastStatus = st.status;
        lastTxHash = st.txHash;
        if (st.status === "Finalized") {
          return { outcome: "finalized", status: "Finalized", txHash: st.txHash };
        }
        if (TERMINAL_FAILURE.includes(st.status)) {
          return { outcome: "failed", status: st.status, txHash: st.txHash };
        }
      } catch (err) {
        // Transient poll errors do not fail the job — retry until the budget
        // is gone. Log to stderr; the caller records the outcome.
        console.error(`[kurier] job-status poll error for ${jobId}:`, (err as Error).message);
      }
      await new Promise((r) => setTimeout(r, Math.min(opts.intervalMs, Math.max(0, deadline - Date.now()))));
    }
  }
}
