// Local test harness: boots the real server on a test port with a test
// HMAC secret and Kurier disabled, replays the sample envelopes, and checks
// every response end-to-end:
//   - HTTP 200 + a valid x-agent-games-signature over the raw response body
//   - expected decision + reason_code
//   - the Groth16 proof verifies locally against the exported VK
//   - the public signals match the task (layout, vk hashes, taskId encoding)
//   - the binding equals Poseidon(salt, taskId) for the salt in the store
// Also covers: preflight, bad HMAC (401), tampered body (401), task replay.
// Usage: npm test   (or: npx tsx test/harness.ts)
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
import { encodeTaskId, parsePublicSignals, toField } from "../src/circuit";

const ROOT = path.resolve(__dirname, "..");
// Random port + data dir per run: a stale server from an earlier run must
// never be able to intercept this run's requests.
const PORT = 18100 + Math.floor(Math.random() * 800);
const BASE = `http://127.0.0.1:${PORT}`;
const TEST_SECRET = "test-secret-do-not-use-in-prod";
const DATA_DIR = path.join(ROOT, `data-test-${PORT}`);

let failures = 0;
let passes = 0;

function check(name: string, cond: boolean, detail = ""): void {
  if (cond) {
    passes++;
    console.log(`  PASS ${name}`);
  } else {
    failures++;
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function sign(raw: Buffer): string {
  return crypto.createHmac("sha256", TEST_SECRET).update(raw).digest("hex");
}

async function postAgent(
  bodyObj: unknown,
  opts: { signWith?: string; tamperAfterSign?: boolean } = {}
): Promise<{ status: number; headers: Headers; text: string; json: unknown }> {
  const raw = Buffer.from(JSON.stringify(bodyObj), "utf8");
  const secret = opts.signWith ?? TEST_SECRET;
  // Sign the ORIGINAL bytes; tampering afterwards must break verification.
  const sig = crypto.createHmac("sha256", secret).update(raw).digest("hex");
  const body = opts.tamperAfterSign
    ? Buffer.concat([raw, Buffer.from(" ", "utf8")])
    : raw;
  const res = await fetch(`${BASE}/agent`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": sig,
    },
    body,
  });
  const text = await res.text();
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch {
    // leave null
  }
  return { status: res.status, headers: res.headers, text, json };
}

function freshTimestamps(obj: Record<string, unknown>): Record<string, unknown> {
  const now = new Date();
  const out = { ...obj };
  if ("issued_at" in out) out.issued_at = now.toISOString();
  if ("deadline_at" in out) {
    out.deadline_at = new Date(now.getTime() + 60_000).toISOString();
  }
  return out;
}

function loadSample(name: string): Record<string, unknown> {
  return JSON.parse(
    fs.readFileSync(path.join(ROOT, "test", "samples", name), "utf8")
  ) as Record<string, unknown>;
}

function storeRecord(taskId: string): Record<string, unknown> | null {
  const p = path.join(DATA_DIR, "proofs.json");
  if (!fs.existsSync(p)) return null;
  const records = JSON.parse(fs.readFileSync(p, "utf8")) as Record<string, unknown>[];
  return records.find((r) => r.taskId === taskId) ?? null;
}

async function waitForHealth(timeoutMs = 20_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE}/health`);
      if (res.ok) return true;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

async function main(): Promise<void> {
  // Fresh store for a deterministic run.
  fs.rmSync(DATA_DIR, { recursive: true, force: true });

  const vk = JSON.parse(
    fs.readFileSync(path.join(ROOT, "circuits", "gatekeeper.vk.json"), "utf8")
  );
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  console.log("[harness] starting server…");
  // Spawn the COMPILED server directly (not via npx/sh) so that killing
  // this child kills the actual server process — no orphaned listeners.
  const server: ChildProcess = spawn(
    "node",
    ["dist/server-main.js"],
    {
      cwd: ROOT,
      env: {
        ...process.env,
        PORT: String(PORT),
        HOST: "127.0.0.1",
        AGENT_GAMES_HMAC_SECRET: TEST_SECRET,
        KURIER_API_KEY: "",
        REQUIRE_KURIER_FINALIZED: "false",
        DATA_DIR,
        CIRCUITS_DIR: path.join(ROOT, "circuits"),
      },
      stdio: ["ignore", "pipe", "pipe"],
    }
  );
  let serverLog = "";
  server.stdout?.on("data", (d: Buffer) => (serverLog += d.toString()));
  server.stderr?.on("data", (d: Buffer) => (serverLog += d.toString()));

  try {
    if (!(await waitForHealth())) {
      console.log("[harness] server did not become healthy in time");
      console.log(serverLog);
      process.exitCode = 1;
      return;
    }
    console.log("[harness] server healthy");

    // ---- Preflight -------------------------------------------------------
    console.log("\n[preflight]");
    {
      const body = freshTimestamps(loadSample("preflight.json"));
      const res = await postAgent(body);
      check("status 200", res.status === 200, `got ${res.status}: ${res.text}`);
      const j = res.json as Record<string, unknown>;
      check("body is { ok: true, protocolVersion: v1 }", j?.ok === true && j?.protocolVersion === "v1");
      const sig = res.headers.get("x-agent-games-signature") ?? "";
      check(
        "response is HMAC-signed",
        sig === sign(Buffer.from(res.text, "utf8")),
        `sig=${sig.slice(0, 16)}…`
      );
    }

    // ---- Task cases ------------------------------------------------------
    // expectProof: false when the circuit cannot prove the decision — the
    // circuit constrains decision == circuitExpectedDecision(task), so a
    // non-circuit rejection (VK substitution, replay) carries no proof.
    const cases: { file: string; decision: string; reason: string; expectProof: boolean }[] = [
      { file: "task-valid.json", decision: "APPROVE", reason: "OK", expectProof: true },
      { file: "task-vk-substitution.json", decision: "REJECT", reason: "VK_SUBSTITUTION", expectProof: false },
      { file: "task-vk-mismatch.json", decision: "REJECT", reason: "VK_MISMATCH", expectProof: true },
      { file: "task-below-minimum.json", decision: "REJECT", reason: "BELOW_MINIMUM", expectProof: true },
      { file: "task-recipient-mismatch.json", decision: "REJECT", reason: "RECIPIENT_MISMATCH", expectProof: true },
      { file: "task-amount-exceeds.json", decision: "REJECT", reason: "AMOUNT_EXCEEDS_MAX", expectProof: true },
      { file: "task-expired.json", decision: "REJECT", reason: "EXPIRED", expectProof: true },
    ];

    for (const c of cases) {
      console.log(`\n[${c.file}] expect ${c.decision}/${c.reason}`);
      const body = freshTimestamps(loadSample(c.file));
      const taskId = body.task_id as string;
      const res = await postAgent(body);
      check("status 200", res.status === 200, `got ${res.status}: ${res.text}`);
      const j = res.json as Record<string, unknown>;
      check("decision matches", j?.decision === c.decision, `got ${j?.decision}`);
      check("reason_code matches", j?.reason_code === c.reason, `got ${j?.reason_code}`);
      const sig = res.headers.get("x-agent-games-signature") ?? "";
      check("response is HMAC-signed", sig === sign(Buffer.from(res.text, "utf8")));

      // Proof present + verifies locally + signals match the task.
      const proof = j?.proof as Record<string, unknown> | null;
      const sigs = j?.public_signals as string[] | null;
      if (!c.expectProof) {
        check("proof is null (circuit cannot prove this decision)", proof === null);
        check("public_signals is null", sigs === null);
        continue;
      }
      check("proof present", proof !== null && typeof proof === "object");
      check("13 public signals", Array.isArray(sigs) && sigs.length === 13);
      if (proof && Array.isArray(sigs) && sigs.length === 13) {
        const ok = await snarkjs.groth16.verify(vk, sigs, proof);
        check("proof verifies against the exported VK", ok);
        const parsed = parsePublicSignals(sigs);
        const input = body.input as Record<string, unknown>;
        const regField = toField(BigInt(input.registered_vk as string)).toString();
        const proofField = toField(BigInt(input.proof_vk as string)).toString();
        check("signal[1] registeredVkHash (task value)", parsed.registeredVkHash === regField);
        check("signal[2] proofVkHash (task value)", parsed.proofVkHash === proofField);
        check("signal[3] minimum", parsed.minimum === String(input.minimum));
        check("signal[4] publicBalance", parsed.publicBalance === String(input.public_balance));
        check("signal[5] expiryBlock", parsed.expiryBlock === String(input.expiry_block));
        check("signal[6] currentBlock", parsed.currentBlock === String(input.current_block));
        check(
          "signal[7] recipient",
          parsed.recipient === BigInt(input.recipient as string).toString()
        );
        check(
          "signal[8] conditionRecipient",
          parsed.conditionRecipient === BigInt(input.condition_recipient as string).toString()
        );
        check("signal[9] amount", parsed.amount === String(input.amount));
        check("signal[10] maxTransfer", parsed.maxTransfer === String(input.max_transfer));
        check(
          "signal[11] decision",
          parsed.decision === (c.decision === "APPROVE" ? "1" : "0")
        );
        check(
          "signal[12] taskId encoding",
          parsed.taskId === encodeTaskId(taskId).toString()
        );
        // Binding = Poseidon(salt, taskId) using the salt from the store.
        const rec = storeRecord(taskId);
        if (rec && typeof rec.salt === "string" && rec.salt !== "") {
          const h = poseidon([BigInt(rec.salt), encodeTaskId(taskId)]);
          check("signal[0] binding = Poseidon(salt, taskId)", F.toString(h) === parsed.binding);
        } else {
          check("store record with salt exists", false, "no record found");
        }
      }
    }

    // ---- Replay: same task_id again ---------------------------------------
    // A replay is a non-circuit rejection (the circuit would still expect
    // APPROVE), so no proof can exist for it.
    console.log("\n[replay task-valid.json]");
    {
      const body = freshTimestamps(loadSample("task-valid.json"));
      const res = await postAgent(body);
      const j = res.json as Record<string, unknown>;
      check("replayed task is REJECT/TASK_REPLAY", j?.decision === "REJECT" && j?.reason_code === "TASK_REPLAY", `got ${j?.decision}/${j?.reason_code}`);
      check("replayed task carries no proof", j?.proof === null && j?.public_signals === null);
    }

    // ---- Bad HMAC / tampered body -----------------------------------------
    console.log("\n[auth failures]");
    {
      const body = freshTimestamps(loadSample("task-valid.json"));
      // Fresh task id so the replay check does not mask the auth result.
      (body as Record<string, unknown>).task_id = "gk_test_auth_001";
      const bad = await postAgent(body, { signWith: "wrong-secret" });
      check("wrong secret => 401", bad.status === 401, `got ${bad.status}`);
      const tampered = await postAgent(body, { tamperAfterSign: true });
      check("tampered body => 401", tampered.status === 401, `got ${tampered.status}`);
    }

    console.log(`\n[harness] ${passes} passed, ${failures} failed`);
    process.exitCode = failures === 0 ? 0 : 1;
  } finally {
    // Wait for the child to actually exit; SIGKILL if it lingers, so no
    // stale server can hold the port or the store for the next run.
    const exited = new Promise<void>((resolve) => {
      if (server.exitCode !== null) return resolve();
      server.once("exit", () => resolve());
      setTimeout(() => resolve(), 5_000);
    });
    server.kill("SIGTERM");
    await exited;
    if (server.exitCode === null) {
      server.kill("SIGKILL");
      await new Promise((r) => setTimeout(r, 500));
    }
    if (serverLog.includes("ERROR") || failures > 0) {
      console.log("\n--- server log ---\n" + serverLog.slice(-3000));
    }
    // Explicit exit: snarkjs/ffjavascript leave worker handles open that
    // would otherwise keep this process alive indefinitely.
    process.exit(process.exitCode ?? 0);
  }
}

main().catch((err) => {
  console.error("[harness] fatal:", err);
  process.exitCode = 1;
});
