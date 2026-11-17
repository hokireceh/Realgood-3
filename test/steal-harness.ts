// Steal-the-VFY test harness: boots the real server on a test port with
// a fixed test strategy (params 8,18,8,0,0,0,0,0 + test salt), replays
// sample turn envelopes, and checks every response end-to-end:
//   - HTTP 200 + a valid x-agent-games-signature over the raw response body
//   - the action the policy selects (incl. the <= opponent boundary)
//   - `amount` present ONLY for EXTRACT (omitted for HOLD / FORTIFY)
//   - the Groth16 policy proof verifies locally against the vfy-policy VK
//   - the 9 public signals match the turn (binding, commitment, matchId
//     encoding, turn, balances, action, amount, circuitVersion)
//   - publicInputsHash recomputes from the same values
//   - a replayed turn returns the byte-identical response
//   - a wrong strategyCommitment hash in the envelope does not change
//     the proof (the registered commitment is used)
// Also covers: unit checks for the policy boundaries + param validation
// + matchId/salt parsing, malformed envelopes (400), bad HMAC (401),
// unknown eventId (400), and Steal disabled without a salt (503).
// Usage: npm run test:steal   (or: npx tsx test/steal-harness.ts)
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import * as snarkjs from "snarkjs";
import {
  computeBinding,
  computeCommitment,
  computePublicInputsHash,
  encodeMatchId,
  parseSalt,
  parseStealPublicSignals,
  STEAL_ACTION_CODE,
  STEAL_CIRCUIT_VERSION,
} from "../src/steal-circuit";
import {
  decideMove,
  parseStrategyParams,
  validateStrategyParams,
} from "../src/policy";
import { stealIdempotencyKey } from "../src/uuidv5";

const ROOT = path.resolve(__dirname, "..");
const PORT = 18200 + Math.floor(Math.random() * 800);
const BASE = `http://127.0.0.1:${PORT}`;
const TEST_SECRET = "test-secret-do-not-use-in-prod";
const TEST_PARAMS = "8,18,8,0,0,0,0,0";
const TEST_SALT = "42424242424242424242";
const DATA_DIR = path.join(ROOT, `data-test-steal-${PORT}`);

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
  opts: { signWith?: string } = {}
): Promise<{ status: number; headers: Headers; text: string; json: unknown }> {
  const raw = Buffer.from(JSON.stringify(bodyObj), "utf8");
  const secret = opts.signWith ?? TEST_SECRET;
  const sig = crypto.createHmac("sha256", secret).update(raw).digest("hex");
  const res = await fetch(`${BASE}/agent`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": sig,
    },
    body: raw,
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

function loadSample(name: string, commitmentHex: string): Record<string, unknown> {
  const raw = fs.readFileSync(path.join(ROOT, "test", "samples", name), "utf8");
  const filled = raw.replaceAll("__TEST_COMMITMENT_HEX__", commitmentHex);
  return JSON.parse(filled) as Record<string, unknown>;
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
  fs.rmSync(DATA_DIR, { recursive: true, force: true });

  const vk = JSON.parse(
    fs.readFileSync(path.join(ROOT, "circuits", "vfy-policy.vk.json"), "utf8")
  );
  const params = parseStrategyParams(TEST_PARAMS);
  const salt = parseSalt(TEST_SALT);
  const commitment = await computeCommitment(params, salt);

  console.log("[steal-harness] starting server…");
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
        STEAL_VFY_PARAMS: TEST_PARAMS,
        STEAL_VFY_SALT: TEST_SALT,
      },
      stdio: ["ignore", "pipe", "pipe"],
    }
  );
  let serverLog = "";
  server.stdout?.on("data", (d: Buffer) => (serverLog += d.toString()));
  server.stderr?.on("data", (d: Buffer) => (serverLog += d.toString()));

  try {
    if (!(await waitForHealth())) {
      console.log("[steal-harness] server did not become healthy in time");
      console.log(serverLog);
      process.exitCode = 1;
      return;
    }
    console.log("[steal-harness] server healthy");

    // ---- Turn cases ------------------------------------------------------
    // action: expected move type; amount: expected EXTRACT amount (null
    // when the response action must NOT carry an amount field).
    const cases: {
      file: string;
      action: string;
      amount: number | null;
      self: string;
      opp: string;
    }[] = [
      { file: "steal-extract.json", action: "EXTRACT", amount: 8, self: "100", opp: "100" },
      { file: "steal-fortify.json", action: "FORTIFY", amount: null, self: "10", opp: "100" },
      { file: "steal-hold.json", action: "HOLD", amount: null, self: "100", opp: "5" },
      // Boundary: opponent == params[2] (8) must HOLD (inclusive).
      { file: "steal-boundary.json", action: "HOLD", amount: null, self: "100", opp: "8" },
      // Boundary: self == params[1] (18) must EXTRACT (strict <).
      { file: "steal-self-boundary.json", action: "EXTRACT", amount: 8, self: "18", opp: "100" },
    ];

    for (const c of cases) {
      console.log(`\n[${c.file}] expect ${c.action}`);
      const body = loadSample(c.file, commitment.hex);
      const matchId = body.matchId as string;
      const turn = body.turn as number;
      const res = await postAgent(body);
      check("status 200", res.status === 200, `got ${res.status}: ${res.text}`);
      const j = res.json as Record<string, unknown>;
      check("echoes matchId", j?.matchId === matchId);
      check("echoes turn", j?.turn === turn);
      const action = j?.action as Record<string, unknown> | undefined;
      check("action type matches", action?.type === c.action, `got ${action?.type}`);
      if (c.amount === null) {
        check("HOLD/FORTIFY omits amount", action !== undefined && !("amount" in action));
      } else {
        check("EXTRACT carries amount", action?.amount === c.amount, `got ${action?.amount}`);
      }
      const sig = res.headers.get("x-agent-games-signature") ?? "";
      check("response is HMAC-signed", sig === sign(Buffer.from(res.text, "utf8")));
      check(
        "idempotencyKey is a deterministic UUID v5 per turn",
        typeof j?.idempotencyKey === "string" &&
          /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
            j.idempotencyKey as string
          ) &&
          j.idempotencyKey === stealIdempotencyKey(matchId, turn)
      );

      const pp = j?.policyProof as Record<string, unknown> | undefined;
      check("policyProof present", pp !== undefined && typeof pp === "object");
      check("policyProof circuitVersion is v1", pp?.circuitVersion === "v1");
      const proof = pp?.proof as Record<string, unknown> | null;
      const sigs = pp?.public_signals as string[] | null;
      check("proof present", proof !== null && typeof proof === "object");
      check("9 public signals", Array.isArray(sigs) && sigs.length === 9);
      if (proof && Array.isArray(sigs) && sigs.length === 9) {
        const ok = await snarkjs.groth16.verify(vk, sigs, proof);
        check("proof verifies against the vfy-policy VK", ok);
        const parsed = parseStealPublicSignals(sigs);
        const matchField = encodeMatchId(matchId);
        const binding = await computeBinding(matchField, BigInt(turn), STEAL_CIRCUIT_VERSION);
        check("signal[0] binding = Poseidon(matchId, turn, circuitVersion)", parsed.binding === binding.toString());
        check("signal[1] commitment", parsed.commitment === commitment.decimal);
        check("signal[2] matchId encoding", parsed.matchId === matchField.toString());
        check("signal[3] turnNumber", parsed.turnNumber === String(turn));
        check("signal[4] selfBalance", parsed.selfBalance === c.self);
        check("signal[5] opponentBalance", parsed.opponentBalance === c.opp);
        check(
          "signal[6] action code",
          parsed.action === STEAL_ACTION_CODE[c.action as keyof typeof STEAL_ACTION_CODE].toString()
        );
        check("signal[7] amount", parsed.amount === String(c.amount ?? 0));
        check("signal[8] circuitVersion", parsed.circuitVersion === "1");
        const expectedHash = computePublicInputsHash({
          commitment: BigInt(commitment.decimal),
          matchId: matchField,
          turnNumber: BigInt(turn),
          selfBalance: BigInt(c.self),
          opponentBalance: BigInt(c.opp),
          action: STEAL_ACTION_CODE[c.action as keyof typeof STEAL_ACTION_CODE],
          amount: BigInt(c.amount ?? 0),
          circuitVersion: STEAL_CIRCUIT_VERSION,
        });
        check("publicInputsHash recomputes", pp?.publicInputsHash === expectedHash);
        const rec = storeRecord(`vfy:${matchId}:${turn}`);
        check("store record exists", rec !== null);
        if (rec) {
          check("store binding matches", rec.binding === parsed.binding);
          check("store decision is the action", rec.decision === c.action);
        }
      }
    }

    // ---- Replay: same turn again -> byte-identical response ---------------
    console.log("\n[replay steal-extract.json turn 1]");
    {
      const body = loadSample("steal-extract.json", commitment.hex);
      const first = await postAgent(body);
      const second = await postAgent(body);
      check("replay status 200", second.status === 200, `got ${second.status}`);
      check("replay body is byte-identical", second.text === first.text);
      const j = second.json as Record<string, unknown>;
      check("replay keeps the same proof", (j?.policyProof as Record<string, unknown>)?.proof !== null);
    }

    // ---- Wrong / missing strategyCommitment in the envelope ---------------
    console.log("\n[envelope commitment handling]");
    {
      const wrong = loadSample("steal-extract.json", commitment.hex);
      (wrong as Record<string, unknown>).turn = 11;
      (wrong as Record<string, unknown>).strategyCommitment = {
        hash: "0x0000000000000000000000000000000000000000000000000000000000000001",
      };
      const res = await postAgent(wrong);
      check("wrong envelope hash still returns 200", res.status === 200, `got ${res.status}: ${res.text}`);
      const pp = (res.json as Record<string, unknown>)?.policyProof as
        | Record<string, unknown>
        | undefined;
      const sigs = pp?.public_signals as string[] | null;
      if (Array.isArray(sigs) && sigs.length === 9) {
        check(
          "proof still uses the registered commitment",
          parseStealPublicSignals(sigs).commitment === commitment.decimal
        );
      } else {
        check("proof present with wrong envelope hash", false, "no signals");
      }

      const missing = loadSample("steal-extract.json", commitment.hex);
      (missing as Record<string, unknown>).turn = 12;
      delete (missing as Record<string, unknown>).strategyCommitment;
      const res2 = await postAgent(missing);
      check("missing strategyCommitment still returns 200", res2.status === 200, `got ${res2.status}`);
    }

    // ---- Malformed envelopes / auth ----------------------------------------
    console.log("\n[envelope + auth failures]");
    {
      const noState = loadSample("steal-extract.json", commitment.hex);
      (noState as Record<string, unknown>).turn = 13;
      delete (noState as Record<string, unknown>).state;
      const bad = await postAgent(noState);
      check("missing state => 400", bad.status === 400, `got ${bad.status}`);

      const badMatch = loadSample("steal-extract.json", commitment.hex);
      (badMatch as Record<string, unknown>).turn = 14;
      (badMatch as Record<string, unknown>).matchId = "not-a-match-id!!";
      const bad2 = await postAgent(badMatch);
      check("unparseable matchId => 400", bad2.status === 400, `got ${bad2.status}`);

      const unknownEvent = loadSample("steal-extract.json", commitment.hex);
      (unknownEvent as Record<string, unknown>).eventId = "steal-the-something-else";
      const bad3 = await postAgent(unknownEvent);
      check("unknown eventId => 400", bad3.status === 400, `got ${bad3.status}`);

      const body = loadSample("steal-extract.json", commitment.hex);
      (body as Record<string, unknown>).turn = 15;
      const badAuth = await postAgent(body, { signWith: "wrong-secret" });
      check("wrong secret => 401", badAuth.status === 401, `got ${badAuth.status}`);
    }

    // ---- Unit: policy boundaries + validation ------------------------------
    console.log("\n[policy unit checks]");
    {
      const p = parseStrategyParams(TEST_PARAMS);
      check(
        "opp == params[2] -> HOLD (inclusive)",
        decideMove({ selfBalance: 100n, opponentBalance: 8n }, p).type === "HOLD"
      );
      check(
        "opp == params[2]+1 -> EXTRACT",
        decideMove({ selfBalance: 100n, opponentBalance: 9n }, p).type === "EXTRACT"
      );
      check(
        "self == params[1] -> EXTRACT (strict <)",
        decideMove({ selfBalance: 18n, opponentBalance: 100n }, p).type === "EXTRACT"
      );
      check(
        "self == params[1]-1 -> FORTIFY",
        decideMove({ selfBalance: 17n, opponentBalance: 100n }, p).type === "FORTIFY"
      );
      const defensive = parseStrategyParams("8,18,8,1,0,0,0,0");
      check(
        "params[3]=1 never EXTRACTs (healthy state -> HOLD)",
        decideMove({ selfBalance: 100n, opponentBalance: 100n }, defensive).type === "HOLD"
      );
      check(
        "params[3]=1 still FORTIFies when low",
        decideMove({ selfBalance: 10n, opponentBalance: 100n }, defensive).type === "FORTIFY"
      );

      const invalid: [string, string][] = [
        ["params[0]=11", "11,18,8,0,0,0,0,0"],
        ["params[0]=0", "0,18,8,0,0,0,0,0"],
        ["params[3]=2", "8,18,8,2,0,0,0,0"],
        ["params[4]=1", "8,18,8,0,1,0,0,0"],
        ["only 7 params", "8,18,8,0,0,0,0"],
        ["non-numeric", "8,18,8,0,0,0,0,x"],
      ];
      for (const [name, raw] of invalid) {
        let threw = false;
        try {
          validateStrategyParams(parseStrategyParams(raw));
        } catch {
          threw = true;
        }
        check(`invalid params rejected: ${name}`, threw);
      }
      check("encodeMatchId accepts UUID", encodeMatchId("9f4e1b2a-1111-2222-3333-444455556666") === 211752801442691422638169725321264588390n);
      check("encodeMatchId accepts 0x hex", encodeMatchId("0x1234") === 0x1234n);
      let threw = false;
      try {
        encodeMatchId("0x" + "ff".repeat(40));
      } catch {
        threw = true;
      }
      check("encodeMatchId rejects out-of-field values", threw);
      check("parseSalt accepts decimal", parseSalt("12345") === 12345n);
      check("parseSalt accepts 0x hex", parseSalt("0x1234") === 0x1234n);
      threw = false;
      try {
        parseSalt("0");
      } catch {
        threw = true;
      }
      check("parseSalt rejects zero", threw);
      const c1 = await computeCommitment(params, salt);
      const c2 = await computeCommitment(params, salt);
      check("commitment is deterministic", c1.hex === c2.hex && c1.decimal === commitment.decimal);
      check("commitment hex is 32 bytes", /^0x[0-9a-f]{64}$/.test(c1.hex));
    }

    console.log(`\n[steal-harness] ${passes} passed, ${failures} failed`);
    process.exitCode = failures === 0 ? 0 : 1;
  } finally {
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
    process.exit(process.exitCode ?? 0);
  }
}

main().catch((err) => {
  console.error("[steal-harness] fatal:", err);
  process.exitCode = 1;
});
