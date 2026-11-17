# AGENTS.md — realgood-3

Minimal working notes for this project (Agent Games — Proof Gatekeeper agent,
TypeScript, Node.js). Agent ke-3 di akun yang sama dengan Realgood (slot 3/3),
didaftarkan 2026-11-17: nama Realgood-3, kedua track (Proof Gatekeeper +
Steal the VFY), strategi Steal DEFENSIF params `5,25,12,0,0,0,0,0` (extract
5, fortify bila saldo < 25, hold bila lawan <= 12) — beda dari Realgood `8,18,8,0,0,0,0,0` dan Realgood-2 `10,12,3,0,0,0,0,0`. Deploy di **Vercel** (Hobby, gratis), repo publik
`hokireceh/Realgood-3`. Kode dasar disalin dari `~/workspace/proof-gatekeeper/`
(Realgood) — JANGAN ubah repo/deploy Fly Realgood yang live.

## Stack & commands

- TypeScript (CommonJS output, `tsc` → `dist/`). No framework, plain HTTP.
- `npm install` · `npm run build` (tsc) · `npm test` (build + `tsx test/harness.ts`,
  end-to-end replay harness — must stay 133 checks, 0 failures) ·
  `npm start` (`node dist/server-main.js`) · `npm run dev` (`tsx src/server-main.ts`) ·
  `npm run fetch-circuits` (download circuit binaries explicitly).
- Runtime deps only: `dotenv`, `ethers`, `snarkjs`, `circomlibjs` (Poseidon
  is used at runtime by the Steal track). Dev: `@types/node`, `tsx`,
  `typescript`.

## Conventions (locked)

- **Fail closed.** On any timeout, error, or uncertainty the agent REJECTs —
  never approve by default. No model makes the final call.
- **Circuit artifacts are fetched, never committed.** `circuits/*.wasm` and
  `circuits/*_final.zkey` are gitignored; `src/artifacts.ts` downloads them
  from `agentgames.zkverify.io/circuits` at startup and verifies SHA-256.
  Only `*.vk.json` is committed.
- **Secrets live only in env.** `.env` (mode 600) and `data/` are gitignored.
  Never print, commit, or paste a secret, API key, or session token. The
  HMAC secret comes from the dashboard Rotate Secret (shown once).
- **No breaking changes to the live Gatekeeper path.** `POST /agent` +
  `GET /health` behaviour, the decision checklist order, and the strict
  Kurier-Finalized mode stay as-is unless the user explicitly approves a
  change. New tracks go on separate routes/files.
- **Verify before reporting.** Worker/cron claims are re-checked against
  `state/*` and on-chain data; BigInt math via script, never by hand.
- **Endpoint source of truth:** `docs/endpoints.md` — every endpoint there
  carries method, URL, headers, example payload/response, and confidence
  (terverifikasi / belum). Undocumented endpoints are only used in code
  after real request/response proof; unverified ones are marked and never
  used in production paths.
- **Protocol assumptions are isolated.** `taskId` encoding lives only in
  `src/circuit.ts → encodeTaskId`; HMAC algorithm only in `HMAC_ALGORITHM`
  env. If the platform documents something different, change only that spot.
- **Tests are the contract.** `test/harness.ts` replays real task samples
  and checks every public signal + local proof verification. New tracks get
  their own harness file; never weaken the existing one.
- **Deploy: Vercel (Hobby, gratis) — Functions via `builds` + `routes`.**
  Vercel CLI 65 memperlakukan project Node polos sebagai **server**:
  build default WAJIB punya entrypoint server (`package.json "main"`)
  dan mengabaikan `api/` — server mode SUDAH DICOBA dan **POST ke
  server itu HANG dari VM ini** (GET /health 200, semua POST timeout;
  lihat catatan POST di bawah). Solusi yang JALAN: `vercel.json` pakai
  legacy **`builds`** (`@vercel/node` untuk `api/agent.ts` +
  `api/health.ts`) + **`routes`** (`/agent` + `/health` + `/api/*` →
  function masing-masing) — build menghasilkan
  `.vercel/output/functions/api/*.func` dan routing bekerja (GET
  /health + GET /api/health 200). Syarat: **framework project di
  dashboard HARUS `null`** (bukan `"node"`; diubah via API
  `PATCH /v9/projects/realgood-3 {framework: null}` — tanpa ini build
  tetap memaksa server entrypoint; tanpa `"main"` di package.json
  build gagal "No entrypoint found", DENGAN builds config build jalan).
  `package.json` TIDAK punya `"main"` (sengaja — `npm start` memanggil
  `dist/server-main.js` secara eksplisit, tidak butuh `"main"`).
  - **CATATAN POST (blocker verifikasi, BUKAN bug kode):** dari VM ini,
    SEMUA request POST ke `*.vercel.app` HANG tanpa respons (teruji:
    POST /agent, POST /api/agent, POST /api/health — bahkan POST tanpa
    body, bahkan ke project Vercel LAIN `tzero-app.vercel.app`, bahkan
    via `vercel curl` dengan protection bypass), sementara GET ke
    domain yang sama 200 dalam ~1–3 dtk DAN POST ke host lain
    (realgood.fly.dev → 401 dalam 0,9 dtk, api.vercel.com, api.github.com)
    normal. POST /api/health SEHARUSNYA 405 instan (handler cek method
    SEBELUM init) — jadi request tidak pernah sampai ke handler: ini
    masalah jaringan/egress VM → edge Vercel untuk POST, bukan kode.
    **Verifikasi POST (preflight bertanda tangan + test turn Steal)
    HARUS dilakukan dari jaringan lain (browser) sebelum registrasi.**
  - `*.vk.json` are statically imported by `src/context.ts` (bundled
    copies in `src/*.vk.json`, same bytes as `circuits/*.vk.json`) and
    written into the circuits dir at init when missing; binary
    wasm/zkey are downloaded to `/tmp` at cold start.
  - **Keterbatasan serverless:** proof store (`data/proofs.json`) +
    cache respons Steal bersifat per-instance (ephemeral) — replay
    protection antar-instance mengandalkan idempotency `task_id` dari
    platform (keputusan deterministik yang sama). Jangan andalkan
    `proofsRecorded` di /health sebagai hitungan global.
  - Batas Hobby (Fluid Compute, docs resmi): durasi 300 dtk, memori 2 GB,
    bundle 250 MB — Gatekeeper APPROVE ~23 dtk, Steal ~2 dtk, peak memori
    prove ~300 MB: semua muat. JANGAN upgrade ke Pro / layanan berbayar
    tanpa persetujuan user.
