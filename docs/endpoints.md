# Endpoints — Agent Games (zkVerify) + Kurier + agen ini

Catatan discovery + rencana + eksekusi, ditulis 2026-11-16. Fase RENCANA
selesai 12:47 WIB; fase EKSEKUSI (Steal the VFY) selesai hari yang sama —
kode Steal sudah dibangun + teruji (lihat §5–§7). Sumber kebenaran: docs
resmi platform dulu, lalu bundle JS frontend resmi, lalu artefak circuit
lokal (probe + eksperimen witness read-only), lalu response nyata dari
request uji. Tidak ada endpoint yang ditebak: yang belum terbukti dicatat
di §2.2 / §5 sebagai "belum terverifikasi".

Catatan aturan tugas: **`AGENTS.md` kini ADA di root project ini**
(`~/workspace/proof-gatekeeper/AGENTS.md`) — dibuat minimal saat fase
eksekusi 2026-11-16, sesuai aturan tugas (sebelumnya belum ada).

## 1. Platform — halaman publik (GET, tanpa auth)

| Halaman | Status | Isi yang dipakai |
|---|---|---|
| `https://agentgames.zkverify.io/` | 200 | landing; chunk JS berisi nav + `/api/stats` |
| `/build` | 200 | sumber kebenaran protokol: envelope, deadline 60 dtk (hard), "verification reached a finalized state before approval", Kurier flow, §06 Steal |
| `/guide` | 200 | registrasi: X atau wallet; handle, country, bio, GitHub + wallet opsional (wallet wajib untuk klaim hadiah); kompetisi 21 Okt–21 Nov 2026, tutup 21 Nov 22:00 UTC; hadiah 400.000 VFY (100.000/track, 50/30/20) |
| `/rules` | 200 | §1.1–1.7 (lihat §3 di bawah) |
| `/leaderboard` | 200 | publik |
| `/events`, `/events/proof-gatekeeper`, `/events/steal-the-vfy`, `/events/wildcard` | 200 | detail tiap track; Steal: jadwal 13–17 Nov 2026, turn 5 mnt (~30 dtk/push), Swiss 7 ronde → Top 16 knockout, skor +18/+9/+3, reliabilitas +0..+2, timeout −1/turn, proof invalid −2/turn |
| `/register` | 200 | form registrasi; `?ref=<kode>` mengisi `referralCode` dari query param (terverifikasi di bundle JS) |
| `/dashboard`, `/dashboard/agents`, `/dashboard/practice` | 307 → `/register` | redirect bila tanpa sesi (terverifikasi via curl `-I`); isi dashboard HANYA bisa dilihat dengan sesi login |

## 2. Platform — API (ditemukan di bundle JS / response nyata)

### 2.1 Terverifikasi

| Endpoint | Method | Bukti | Contoh |
|---|---|---|---|
| `/api/circuit-info` | GET publik | curl 2026-11-16, JSON | `{"network":"mainnet","circuits":{"gatekeeper":{"vkHash":"0x6b79c6…","artifacts":{"wasm":"…/circuits/gatekeeper.wasm","zkey":"…/circuits/gatekeeper_final.zkey"}},"vfyPolicy":{"vkHash":"0x6c5650…","artifacts":{"wasm":"…/circuits/vfy-policy.wasm","zkey":"…/circuits/vfy-policy_final.zkey"}}}}` |
| `/api/stats` | GET publik | curl 2026-11-16 | `{"builders":4132,"activeAgents":300,"participants":4132,"proofsSubmitted":1613,"countries":30}` |
| `/api/auth/session` | GET (cookie sesi Auth.js) | response nyata sesi user 2026-11-16: `{"user":{"registrationComplete":true,"competitionUserId":"0391ca70-…","walletAddress":"0x6cf88809b832d8400b5fd2753b86eca8b3e733a2","isAdmin":false},"expires":"2026-12-16T05:34:57.956Z"}`; tanpa cookie → `null` (curl). Nilai token sesi TIDAK dicatat di mana pun. | — |
| `/api/auth/wallet/siwe/nonce` | GET | bundle `0a1e-834m1j3v.js`: `fetch("/api/auth/wallet/siwe/nonce")` → `{nonce}`; lalu client membangun pesan SIWE (chainId, domain, expirationTime, issuedAt, nonce, notBefore, requestId, resources, scheme, uri, version) dan `signMessageAsync`. Library sesi: Auth.js (`__Secure-authjs.session-token`, `BroadcastChannel "next-auth"`). | — |
| `/api/handles/availability?handle=<handle>` | GET, `cache:"no-store"` | bundle `0a1e-834m1j3v.js`, debounce 350 mdtk | respons `{valid, available}`; `ok && valid` → `available ? "available" : "taken"`, selain itu `"taken"` |
| `/api/auth` | (base Auth.js) | bundle `12wikfc8qhg7o.js` | prefix rute Auth.js; sub-rute lain belum dipetakan |

### 2.2 Belum terverifikasi (butuh sesi / observasi dashboard)

| Endpoint (dugaan fungsi) | Alasan belum | Cara verifikasi |
|---|---|---|
| SIWE verify (POST setelah `signMessageAsync`) | path tidak muncul di chunk publik (`/register`, homepage); kemungkinan callback Auth.js/credentials | amati network call saat login wallet di browser user, atau baca chunk dashboard dengan sesi |
| Simpan profil/registrasi (POST form: handle, displayName, contactEmail, twitter, country, bio, referralCode) | path tidak muncul di chunk publik; kemungkinan Next.js Server Action | sama seperti di atas |
| Simpan konfigurasi agen (repo + endpoint URL + Save + preflight) | chunk dashboard butuh auth (307 tanpa sesi) | buka `/dashboard/agents` dengan sesi; baca chunk + network call tombol Save |
| Registrasi commitment Steal (tombol "Register commitment") | sama | amati network call tombol itu; catat method, path, body (commitment hash saja atau strategyParams ikut terkirim) |
| Dispatch practice (tombol dispatch di `/dashboard/practice`) | sama | amati network call dispatch + simpan satu envelope turn Steal asli (format JSON lengkap) |
| Leaderboard / agent profile publik (GET) | belum dicoba | curl halaman `/leaderboard` + profil agen bila ada |

Catatan: token sesi user TIDAK dipakai ulang di tool call pada fase ini
(alasan keamanan kredensial — token tidak boleh masuk log/file). Fakta
non-rahasia dari sesi (wallet terdaftar `0x6cf88809…`, `competitionUserId`,
`registrationComplete: true`) sudah cukup untuk rencana; verifikasi §2.2
dijadwalkan sebagai langkah pertama fase eksekusi, dibantu user (buka
dashboard → paste network call) atau sesi browser yang login.

## 3. Aturan platform yang mengikat rencana (dari `/rules`, terverifikasi)

- Agen = program yang di-host sendiri di HTTPS publik; **dilarang**
  localhost, IP privat, port custom. Platform tidak menjalankan kode kita.
- Respons harus ditandatangani HMAC (`x-agent-games-signature`) dan sampai
  dalam deadline di tiap request. `task_id` = idempotency key (platform
  boleh retry setelah gagal jaringan).
- HMAC secret: 32-byte acak, ditampilkan **sekali** saat registrasi;
  platform menyimpan salinan terenkripsi AES-256-GCM; rotate dari halaman
  settings agen — secret lama langsung mati.
- Offline saat task datang = forfeit (kebijakan publik). Timeout dicatat;
  riwayat uptime dipublikasikan di profil agen. Free-tier yang sleep
  berbahaya.
- Satu GitHub per akun kompetisi; satu akun per orang/tim; multi-akun di
  event yang sama = diskualifikasi langsung. Hadiah hanya ke wallet
  terdaftar; pemenang diverifikasi manual setelah standings freeze.
- Dilarang main manual menggantikan agen.
- Practice mode: format identik dengan scored, tidak pengaruhi leaderboard,
  **dibatasi 10 dispatch per agen aktif per jam**, tercatat di debugging
  history. Tersedia sebelum scored round dibuka.

## 4. Kurier (zkVerify) — sudah dipakai agen Gatekeeper, terverifikasi

- Mainnet `https://api.kurier.xyz/api/v1`, testnet
  `https://api-testnet.kurier.xyz/api/v1` (header API key).
- `POST /register-vk/{key}` → vkHash. `POST /submit-proof/{key}` body
  `{proofType:"groth16", vkRegistered:true, proofOptions:{library:"snarkjs",
  curve:"bn128"}, proofData:{proof, publicSignals, vk:vkHash}}` →
  `{jobId, optimisticVerify}`. `GET /job-status/{key}/{jobId}` poll tiap
  5 dtk: Queued / Valid / Submitted / IncludedInBlock / **Finalized** /
  Failed.
- Gatekeeper: vk `0x6b79c6…` sudah terdaftar mainnet; `KURIER_VK_REGISTERED=true`.
  vfy-policy: vk `0x6c5650…` — status registrasi Kurier BELUM dicek, dan
  **tidak dibutuhkan untuk Steal v1**: agen tidak submit proof Steal ke
  Kurier (platform memverifikasi policy proof sendiri; `proofReference`
  hanya pointer audit opsional per `/build` §06). Bila suatu saat mau
  submit Steal ke Kurier, daftarkan dulu vk vfy-policy (`register-vk`)
  dengan flag terpisah — jangan campur dengan flag Gatekeeper.

## 5. Circuit vfy-policy (Steal the VFY) — TERVERIFIKASI PENUH via eksperimen witness 2026-11-16

Metode: baca `circuits/vfy-policy.wasm` lokal (sudah terverifikasi identik
dengan download resmi, SHA-256 di `src/artifacts.ts`), panggil
`getInputSignalSize` dengan hash FNV-1a tiap nama kandidat (kontrol:
metode yang sama mereproduksi tepat 13 input Gatekeeper yang sudah
diketahui), lalu 4 ronde eksperimen witness dengan `snarkjs.groth16.fullProve`
+ `verify` terhadap vk lokal (script probe hanya di `/tmp`, bukan bagian
project; skrip eksperimen: `/tmp/steal-exp*.cjs`).

- **17 slot input, 10 nama** (terverifikasi lengkap — 9 skalar + 1 array):
  `matchId`, `turnNumber`, `action`, `amount`, `selfBalance`,
  `opponentBalance`, `commitment`, `circuitVersion`, `salt`,
  `strategyParams[8]` (array 8 angka). 9×1 + 8 = 17. ✓
- vk: `nPublic = 9`, vkHash `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`.
- `getWitnessSize = 1909` (Gatekeeper: 647 — circuit Steal lebih besar).
- Artefak lokal: `circuits/vfy-policy.wasm` (2.991.212 B),
  `circuits/vfy-policy_final.zkey` (810.586 B), `circuits/vfy-policy.vk.json`.
- **9 public signals, urutan terverifikasi** (dibaca dari witness):
  `[0] binding, [1] commitment, [2] matchId, [3] turnNumber,
  [4] selfBalance, [5] opponentBalance, [6] action, [7] amount,
  [8] circuitVersion`.
- **Commitment = Poseidon(strategyParams[0..7], salt)** — terverifikasi:
  prove sukses dengan commitment itu; commitment salah → assert gagal
  (template line 72). Nilai default (params `8,18,8,0,0,0,0,0`, salt
  `12345678901234567890`): `18509752657592529527109630018603854483195680471699643211660232613401632907815`.
- **Binding = Poseidon(matchId, turnNumber, circuitVersion)** — terverifikasi
  (MATCH eksplisit di ronde 4). Binding TIDAK tergantung salt, commitment,
  balance, atau aksi; berubah bila turn atau circuitVersion berubah. Jadi
  ini ID per-turn: satu slot proof per (match, turn, version).
- **Encoding `matchId`**: BigInt dari hex tanpa prefix `0x` dan tanpa
  hyphen (UUID → 128-bit). Terverifikasi: UUID
  `9f4e1b2a-1111-2222-3333-444455556666` → signal[2]
  `211752801442691422638169725321264588390`. MatchId 32-byte (256-bit)
  TIDAK muat di field — handler menolaknya (fail-closed).
- **Encoding `action`**: HOLD=0, FORTIFY=1, EXTRACT=2 (terverifikasi:
  action=3 → assert gagal line 140).
- **Arti `strategyParams` (terverifikasi, per assert line template
  `VfyPolicyProof_154`)**:
  - `[0]` extract amount, **1..10** (line 90/95; 0 dan 11 gagal).
  - `[1]` fortify threshold — FORTIFY bila `selfBalance < params[1]`
    (strikt; self == params[1] → EXTRACT boleh).
  - `[2]` hold threshold — HOLD bila `opponentBalance <= params[2]`
    (**INKLUSIF**; opp == params[2] → EXTRACT gagal line 140, HOLD lolos).
  - `[3]` never-extract flag, **{0, 1}** (line 98; 2 gagal). Bila 1:
    FORTIFY bila self < params[1], selain itu HOLD — EXTRACT tidak
    pernah boleh.
  - `[4..7]` reserved, **harus 0** (lines 75–78; 1 dan 99 sama-sama gagal).
- **Aturan amount**: EXTRACT amount harus == params[0] (line 149; 5 dan
  0 gagal saat params[0]=8); HOLD/FORTIFY amount harus 0 (line 153).
- **circuitVersion TIDAK dikonstrain circuit** (version=2 tetap prove +
  verify; signal[8]=2) — platform yang memeriksa versi terhadap
  registrasi. Agen selalu kirim 1 / `"v1"`.
- **Sumber ketiga yang dipakai + dikoreksi**: repo peserta
  `https://github.com/DaddyUnikii/zkverify-agent` (dual-track, `src/stealVfy.js`,
  `src/server.js`, `test/test.js`, `.env.example`) — memberi envelope turn,
  rumus commitment, dan `publicInputsHash`. Dua bug-nya ditemukan lewat
  eksperimen dan TIDAK disalin: (1) `decideMove` pakai `<` strikt untuk
  opponent (circuit pakai `<=`); (2) `params[3]` diabaikan (circuit
  memakainya sebagai flag never-extract). Repo itu juga memakai
  `strategyCommitment.hash` dari envelope bila ada — agen ini selalu
  memakai commitment lokal yang terdaftar (lihat §7).
- **publicInputsHash** (response): keccak256 atas 8 kata 32-byte
  big-endian — commitment, matchId, turn, selfBalance, opponentBalance,
  action, amount, circuitVersion — sesuai rumus repo peserta. **Belum
  terverifikasi terhadap platform** (formula tidak dipublikasikan);
  pointer audit saja, bukan verifikasi utama.

**Masih belum terverifikasi (bukan penghambat kode agen):**
- Endpoint API dashboard untuk registrasi commitment + dispatch practice
  (§2.2) — butuh observasi dengan sesi login; itu aksi dashboard oleh
  user, bukan kode agen.
- Deadline practice 15 vs 60 detik (Gatekeeper) — butuh observasi kedua.

## 6. Agen ini — endpoint sendiri (terverifikasi, live)

- `POST /agent` — Proof Gatekeeper; HMAC-SHA256 atas raw body
  (`x-agent-games-signature`), timing-safe; respons bertanda tangan.
  Deadline platform 60 dtk (hard, `/build`); observasi: satu task practice
  membawa `deadline_at` hanya 15 dtk setelah `issued_at` (kemungkinan
  khusus practice — perlu observasi kedua).
- `POST /agent` — **Steal the VFY** (baru, teruji 2026-11-16): dispatch
  oleh `eventId: "steal-the-vfy"` (bukan field `type`). Envelope
  terverifikasi (dari test repo peserta + circuit):
  `{protocolVersion:"v1", eventId:"steal-the-vfy", mode, matchId (UUID),
  turn (number), state:{selfBalance, opponentBalance (string)},
  strategyCommitment:{hash}}`. Respons:
  `{matchId, turn, action:{type, amount?}, policyProof:{circuitVersion:"v1",
  proof, public_signals, publicInputsHash}, agentTimestamp,
  idempotencyKey:<UUID v5 deterministik dari matchId+turn>}` — `amount` WAJIB absen
  untuk HOLD/FORTIFY. (Koreksi 2026-11-16: format lama
  `steal-<matchId>-turn-<n>` DITOLAK platform — "idempotencyKey: Invalid
  UUID" pada practice dispatch; kini UUID v5, `src/uuidv5.ts`.) Deadline turn 5 mnt (budget internal: min(deadline
  envelope, terima+300 dtk) − 10 dtk reserve); prove lokal ~1 dtk; tanpa
  Kurier (platform verifikasi proof sendiri). Replay turn yang sama →
  respons byte-identik dari cache in-memory (500 entri, FIFO).
  Tanpa `STEAL_VFY_SALT` → 503 `steal_not_configured` (Gatekeeper tetap jalan).
- `GET /health` → `{ok, protocolVersion, mode, uptimeSec, proofsRecorded}`.
- Live: `https://realgood.fly.dev` (app Fly `realgood`, iad, 2 mesin 256 MB,
  `min_machines_running=0` — cold-start ~6–10 dtk). Terdaftar + aktif
  untuk Proof Gatekeeper; endpoint `/agent` + repo
  `https://github.com/hokireceh/Realgood` sudah diisi di dashboard.
  **Steal BELUM di-deploy / didaftarkan**: kode selesai + teruji lokal,
  commitment strategi v1
  `0x2a8660c949bcb35d138d9b304c1bf995f0bcd975e580d905369c167449606324`
  (params `8,18,8,0,0,0,0,0`) siap ditempel ke dashboard; deploy + registrasi
  + practice turn masih menunggu keputusan user (juga `min_machines_running=1`
  belum diputuskan — soal biaya cold-start vs bonus reliabilitas).
- Asumsi yang masih terbuka (di `README.md`): encoding `taskId`
  (keccak256 mod FIELD_PRIME) dan algoritma HMAC (sha256) — keduanya
  diisolasi di satu fungsi/env masing-masing; plus rumus
  `publicInputsHash` Steal (lihat §5).

## 7. Alur request (ringkas; detail di rencana)

1. **Auth akun (dashboard):** X OAuth ATAU wallet (SIWE):
   `GET /api/auth/wallet/siwe/nonce` → bangun pesan SIWE → sign di wallet
   → verify (endpoint belum terverifikasi) → cookie sesi Auth.js
   `__Secure-authjs.session-token` → `GET /api/auth/session` → user.
2. **Registrasi agen:** isi repo + endpoint `https://…/agent` → Rotate
   Secret (sekali) → simpan `AGENT_GAMES_HMAC_SECRET` → restart →
   preflight bertanda tangan dari dashboard → agen aktif.
3. **Task Gatekeeper:** platform POST `/agent` (HMAC) → cek deterministik
   → prove lokal (~1 dtk) → submit Kurier → poll Finalized (strict mode,
   ≤40 dtk) → respons bertanda tangan ≤60 dtk.
4. **Turn Steal (TERIMPLEMENTASI 2026-11-16, `src/steal-handler.ts`):**
   platform POST `/agent` (HMAC) berisi `eventId:"steal-the-vfy"`,
   matchId, turn, state (selfBalance/opponentBalance), strategyCommitment
   opsional → agen pilih aksi sesuai `strategyParams` (deterministik,
   `src/policy.ts`) → prove policy lokal (~1 dtk) + verifikasi lokal
   terhadap vk vfy-policy → respons echo matchId+turn + aksi +
   `policyProof{circuitVersion:"v1", proof, public_signals,
   publicInputsHash}` + `idempotencyKey` deterministik; deadline 5
   mnt/turn. Tanpa Kurier. Envelope `strategyCommitment.hash` yang beda
   dari commitment terdaftar hanya di-log sebagai warning — proof selalu
   memakai commitment lokal (memakai hash envelope akan membuat proof
   gagal karena circuit menurunkan commitment dari params+salt lokal).
5. **Registrasi Steal (LANGKAH USER BERIKUTNYA):** `npm run steal-commitment`
   → tempel commitment hex ke dashboard ("Commitment hash") → Register
   commitment → preflight + practice turn → gabung ronde Swiss berikutnya
   (jadwal 13–17 Nov; commitment beku mid-match, redeploy antar ronde).
   Strategi v1: params `8,18,8,0,0,0,0,0`, salt sudah di `.env` lokal
   (mode 600, gitignored — JANGAN commit; harus diset juga sebagai Fly
   secret saat deploy). Mengubah params/salt = commitment baru =
   registrasi ulang.
