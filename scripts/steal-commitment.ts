// Print the Steal-the-VFY strategy commitment for dashboard registration.
//
// Usage: npm run steal-commitment
// Reads STEAL_VFY_PARAMS + STEAL_VFY_SALT from .env (never prints the
// salt — it stays secret on the server). The printed commitment hex is
// public: paste it into the Agent Games dashboard ("Commitment hash" in
// the Steal the VFY section). Changing params or salt afterwards
// produces a DIFFERENT commitment and requires re-registration.
import dotenv from "dotenv";
import { parseStrategyParams } from "../src/policy";
import { computeCommitment, parseSalt } from "../src/steal-circuit";

dotenv.config();

async function main(): Promise<void> {
  const paramsRaw = process.env.STEAL_VFY_PARAMS?.trim() || "8,18,8,0,0,0,0,0";
  const saltRaw = process.env.STEAL_VFY_SALT?.trim();
  if (!saltRaw) {
    console.error(
      "STEAL_VFY_SALT is not set. Generate one (random, never reused elsewhere):\n" +
        '  node -e "console.log(\'0x\' + require(\'crypto\').randomBytes(16).toString(\'hex\'))"\n' +
        "then put it in .env as STEAL_VFY_SALT=<value> (and as a Fly secret at deploy time)."
    );
    process.exit(1);
  }
  const params = parseStrategyParams(paramsRaw);
  const salt = parseSalt(saltRaw);
  const commitment = await computeCommitment(params, salt);
  console.log("Strategy Params :", params.map(String).join(","));
  console.log("Commitment (hex):", commitment.hex);
  console.log("Commitment (dec):", commitment.decimal);
  process.exit(0);
}

main().catch((err) => {
  console.error("[steal-commitment] fatal:", (err as Error).message);
  process.exit(1);
});
