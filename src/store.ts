// Durable local record of every answered task.
// Used for (a) replay protection — task ids and proof bindings must never be
// reused — and (b) dispute evidence (checklist item 09: proof and
// transaction references are retained). The file lives in DATA_DIR and is
// gitignored; it contains salts (private per-task randomness) and must never
// be shared or committed.
import fs from "node:fs";
import path from "node:path";

export interface ProofRecord {
  taskId: string;
  binding: string;
  decision: string;
  reasonCode: string;
  salt: string;
  publicSignals: string[];
  proofTx: string | null;
  kurierJobId: string | null;
  kurierStatus: string | null;
  receivedAtMs: number;
  respondedAtMs: number;
}

export class ProofStore {
  private readonly filePath: string;
  private records: ProofRecord[] = [];
  private readonly taskIds = new Set<string>();
  private readonly bindings = new Set<string>();

  constructor(dataDir: string) {
    fs.mkdirSync(dataDir, { recursive: true });
    this.filePath = path.join(dataDir, "proofs.json");
    this.load();
  }

  private load(): void {
    if (!fs.existsSync(this.filePath)) return;
    try {
      const parsed = JSON.parse(fs.readFileSync(this.filePath, "utf8")) as unknown;
      if (!Array.isArray(parsed)) return;
      for (const r of parsed as ProofRecord[]) {
        if (r && typeof r.taskId === "string" && typeof r.binding === "string") {
          this.records.push(r);
          this.taskIds.add(r.taskId);
          this.bindings.add(r.binding);
        }
      }
    } catch (err) {
      console.error(`[store] could not load ${this.filePath}:`, (err as Error).message);
    }
  }

  hasTaskId(taskId: string): boolean {
    return this.taskIds.has(taskId);
  }

  hasBinding(binding: string): boolean {
    return this.bindings.has(binding);
  }

  record(rec: ProofRecord): void {
    this.records.push(rec);
    this.taskIds.add(rec.taskId);
    this.bindings.add(rec.binding);
    this.persist();
  }

  private persist(): void {
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.records, null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  get count(): number {
    return this.records.length;
  }
}
