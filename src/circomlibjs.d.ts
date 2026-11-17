// Minimal type declarations for circomlibjs 0.1.x (the package ships no types).
declare module "circomlibjs" {
  export interface PoseidonField {
    toObject(x: unknown): bigint;
    /** Field element to its canonical decimal string (ffjavascript). */
    toString(x: unknown): string;
  }
  export interface Poseidon {
    (inputs: readonly bigint[]): bigint;
    F: PoseidonField;
  }
  export function buildPoseidon(): Promise<Poseidon>;
}
