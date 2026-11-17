// Minimal type declarations for snarkjs 0.7.x (the package ships no types).
declare module "snarkjs" {
  export namespace groth16 {
    function fullProve(
      input: Record<string, unknown>,
      wasmPath: string,
      zkeyPath: string
    ): Promise<{ proof: unknown; publicSignals: unknown }>;
    function verify(
      vk: Record<string, unknown>,
      publicSignals: unknown,
      proof: unknown
    ): Promise<boolean>;
  }
  export namespace zKey {
    function exportVerificationKey(zkeyPath: string): Promise<Record<string, unknown>>;
  }
}
