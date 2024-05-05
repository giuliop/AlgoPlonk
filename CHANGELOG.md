# Changelog

## v0.1.4
*Date: 2024-05-05*

### Added
- **testutils package**:
  - Introduced additional test utility functions:
    - `SerializeCompiledCircuit` / `DeserializeCompiledCircuit` to/from file
    - `Substitute` for template variable substitution in TEAL files
    - `EnsureFunded` for funding accounts on a local network.
    - `ShouldRecompile` for conditional recompilation of target files

### Changed
- **API changes**:

  - Renamed `WriteProofAndPublicInputs` to `ExportProofAndPublicInputs`
  - Changed signature of `WriteProof` and `WritePublicInputs` to accept an `io.Writer` instead of a filename string
  - Modified the type of the smart contracts verifier method arguments to `DynamicArray` from `StaticArray` for better ease of passing methods in

- **Other**:
  - **testutils package**:
    - Split AlgoSDK wrapper functions into a separate `algosdkwrapper` package within `testutils`
    - Changed `ExecuteAbiCall` signature to include a `boxes` argument
    - Changed `CompileWithPuyapy` signature to include an `options` argument, to pass to the Puyapy compiler

  - **Documentation**:
    - Made naming in the codebase more consistent
