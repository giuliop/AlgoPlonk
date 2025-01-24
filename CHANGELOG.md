# Changelog

## v0.1.8
*Date: 2025-10-17*

### Added
- **utils package**
  - Added `func ShouldRecompile` helper to determine if source files need recompilation
  - Split `func AbiEncodeProofAndPublicInputs` into two functions:
    - `func AbiEncodeProofAndPublicInputs` to encode the proof and public inputs in abi format
    - `func ProofAndPublicInputsForAtomicComposer` to return the proof and public inputs as expected by the AtomicTransactionComposer to create the app args

## v0.1.7
*Date: 2025-10-16*

### Added
- **utils package**
  - New `utils` package which includes functions and types to support compilation and serialization / deserialization

### Changed
- **testutils package**
  - Functions and types related to compilation and serialization / deserialization moved to new utils package:
    - `func CompileWithPuyaPy`
    - `func RenamePuyaPyOutput`
    - `func AbiEncodeProofAndPublicInputs`
    - `func SerializeCompiledCircuit`
    - `func DeserializeCompiledCircuit`
    - `type CompiledCircuitBytes`

## v0.1.6
*Date: 2025-01-03*

### Added
- **New Feature: Logicsig Verifiers**
  - `AlgoPlonk` now supports the generation of **logicsig verifiers** in addition to **smart contract verifiers**

### Changed
- **API changes**:
  - Changed signature of `WritePuyaPyVerifier` to include `verifier.OutputType` for specifying verifier types (`LogicSig` or `SmartContract`)
- **testutils package**:
  - overhauled to better support testing
  - added support to use a custom devnet in addition to algokit localnet
- **Dependencies**
  - Go v1.22
  - gnark v0.11.0
  - gnark-crypto v0.14.0

### GPG Key
The signing GPG key is now `3BCAD2CB70EDF387D682A2C0767CDA51BA8C0284`, changed from `81E0FB63130466B782D4859D6C036245DBDB025D`.

## v0.1.5
*Date: 2024-05-13*

### Changed
- **Updates to match changes in gnark v0.10.0**
  - Changed verifiers to reflect gnark updating to new version of Plonk paper
  - Changed internal functions to match new gnark-crypto API


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
