This file provides guidance to AI agents when working with code in this repository.

## What this is

AlgoPlonk is a Go library that auto-generates Algorand smart contract / logicsig verifiers from gnark plonk circuits. It supports the BN254 and BLS12-381 curves (the ones with AVM elliptic curve opcodes); custom gates are not supported. Pin gnark/gnark-crypto to the versions in `go.mod` for compatibility.

## Commands

```sh
make test        # runs `rm ./testutils/generated/*` then `go test -v ./...`
make examples    # runs `rm ./generated/*` then every examples/**/main.go
make all         # examples then tests

go test -run TestLogicsigVerifier ./testutils   # single test
go test . ./setup ./verifier                    # localnet-free package tests
```

External requirements for integration tests (`testutils` package) and examples:
- Docker must be running before starting localnet; `algokit localnet start` uses Docker containers.
- A local Algorand network with default algokit configuration must be running (`algokit localnet start`). Connection defaults (algod on localhost:4001, etc.) are at the top of `testutils/algosdkwrapper/setup.go`.
- `algokit` on PATH: generated Python verifiers are compiled by shelling out to `algokit compile py` (see `utils.CompileWithPuyaPy`).

Unit tests in the root, `setup`, and `verifier` packages run without a localnet (the trusted-setup tests are slow but self-contained). `make test` and `go test ./...` include the `testutils` integration tests, so they need localnet and algokit. The `make` cleanup commands do not use `rm -f`; if a generated directory is empty, create or leave a placeholder file before relying on those targets.

## The pipeline (big picture)

1. **Compile** (`algoplonk.go`): `ap.Compile(circuit, curve, setupName)` compiles a gnark circuit and runs the plonk setup, returning a `CompiledCircuit` (constraint system + proving/verifying keys).
2. **Generate verifier** (`verifier` package): `CompiledCircuit.WritePuyaPyVerifier` renders Python (PuyaPy) source for either a `verifier.LogicSig` or `verifier.SmartContract` via Go `text/template`. There are four templates — `templateLogicSig{BN254,BLS12_381}.go` and `templateSmartContract{BN254,BLS12_381}.go` — which are Go files holding the full Python source as template strings; the verifying-key points/constants get baked into the generated code. The generated contract is always named `Verifier` (`verifier.DefaultFileName`); after PuyaPy compilation, rename the emitted `.teal`, `.approval.teal`, `.clear.teal`, `.arc56.json`, and `.puya.map` files with `utils.RenamePuyaPyOutput`.
3. **Compile to TEAL**: `utils.CompileWithPuyaPy` invokes `algokit compile py`.
4. **Prove & export** (`algoplonk.go`, `helper.go`): `CompiledCircuit.Verify(assignment)` produces a `VerifiedProof`; `ExportProofAndPublicInputs` writes the binary blobs the AVM verifier expects. BN254 proofs use gnark's `MarshalSolidity`; BLS12-381 has a hand-rolled marshaller in `helper.go`.
5. **Verify on-chain** (`testutils`, `testutils/algosdkwrapper`): helpers deploy apps and build the app-call transaction groups (with fee pooling / opcode-budget padding) that exercise the verifier on localnet.

## Key conventions and gotchas

- **Trusted setups** (`setup` package): the `Name` enum and `setups` map in `setup/setup.go` form a registry; pk.bin/vk.bin parameters are embedded via `go:embed` from per-ceremony subdirectories (note the `EethereumKzgCeremonyBLS12_381` directory name is intentionally spelled with the double E). Steps for adding a new setup are documented in a comment above the `Name` constants. `TestOnly*` setups use `unsafekzg` and must never be used in production. Each ceremony subdirectory has a `doc.go`/`audit.go` describing how to audit the parameters against the original source.
- **Logicsig verifiers** sign an app-call transaction and read the proof and public inputs from application args 1 and 2 (arg 0 is the ARC4 method selector). They are stateless proof predicates, not escrow accounts: they reject rekeying but deliberately do not bind to an app id, method, or group shape — app-specific authorization belongs in the consuming application.
- **Smart contract verifiers** are ARC4 contracts with `create`/`update`/`make_immutable`/`verify` methods; `update` is blocked once `immutable` is set.
- **BLS12-381 point-at-infinity encoding**: when baking G1 points into templates for AVM elliptic-curve ops, the infinity flag byte (0x40) is rewritten to 0x00 (see the `hex` template func in `verifier/verifier.go`). Fiat-Shamir inputs use `hexEncoded` to preserve gnark's uncompressed `RawBytes` encoding. The templates also handle point inversion and fixed-width x-coordinate bytes specially — `verifier/templates_test.go` guards this.
- Changes to verifier templates should be validated end-to-end with the `testutils` integration tests on localnet, since template output correctness only surfaces when the TEAL actually runs.
