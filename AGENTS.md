This file provides guidance to AI agents when working with code in this repository.

## What this is

AlgoPlonk is a Go library that auto-generates Algorand smart contract / logicsig verifiers from gnark plonk circuits. It supports the BN254 and BLS12-381 curves (the ones with AVM elliptic curve opcodes) and BSB22 commitments (`frontend.Committer`); other custom gates are not supported. Pin gnark/gnark-crypto to the versions in `go.mod` for compatibility. The minimum Go version is the exact version declared in `go.mod` (currently Go 1.25.13); this patch-level floor is deliberate.

## Commands

```sh
make test        # runs `rm ./testutils/generated/*` then `go test -v ./...`
make examples    # runs `rm ./generated/*` then every examples/**/main.go
make all         # examples then tests

go test -run TestLogicsigVerifier ./testutils   # single test
go test . ./setup ./verifier                    # localnet-free package tests
go test -v ./testutils                          # full localnet integration suite
```

External requirements for integration tests (`testutils` package) and examples:
- Docker must be running before starting localnet; `algokit localnet start` uses Docker containers.
- A local Algorand network with default algokit configuration must be running (`algokit localnet start`). Connection defaults (algod on localhost:4001, etc.) are at the top of `testutils/algosdkwrapper/setup.go`.
- `algokit` on PATH: generated Python verifiers are compiled by shelling out to `algokit compile py` (see `utils.CompileWithPuyaPy`). The compiler inherits the test process's `PATH`, so ensure a Python version supported by the installed PuyaPy comes before an older system Python. On macOS, `/usr/bin/python3` may be too old; put Homebrew Python first when necessary.

Unit tests in the root, `setup`, and `verifier` packages run without a localnet (the trusted-setup tests are slow but self-contained). `make test` and `go test ./...` include the `testutils` integration tests, so they need localnet and algokit. The `make` cleanup commands do not use `rm -f`; if a generated directory is empty, create or leave a placeholder file before relying on those targets.

## Releases

Stable releases use annotated tags named `vX.Y.Z`. Before tagging, add a matching
`## vX.Y.Z` section to `CHANGELOG.md` and commit it. Pushing the tag triggers
`.github/workflows/release.yml`, which publishes a GitHub Release using that
changelog section as its notes. The workflow can also be dispatched manually
with an existing tag, which is useful if a tag was pushed before the release
workflow existed or an earlier run failed. It is idempotent when the release
already exists.

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
- **BLS12-381 point-at-infinity encoding**: gnark's uncompressed `RawBytes` encoding is 96 bytes with the infinity flag `0x40` in the first byte, while AVM elliptic-curve opcodes require the affine `(0,0)` encoding (96 zero bytes). The BLS12-381 proof marshaller in `helper.go` converts every proof G1 point to AVM encoding, and the `hex` template func in `verifier/verifier.go` does the same for baked verifying-key points.
- **BLS12-381 Fiat-Shamir encoding**: transcript inputs must still match gnark. Baked verifying-key transcript values use `hexEncoded`, while the template `fs` helper converts dynamic AVM infinity back to gnark's `0x40` encoding before hashing. Apply `fs` to every dynamic G1 point entering a gnark-compatible transcript, including proof points and computed points such as `lin_poly_com` and `digest`. AVM byte-array bit indexes start at the leftmost bit, so `setbit_bytes(p, 1, True)` produces `0x40`; index 0 would incorrectly produce `0x80`.
- **BLS12-381 subgroup checks and proof identity**: generated verifiers omit gnark's per-proof-point subgroup checks to stay within AVM opcode budgets. The final `ec_pairing_check` checks its inputs' subgroup membership, but byte-distinct proofs with the same effective proof may be accepted. Consuming applications must not use raw proof bytes as a unique identifier.
- **Verifier output type**: `verifier.WritePythonCode` accepts only `verifier.LogicSig` and `verifier.SmartContract`; invalid `ContractType` values must return an error rather than silently selecting a template.
- Changes to proof marshalling or verifier templates should be validated with localnet-free unit tests and end-to-end with `go test -v ./testutils` on localnet, since template output correctness only surfaces when the generated TEAL actually runs.
