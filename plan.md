# Add BSB22 Commitment Gate Support

## Summary

- Support gnark PLONK circuits that use `frontend.Committer.Commit`, the BSB22 commitment path currently rejected by AlgoPlonk as "custom gates".
- Keep support scoped to BN254 and BLS12-381, matching existing AlgoPlonk curves and gnark `v0.14.0`.
- Leave broader experimental `constraint.CustomizableSystem` custom constraints out of scope.

## Key Changes

- Remove the hard rejection in `verifier.WritePythonCode`; instead expose `Qcp`, `CommitmentConstraintIndexes`, and commitment count to the templates.
- Extend proof parsing:
  - BN254 proof length becomes `24 + 3*n` 32-byte words.
  - BLS12-381 proof length becomes `33 + 4*n` 32-byte words.
  - For each commitment gate, parse one `qcp(zeta)` scalar followed by one BSB22 commitment point.
- Update Fiat-Shamir transcript logic to match gnark Solidity:
  - Include `Qcp` commitments in `gamma`.
  - Include BSB22 commitments before `Z` in `alpha`.
  - Include `Qcp` commitments and `qcp(zeta)` values in the KZG folding challenge.
- Implement generated PuyaPy helper for BSB22 hash-to-field using `sha256`/XMD with DST `BSB22-Plonk`, matching gnark `fr.Hash`.
- Add commitment-gate contribution to public input interpolation:
  - For each `CommitmentConstraintIndexes[i]`, compute `hash_fr(Bsb22Commitment[i]) * L_{NbPublicVariables + index}(zeta)`.
- Add `qcp(zeta) * Bsb22Commitment` terms to the linearized polynomial commitment.
- Fold each `Qcp` commitment and claimed `qcp(zeta)` value into the batched KZG opening at `zeta`.

## Tests

- Add a small test circuit using `api.(frontend.Committer).Commit(...)`, then prove and verify with gnark locally for BN254 and BLS12-381.
- Add template/unit tests that generated code contains the commitment-gate transcript, proof-length formulas, and hash-to-field helper only when `len(Qcp) > 0`.
- Add proof blob tests confirming `MarshalProof` layout matches gnark `MarshalSolidity` for BN254 and the hand-rolled BLS12-381 layout.
- Run localnet integration tests for both verifier output types:
  - LogicSig BN254 and BLS12-381 with one commitment gate.
  - SmartContract BN254 and BLS12-381 with one commitment gate.
- Keep existing no-commitment tests unchanged to verify backward compatibility.

## Assumptions

- "Custom gates" means gnark's BSB22 `frontend.Committer.Commit` support, not arbitrary user-defined custom constraints.
- gnark and gnark-crypto remain pinned to `go.mod` versions: `gnark v0.14.0`, `gnark-crypto v0.19.2`.
- The generated PuyaPy verifier should remain self-contained; no new runtime proof-export API is needed.
- References checked: local pinned gnark source plus gnark master Solidity verifier at <https://github.com/Consensys/gnark/blob/master/backend/plonk/bn254/solidity.go>.
