/*
package setup contains trusted parameters for the supported curves and functions to set up
zkp protocols with them.

Source of the trusted parameters
====================================================================================================
To secure the plonk protocol we need shared securities parameters between Prover and Verifier.
The creation of these parameters requires a "trusted setup" procedure, so called because it is
critical to run the procedure correctly to ensure the security of proof verifications.

To make the risk of a dishonest setup statistically insignificant, a distributed, permissionless,
setup ceremony, open to everyone, can be run. The ceremony guarantees security as long as at least
one participant is honest. In fact, all the participants would need to collude together to act
maliciously.
In addition, the software used to run the procedure must be audited carefully, to avoid bugs.

For the bls12-381 curve, the largest distributed ceremony has been run by the Ethereum Foundation
to implement Proto-danksharding (EIP-4844), with over 140,000 participants and rigorous auditing.
AlgoPlonk uses these parameters to secure BLS12-381 proof systems which can support circuits up to
2^14 (16,384) constraints.

Learn more about the ceremony here:
https://ceremony.ethereum.org/
https://github.com/ethereum/kzg-ceremony

For the bn254 curve, AlgoPlonk includes the parameters from the battle tested perpetual
“powers-of-tau” ceremony used by projects such as Semaphore, Hermez, Torndado Cash and snarkjs.
The parameters included in AlgoPlonk support circuits up to 2^17 (128k) constraints, but the
ceremony provided parameters that can support up to 2^27 (128M) constraints which could be added.

Learn more about the ceremony here:
https://github.com/privacy-scaling-explorations/perpetualpowersoftau

To audit the trusted parameters used in this library and verify they match the original source,
refer to the doc.go file in the bls12-381 and bn254 subfolders.
*/
package setup
