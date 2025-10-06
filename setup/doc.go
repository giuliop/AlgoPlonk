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

For the BN254 curve, AlgoPlonk includes the parameters from the battle tested perpetual
“powers-of-tau” ceremony used by projects such as Semaphore, Hermez, Torndado Cash and snarkjs.
The parameters included in AlgoPlonk support circuits up to 2^17 (128k) constraints, but the
ceremony provided parameters that can support up to 2^27 (128M) constraints which could be added.

Learn more about the ceremony here:
https://github.com/privacy-scaling-explorations/perpetualpowersoftau

For the BLS12-381 curve, the largest distributed ceremony has been run by the Ethereum Foundation
to implement Proto-danksharding (EIP-4844), with over 140,000 participants and rigorous auditing.
AlgoPlonk uses these parameters to secure BLS12-381 proof systems which can support circuits up to
2^14 (16,384) constraints.

Learn more about the ceremony here:
https://ceremony.ethereum.org/
https://github.com/ethereum/kzg-ceremony

Another BLS12-381 ceremony has been run by Dusk Network, extending the Zcash ceremony that had 88
participants, with 15 additional participants, so it is more secure than the original Zcash alone,
which is already widely trusted and battle-tested.
It generated parameters that can support circuits up to 2^21 (2M) constraints.

Learn more about the ceremony here:
https://github.com/dusk-network/trusted-setup

To audit the trusted parameters used in this library and verify they match the original source,
refer to the doc.go file in the respective ceremony subfolder.
*/
package setup
