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
to implement Proto-danksharding (aka EIP-4844), with over 140,000 participants and rigorous auditing.
We use these parameters to secure BLS12-381 proof systems.
These parameters support circuits with up to 2^15 (32768) constraints.

You can learn more about the procedure here:
https://ceremony.ethereum.org/
https://github.com/ethereum/kzg-ceremony

To audit the trusted parameters used in this library and verify they match the original source refer
to the doc.go file in the bls12-381 subfolder.

For the bn254 curve, at the moment no trusted setup is included. You can use bn254 in test only mode
and an (insecure) setup will be generated for any number of constraints. Suitable for testing but
not for production.
*/

package setup
