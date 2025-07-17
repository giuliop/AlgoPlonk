/*
package main contains the trusted parameters for the bls12_381 curve
as described in the doc.go file in the setup package (parent folder).

The parameters for the Prover and the Verifier are in the pk.bin and
vk.bin files, respectively.

These files have been created using the script in the audit.go file.
To audit the parameters you need to:

1) download the original response file from https://github.com/dusk-network/trusted-setup/tree/main/contributions/0015

2) Place the `response` file in this directory

3) Run the audit.go main program with `go run .`

This will create the pk.audit and vs.audit files and test they match the
pk.bin and vk.bin files.
*/
package main
