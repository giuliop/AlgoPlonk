# AlgoPlonk

## The power of zero knowledge proofs on the Algorand blockchain.

> **Disclaimer:** AlgoPlonk is a new project and  should be used with caution in production environments. Feedback and contributions are welcome as we work to advance the state of zero knowledge proofs on the Algorand blockchain.

AlgoPlonk automatically generates a smart contract verifier from a zk circuit definition. It integrates with the [gnark](https://github.com/Consensys/gnark) toolchain, so you can use [gnark](https://github.com/Consensys/gnark) to define a plonk based zk circuit and to generate proofs for it, and use AlgoPlonk to generate an Algorand smart contract verifier that can verify those proofs.


The typical workflow is the following:
1. Define and compile a plonk based zk circuit with [gnark](https://github.com/Consensys/gnark) using the [trusted setup](#trusted-setup) provided by AlgoPlonk
2. Automatically generate a python Algorand Smart Contract with AlgoPlonk from your compiled circuit
3. Compile the python code into the teal files to create the contract with [algokit](https://github.com/algorandfoundation/algokit-cli) and the puyapy compiler
4. Generate proofs and witnesses for your circuit with [gnark](https://github.com/Consensys/gnark)
5. Export proofs and witnesses with AlgoPlonk and generate the method calls to the smart contract verifier to verify them

### Supported curves

AlgoPlonk supports the curves for which the AVM offers elliptic curve operations: bn254 and bls12-381.

A bn254 verifier consumes ~145,000 opcode budget, a bls12-381 verifier ~185,000.

Note that at the moment AlgoPlonk does not support custom gates.

### Trusted Setup

AlgoPlonk provides an out of the box trusted setup for both bls12-381 and bn256 verifiers using the [Ethereum KZG Ceremony](https://github.com/ethereum/kzg-ceremony) and the [Perpetual Powers of Tau Ceremony](https://github.com/privacy-scaling-explorations/perpetualpowersoftau), respectively.

The included trusted setup can support circuits with a number of constraints up to 2^14 (16K) for bls12-381, and 2^17 (128k) for bn254, and the latter could be extended to circuits of up to 128M constraints if needed.

Check the [`doc.go`](https://github.com/giuliop/AlgoPlonk/blob/main/setup/doc.go) file in the setup package for more details.

AlgoPlonk also provides test-only setups for circuits of any number of gates. These are NOT SUITABLE FOR PRODUCTION.

### How to use AlgoPlonk

The [`examples`](https://github.com/giuliop/AlgoPlonk/tree/main/examples) folder contains some examples of how to use AlgoPlonk that you can run with `go run main.go` in each example subfolder.

Let's follow here the one in [`examples/basic`](https://github.com/giuliop/AlgoPlonk/tree/main/examples/basic), with some added commentary (but we'll be omitting error checking for brevity, check the full example for that).

After the mandatory imports...
```
package main

import (
	"fmt"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"
	"github.com/giuliop/algoplonk/testutils"
)
```
...we define a simple zk circuit with [gnark](https://github.com/Consensys/gnark) that given public variables `a` and `b`, verifies that the Prover knows a secret `c` that satisfies the Pythagorean equation:  a^2 + b^2 == c^2
```
type BasicCircuit struct {
	A frontend.Variable `gnark:",public"`
	B frontend.Variable `gnark:",public"`
	C frontend.Variable
}

func (circuit *BasicCircuit) Define(api frontend.API) error {
	aa := api.Mul(circuit.A, circuit.A)
	bb := api.Mul(circuit.B, circuit.B)
	cc := api.Mul(circuit.C, circuit.C)
	api.AssertIsEqual(api.Add(aa, bb), cc)

	return nil
}
```
Let's also make an assignment that we'll use to generate a proof later
```
func main() {
	var circuit BasicCircuit

	// 3*3 + 4*4 == 5*5
	var assignment BasicCircuit
	assignment.A = 3
	assignment.B = 4
	assignment.C = 5
```
A bit of housekeeping now, specify where to put the automatically generated files and how to call them.

AlgoPlonk will generate these files later on:
* generated/BasicVerifier.py (the smart contract verifier)
* generated/BasicVerifier.proof (input for the verifier)
* generated/BasicVerifier.public_inputs (input for the verifier)

And puyapy will generate these files compiling BasicVerifier.py:
* generated/BasicVerifier.approval.teal
* generated/BasicVerifier.clear.teal
* generated/BasicVerifier.arc32.json
```
	artefactsFolder := "generated"
	testutils.CreateDirectoryIfNeeded(artefactsFolder)

	verifierName := "BasicVerifier"

	puyaVerifierFilename := artefactsFolder + verifierName + ".py"
	proofFilename := artefactsFolder + verifierName + ".proof"
	publicInputsFilename := artefactsFolder + verifierName + ".public_inputs"
```
Let's choose a curve, we use bls12-381 here, and compile the circuit.
Then we write to file the python code for the smart contract verifier with `WritePuyaPyVerifier` and finally we compile it to teal files
```
	curve := ecc.BLS12_381

	compiledCircuit, err := ap.Compile(&circuit, curve, setup.Trusted)
	err = compiledCircuit.WritePuyaPyVerifier(puyaVerifierFilename)
	err = testutils.CompileWithPuyapy(verifierName, artefactsFolder)
```
Cool, let's now deploy the verifier contract on a local blockchain (use `algokit localnet start` to activate it).
```
	app_id, err := testutils.DeployArc4AppIfNeeded(verifierName, artefactsFolder)
```
Yes! We are ready to rock n' roll now, let's create a proof and export it to file together with its public inputs so we can verify it.
```
	verifiedProof, err := compiledCircuit.Verify(&assignment)
	err = verifiedProof.WriteProofAndPublicInputs(proofFilename,
		publicInputsFilename)
```
We simulate a call to the `verify` method of the verifier contract passing the generated proof and public inputs as parameters.
```
	simulate := true
	schema, err := testutils.ReadArc32Schema(artefactsFolder +
		verifierName + ".arc32.json")
	result, err := testutils.CallVerifyMethod(app_id, nil, proofFilename, publicInputsFilename, schema, simulate)

	fmt.Printf("Verifier app returned: %v\n", result.ReturnValue)
}
```
> Verifier app returned: true

Life is sweet :)

#### The Verifier smart contract
The generated smart contract verifiers are [ARC4](https://github.com/algorandfoundation/ARCs/blob/main/ARCs/arc-0004.md) contracts with the following ABI methods:

* `create` is used to create the application and will set two global properties:
	1.  `app_name` with the provided name
	2. `immutable` with `False`
```
	@abimethod(create='require')
	def create(self, name: String) -> None:
```
* `update` allows the creator to update / delete the application unless the `immutable` property has been set to `True`
```
	@abimethod(allow_actions=["UpdateApplication", "DeleteApplication"])
	def update(self) -> None:
```
* `make_immutable` allows the creator to set the `immutable` property to `True`, making the contract fully decentralized with no one able to further modify or delete it.
```
	@abimethod
	def make_immutable(self) -> None:
```
* `verify` takes as parameters a proof and public inputs as exported by AlgoPlonk and returns `True` if the proof is verifier, `False` otherwise
```
	@abimethod
	def verify(self, proof: ..., public_inputs: ...) -> arc4.Bool:
```

### Next steps
Go unleash the power of zero knowledge proofs on Algorand!

Let us now what you create so that we can curate a list of zk applications.

### GPG key
All release tags are signed by the GPG key 81E0FB63130466B782D4859D6C036245DBDB025D
