# AlgoPlonk

## The power of zero knowledge proofs on the Algorand blockchain.

> **Disclaimer:** AlgoPlonk is a new project and  should be used with caution in production environments. Feedback and contributions are welcome as we work to advance the state of zero knowledge proofs on the Algorand blockchain.

AlgoPlonk automatically generates a smart contract verifier from a zk circuit definition. It integrates with the [gnark](https://github.com/Consensys/gnark) toolchain, so you can use [gnark](https://github.com/Consensys/gnark) to define a plonk based zk circuit and to generate proofs for it, and use AlgoPlonk to generate an Algorand smart contract verifier that can verify those proofs.

The typical workflow is the following:
1. Define and compile a plonk based zk circuit with [gnark](https://github.com/Consensys/gnark) using the [trusted setup](#trusted-setup) provided by AlgoPlonk
2. Automatically generate a python Algorand Smart Signature or Smart Contract verifier with AlgoPlonk from your compiled circuit
3. Compile the python code into teal files to create the verifier with [algokit](https://github.com/algorandfoundation/algokit-cli) and the puyapy compiler
4. Generate proofs and witnesses for your circuit with [gnark](https://github.com/Consensys/gnark)
5. Export proofs and witnesses with AlgoPlonk and generate the calls to the verifier to verify them

To ensure compatibility with gnark (and gnark-crypto if you are using it as well), you can pin them to the versions shown in AlgoPlonk's `go.mod` file.

### Supported circuits

AlgoPlonk supports the plonk protocol and the curves for which the AVM offers elliptic curve operations: BN254 and BLS12-381.
Custom gates are not supported.

### Verifiers types

AlgoPlonk can generate both logicsig verifiers and smart contract verifiers.

A BN254 verifier consumes ~145,000 opcode budget, a BLS12-381 verifier ~185,000.
Because of these large consumption numbers, logicsig verifiers are recommended:
1) Each top level transaction in a transaction group offers 20,000 logicsig opcode budget for the cost of 1 minimum transaction fee, so you pay 8 (for BN254) or 10 (for BLS12-381) minimum transaction fees to verify a proof.

	Smart contracts get 700 opcode budget for each app call transaction in a group (top level or inner), so you have to pay ~208 (for BN254) or ~265 (for BLS12-381) minimum transaction fees to verify a proof with a smart contract verifier.

2) The opcode budget for logicsig and smart contracts are separate, so by using logicsig verifiers you preserve the smart contract opcode budget for your application logic.

Note that the maximum opcode budget a transaction group can make available on Algorand at the moment is 320,000 (20,000 * 16) for logicsigs and 190,400 ( (16+256) * 700 ) for smart contracts. You can achieve that by creating a group with 16 top level app calls and 256 inner app call transactions.

### Trusted Setup

AlgoPlonk provides an out of the box trusted setup for both BLS12-381 and bn256 verifiers using the [Ethereum KZG Ceremony](https://github.com/ethereum/kzg-ceremony) and the [Perpetual Powers of Tau Ceremony](https://github.com/privacy-scaling-explorations/perpetualpowersoftau), respectively.

The included trusted setup can support circuits with a number of constraints up to 2^14 (16K) for BLS12-381, and 2^17 (128k) for BN254, and the latter could be extended to circuits of up to 128M constraints in the future leveraging additional parameters from the [Perpetual Powers of Tau Ceremony](https://github.com/privacy-scaling-explorations/perpetualpowersoftau).

Check the [`doc.go`](https://github.com/giuliop/AlgoPlonk/blob/main/setup/doc.go) file in the setup package for more details.

AlgoPlonk also provides test-only setups for circuits of any number of gates. These are NOT SUITABLE FOR PRODUCTION.

### How to use AlgoPlonk

The [`examples`](https://github.com/giuliop/AlgoPlonk/tree/main/examples) folder contains some examples of how to use AlgoPlonk with both logicsig and smart contract verifiers that you can run with `go run main.go` in each example subfolder.

Let's follow here the logicsig example in [`examples/basic`](https://github.com/giuliop/AlgoPlonk/tree/main/examples/basic/logicsigVerifier), with some added commentary (but we'll be omitting error checking for brevity, check the full example for that).

After the mandatory imports...
```
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"
	"github.com/giuliop/algoplonk/testutils"
	sdk "github.com/giuliop/algoplonk/testutils/algosdkwrapper"
	"github.com/giuliop/algoplonk/verifier"
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
A bit of housekeeping now, we specify where to put the automatically generated files and how to call them.

AlgoPlonk will generate these files later on:
* generated/BasicVerifier.py (the logicsig verifier)
* generated/BasicVerifier.proof (input for the verifier)
* generated/BasicVerifier.public_inputs (input for the verifier)

```
artefactsFolder := "generated"
testutils.CreateDirectoryIfNeeded(artefactsFolder)

verifierName := "BasicVerifier"

puyaVerifierFilename := filepath.Join(artefactsFolder, verifierName+".py")
proofFilename := filepath.Join(artefactsFolder, verifierName+".proof")
publicInputsFilename := filepath.Join(artefactsFolder,
	verifierName+".public_inputs")
```
Let's choose a curve, we use BLS12-381 here, and compile the circuit.
Then we write to file the python code for the verifier with `WritePuyaPyVerifier` and finally we compile it to a teal file.
Note that we pass `verifier.LogicSig` to `WritePuyaPyVerifier` to specify that we want to generate logicsig verifiers.
```
curve := ecc.BLS12_381

compiledCircuit, err := ap.Compile(&circuit, curve, setup.Trusted)
err = compiledCircuit.WritePuyaPyVerifier(puyaVerifierFilename,
	verifier.LogicSig)
err = testutils.CompileWithPuyaPy(puyaVerifierFilename, "")
err = testutils.RenamePuyaPyOutput(verifier.DefaultFileName, verifierName,
	artefactsFolder)
```
Cool, let's now retrieve the logicsig verifier to use it later.
```
verifierTealFile := filepath.Join(artefactsFolder, verifierName+".teal")
verifierLogicSig, err := sdk.LogicSigFromFile(verifierTealFile)
```
We are ready to rock n' roll now, let's create a proof and export it to file together with its public inputs so we can verify it.
```
verifiedProof, err := compiledCircuit.Verify(&assignment)
err = verifiedProof.ExportProofAndPublicInputs(proofFilename,
	publicInputsFilename)
```
To use the logicsig verifier we deploy a dummy smart contract so that we can make an app call signed by the logicsig verifier. If we supply a valid proof it will succeed, otherwise the logicsig will fail.
```
testAppId, testAppSchema, err := testutils.DeployAppWithVerifyMethod(artefactsFolder)
```
Let's now read the proof and public inputs from file (we exported them above) and try using the verifier!
```
proof, err := os.ReadFile(proofFilename)
publicInputs, err := os.ReadFile(publicInputsFilename
simulate := true
err = testutils.CallLogicSigVerifier(testAppId, testAppSchema,
	verifierLogicSig, proof, publicInputs, simulate)
}
```
> Proof verified successfully !

Life is sweet :)

#### The logicsig verifiers ####
The generated logicsig verifiers expect to be called signing an app call transaction and to read the proof and public inputs as the second and third application arguments of the app call (since the first app arg is reserved for the method name for arc4 smart contracts).

#### The smart contract verifiers ####
The generated smart contract verifiers are [ARC4](https://github.com/algorandfoundation/ARCs/blob/main/ARCs/arc-0004.md) contracts with the following ABI methods:

`create` is used to create the application and will set two global properties:
	1.  `app_name` with the provided name
	2. `immutable` with `False`
```
@abimethod(create='require')
def create(self, name: String) -> None:
```
`update` allows the creator to update / delete the application unless the `immutable` property has been set to `True`
```
@abimethod(allow_actions=["UpdateApplication", "DeleteApplication"])
def update(self) -> None:
```
`make_immutable` allows the creator to set the `immutable` property to `True`, making the contract fully decentralized with no one able to further modify or delete it.
```
@abimethod
def make_immutable(self) -> None:
```
`verify` takes as parameters a proof and public inputs as exported by AlgoPlonk and returns `True` if the proof is verifier, `False` otherwise
```
@abimethod
def verify(self, proof: ..., public_inputs: ...) -> arc4.Bool:
```

### Next steps
Go unleash the power of zero knowledge proofs on Algorand!

Let us now what you create so that we can curate a list of zk applications.

### GPG key
All release tags are currently signed by the GPG key 3BCAD2CB70EDF387D682A2C0767CDA51BA8C0284.
Check the [CHANGELOG](https://github.com/giuliop/AlgoPlonk/blob/main/CHANGELOG.md) for keys used by older releases.
