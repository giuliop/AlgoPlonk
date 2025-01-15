// This example defines a basic circuit that given public variables 'a' and 'b',
// verifies that the Prover knows a secret 'c' that satisfies the Pythagorean
// equation: a*a + b*b == c*c
//
// We compile the circuit with gnark, build and test a proof, generate an AVM
// verifier and compile it with puyapy, deploy it to the local network, and
// simulate on the AVM a proof verification of the generated proof
package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"
	"github.com/giuliop/algoplonk/testutils"
	sdk "github.com/giuliop/algoplonk/testutils/algosdkwrapper"
	"github.com/giuliop/algoplonk/utils"
	"github.com/giuliop/algoplonk/verifier"
)

// BasicCircuit is a simple circuit that given public variables 'a' and 'b',
// verifies that the prover knows a secret 'c' that satisfies the
// Pythagorean equation: a*a + b*b == c*c
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

func main() {
	var circuit BasicCircuit

	// 3*3 + 4*4 == 5*5
	var assignment BasicCircuit
	assignment.A = 3
	assignment.B = 4
	assignment.C = 5

	artefactsFolder := "generated"
	testutils.CreateDirectoryIfNeeded(artefactsFolder)

	verifierName := "BasicVerifier"

	puyaVerifierFilename := filepath.Join(artefactsFolder, verifierName+".py")
	proofFilename := filepath.Join(artefactsFolder, verifierName+".proof")
	publicInputsFilename := filepath.Join(artefactsFolder,
		verifierName+".public_inputs")

	curve := ecc.BLS12_381

	fmt.Println("\nCompiling circuit with gnark")
	compiledCircuit, err := ap.Compile(&circuit, curve, setup.Trusted)
	if err != nil {
		log.Fatalf("\nerror compiling circuit: %v", err)
	}

	fmt.Printf("\nWriting PuyaPy verifier to %s\n", puyaVerifierFilename)
	err = compiledCircuit.WritePuyaPyVerifier(puyaVerifierFilename, verifier.SmartContract)
	if err != nil {
		log.Fatalf("error writing PuyaPy verifier: %v", err)
	}

	fmt.Print("\nCompiling verifier app with puyapy: ")
	err = utils.CompileWithPuyaPy(puyaVerifierFilename, "")
	if err != nil {
		log.Fatal(err)
	}
	err = utils.RenamePuyaPyOutput(verifier.DefaultFileName,
		verifierName, artefactsFolder)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\nDeploying verifier app to local network with name `%s`\n",
		verifierName)
	app_id, err := sdk.DeployArc4AppIfNeeded(verifierName, artefactsFolder)
	if err != nil {
		log.Fatalf("error deploying verifier app to local network: %v", err)
	}

	fmt.Println("\nVeryfing proof with gnark")
	verifiedProof, err := compiledCircuit.Verify(&assignment)
	if err != nil {
		log.Fatalf("\nerror during verification: %v", err)
	}

	fmt.Printf("\nWriting proof to %s and public inputs to %s\n", proofFilename,
		publicInputsFilename)
	err = verifiedProof.ExportProofAndPublicInputs(proofFilename,
		publicInputsFilename)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\nSimulating calling verifier app to verify proof")
	simulate := true
	schema, err := sdk.ReadArc32Schema(filepath.Join(artefactsFolder,
		verifierName+".arc32.json"))
	if err != nil {
		log.Fatalf("failed to read application schema: %s", err)
	}
	result, err := testutils.CallVerifyMethod(app_id, proofFilename,
		publicInputsFilename, schema, simulate)
	if err != nil {
		log.Fatalf("error calling verifier app: %v", err)
	}

	rawValue := result.RawReturnValue
	if len(rawValue) == 0 {
		log.Fatalf("verifier app returned empty value")
	}
	fmt.Printf("Verifier app returned: %v\n", result.ReturnValue)
	switch rawValue[0] {
	case 0x80:
		fmt.Printf("Proof verified successfully !\n\n")
	case 0x81:
		fmt.Printf("Proof verification failed !\n\n")
	default:
		log.Fatalf("Verifier app returned unknown value: %v\n", rawValue)
	}
}
