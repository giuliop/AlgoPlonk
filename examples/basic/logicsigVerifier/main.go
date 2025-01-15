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
	"os"
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
	err = compiledCircuit.WritePuyaPyVerifier(puyaVerifierFilename,
		verifier.LogicSig)
	if err != nil {
		log.Fatalf("error writing PuyaPy verifier: %v", err)
	}

	fmt.Print("\nCompiling verifier logicsig with puyapy: ")
	err = utils.CompileWithPuyaPy(puyaVerifierFilename, "")
	if err != nil {
		log.Fatal(err)
	}
	err = utils.RenamePuyaPyOutput(verifier.DefaultFileName, verifierName,
		artefactsFolder)
	if err != nil {
		log.Fatal(err)
	}

	verifierTealFile := filepath.Join(artefactsFolder, verifierName+".teal")
	verifierLogicSig, err := sdk.LogicSigFromFile(verifierTealFile)
	if err != nil {
		log.Fatalf("error reading verifier logicsig: %v", err)
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

	fmt.Println("\nSimulating verifying proof")
	simulate := true

	// Read proof and public inputs from files
	proof, err := os.ReadFile(proofFilename)
	if err != nil {
		log.Fatalf("failed to read proof file: %v", err)
	}
	publicInputs, err := os.ReadFile(publicInputsFilename)
	if err != nil {
		log.Fatalf("failed to read public inputs file: %v", err)
	}

	testAppId, testAppSchema, err := testutils.DeployAppWithVerifyMethod(artefactsFolder)
	if err != nil {
		log.Fatalf("error deploying test verifier app to local network: %v", err)
	}

	err = testutils.CallLogicSigVerifier(testAppId, testAppSchema, verifierLogicSig, proof,
		publicInputs, simulate)
	if err != nil {
		log.Fatalf("error calling logicsig verifier: %v", err)
	}
	fmt.Printf("\nProof verified successfully !\n\n")
}
