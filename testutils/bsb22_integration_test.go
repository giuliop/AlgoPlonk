package testutils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"
	sdk "github.com/giuliop/algoplonk/testutils/algosdkwrapper"
	"github.com/giuliop/algoplonk/utils"
	"github.com/giuliop/algoplonk/verifier"
)

// Bsb22Circuit uses a BSB22 commitment (frontend.Committer) so that its
// verifier exercises the commitment-gate code paths.
type Bsb22Circuit struct {
	Public frontend.Variable `gnark:",public"`
	Secret frontend.Variable

	nbCommitments int
}

func (c *Bsb22Circuit) Define(api frontend.API) error {
	committer, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("compiler does not support Commit")
	}
	nbCommitments := c.nbCommitments
	if nbCommitments == 0 {
		nbCommitments = 1
	}
	toCommit := c.Secret
	for range nbCommitments {
		cmt, err := committer.Commit(toCommit, c.Public)
		if err != nil {
			return err
		}
		api.AssertIsDifferent(cmt, 0)
		toCommit = cmt
	}
	api.AssertIsEqual(c.Public, api.Mul(c.Secret, c.Secret))
	return nil
}

// TestLogicsigVerifierWithCommitment tests the verifier logicsig for a
// circuit with a BSB22 commitment gate, for both BN254 and BLS12_381 curves
func TestLogicsigVerifierWithCommitment(t *testing.T) {
	for _, curve := range []ecc.ID{ecc.BN254, ecc.BLS12_381} {
		t.Run(curve.String(), func(t *testing.T) {
			var circuit Bsb22Circuit
			assignment := Bsb22Circuit{Public: 9, Secret: 3}

			verifierName := "VerifierLogicSigBsb22ForCurve" + curve.String()

			puyaVerifierFilename := filepath.Join(artefactsFolder, verifierName+".py")
			proofFilename := filepath.Join(artefactsFolder, verifierName+".proof")
			publicInputsFilename := filepath.Join(artefactsFolder,
				verifierName+".public_inputs")

			setupConf := setup.TestOnlySetup(curve)
			compiledCircuit, err := ap.Compile(&circuit, curve, setupConf)
			if err != nil {
				t.Fatalf("\nerror compiling circuit: %v", err)
			}

			verifiedProof, err := compiledCircuit.Verify(&assignment)
			if err != nil {
				t.Fatalf("\nerror during verification: %v", err)
			}
			err = compiledCircuit.WritePuyaPyVerifier(puyaVerifierFilename,
				verifier.LogicSig)
			if err != nil {
				t.Fatalf("error writing PuyaPy verifier: %v", err)
			}

			err = verifiedProof.ExportProofAndPublicInputs(proofFilename,
				publicInputsFilename)
			if err != nil {
				t.Fatal(err)
			}

			err = utils.CompileWithPuyaPy(puyaVerifierFilename, "")
			if err != nil {
				t.Fatal(err)
			}
			err = utils.RenamePuyaPyOutput(verifier.DefaultFileName, verifierName,
				artefactsFolder)
			if err != nil {
				t.Fatal(err)
			}

			verifierTealFile := filepath.Join(artefactsFolder, verifierName+".teal")
			verifierLogicSig, err := sdk.LogicSigFromFile(verifierTealFile)
			if err != nil {
				t.Fatalf("error reading verifier logicsig: %v", err)
			}

			proof, err := os.ReadFile(proofFilename)
			if err != nil {
				t.Fatalf("failed to read proof file: %v", err)
			}
			publicInputs, err := os.ReadFile(publicInputsFilename)
			if err != nil {
				t.Fatalf("failed to read public inputs file: %v", err)
			}

			testAppId, testAppSchema, err := DeployAppWithVerifyMethod(artefactsFolder)
			if err != nil {
				t.Fatalf("error deploying test verifier app to local network: %v", err)
			}

			simulate := true
			err = CallLogicSigVerifier(testAppId, testAppSchema, verifierLogicSig,
				proof, publicInputs, simulate)
			if err != nil {
				t.Fatalf("error calling logicsig verifier: %v", err)
			}

			// now let's change the public inputs and see it fail
			if publicInputs[31] == 0 {
				publicInputs[31] = 1
			} else {
				publicInputs[31] = 0
			}
			err = CallLogicSigVerifier(testAppId, testAppSchema, verifierLogicSig,
				proof, publicInputs, simulate)
			if err == nil {
				t.Fatalf("Logicsig successful but was expected to fail")
			}
			if !strings.Contains(err.Error(), "rejected by logic") {
				t.Fatalf("Unexpected error: %v", err)
			}
		})
	}
}

// TestSmartContractVerifierWithCommitment tests the verifier smart contract
// for a circuit with a BSB22 commitment gate, for both BN254 and BLS12_381
// curves
func TestSmartContractVerifierWithCommitment(t *testing.T) {
	for _, curve := range []ecc.ID{ecc.BN254, ecc.BLS12_381} {
		t.Run(curve.String(), func(t *testing.T) {
			runSmartContractVerifierWithCommitments(t, curve, 1,
				"VerifierSmartContractBsb22ForCurve"+curve.String())
		})
	}
}

// TestSmartContractVerifierWithTwoCommitments measures the verifier budget
// overhead of an additional BSB22 commitment. In local simulation this reports
// about 35,000 extra app opcode budget for BN254 and 40,000 for BLS12-381.
func TestSmartContractVerifierWithTwoCommitments(t *testing.T) {
	for _, curve := range []ecc.ID{ecc.BN254, ecc.BLS12_381} {
		t.Run(curve.String(), func(t *testing.T) {
			runSmartContractVerifierWithCommitments(t, curve, 2,
				"VerifierSmartContractBsb22TwoCommitmentsForCurve"+curve.String())
		})
	}
}

func runSmartContractVerifierWithCommitments(t *testing.T, curve ecc.ID,
	nbCommitments int, verifierName string) {
	t.Helper()

	circuit := Bsb22Circuit{nbCommitments: nbCommitments}
	assignment := Bsb22Circuit{Public: 9, Secret: 3}

	puyaVerifierFilename := filepath.Join(artefactsFolder, verifierName+".py")
	proofFilename := filepath.Join(artefactsFolder, verifierName+".proof")
	publicInputsFilename := filepath.Join(artefactsFolder,
		verifierName+".public_inputs")

	setupConf := setup.TestOnlySetup(curve)
	compiledCircuit, err := ap.Compile(&circuit, curve, setupConf)
	if err != nil {
		t.Fatalf("\nerror compiling circuit: %v", err)
	}

	verifiedProof, err := compiledCircuit.Verify(&assignment)
	if err != nil {
		t.Fatalf("\nerror during verification: %v", err)
	}

	err = compiledCircuit.WritePuyaPyVerifier(puyaVerifierFilename,
		verifier.SmartContract)
	if err != nil {
		t.Fatalf("error writing PuyaPy verifier: %v", err)
	}

	err = verifiedProof.ExportProofAndPublicInputs(proofFilename,
		publicInputsFilename)
	if err != nil {
		t.Fatal(err)
	}

	err = utils.CompileWithPuyaPy(puyaVerifierFilename, "")
	if err != nil {
		t.Fatal(err)
	}
	err = utils.RenamePuyaPyOutput(verifier.DefaultFileName, verifierName,
		artefactsFolder)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := os.ReadFile(proofFilename)
	if err != nil {
		t.Fatalf("failed to read proof file: %v", err)
	}
	publicInputs, err := os.ReadFile(publicInputsFilename)
	if err != nil {
		t.Fatalf("failed to read public inputs file: %v", err)
	}

	args, err := utils.ProofAndPublicInputsForAtomicComposer(proof,
		publicInputs)
	if err != nil {
		t.Fatalf("error abi encoding proof and public inputs: %v", err)
	}

	app_id, err := sdk.DeployArc4AppIfNeeded(verifierName, artefactsFolder)
	if err != nil {
		t.Fatalf("error deploying verifier app to local network: %v", err)
	}

	simulate := true
	schema, err := sdk.ReadArc56Schema(filepath.Join(artefactsFolder,
		verifierName+".arc56.json"))
	if err != nil {
		t.Fatalf("failed to read application schema: %s", err)
	}

	result, err := sdk.ExecuteAbiCall(app_id, schema, "verify", types.NoOpOC,
		args, nil, nil, simulate)
	if err != nil {
		t.Fatalf("error calling verifier app: %v", err)
	}
	if result.DecodeError != nil {
		t.Fatalf("error decoding result: %v", result.DecodeError)
	}
	if result.ReturnValue != true {
		t.Fatal("verifier app did not return true")
	}

	// now let's change the public inputs and see it fail
	publicInputs[31] ^= 1
	args, err = utils.ProofAndPublicInputsForAtomicComposer(proof,
		publicInputs)
	if err != nil {
		t.Fatalf("error abi encoding proof and public inputs: %v", err)
	}
	result, err = sdk.ExecuteAbiCall(app_id, schema, "verify", types.NoOpOC,
		args, nil, nil, simulate)
	if err != nil {
		t.Fatalf("error calling verifier app: %v", err)
	}
	if result.DecodeError != nil {
		t.Fatalf("error decoding result: %v", result.DecodeError)
	}
	if result.ReturnValue != false {
		t.Fatal("verifier app succeeded but was expected to fail")
	}
}
