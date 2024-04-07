package testutils

import (
	"path/filepath"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"
)

const (
	artefactsFolder = "generated"
)

func init() {
	// if artefactsFolder does not exist, create it
	CreateDirectoryIfNeeded(artefactsFolder)
}

type TestCircuit struct {
	Public frontend.Variable `gnark:",public"`
	Secret frontend.Variable
}

func (circuit *TestCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(circuit.Public, circuit.Secret)
	return nil
}

func TestCircuitBothCurves(t *testing.T) {
	var circuit TestCircuit
	var assignment TestCircuit
	assignment.Public = 5
	assignment.Secret = 5

	for _, curve := range []ecc.ID{ecc.BLS12_381, ecc.BN254} {
		verifierName := "TestVerifierForCurve" + curve.String()
		puyaVerifierFilename := filepath.Join(artefactsFolder, verifierName+".py")
		proofFilename := filepath.Join(artefactsFolder, verifierName+".proof")
		publicInputsFilename := filepath.Join(artefactsFolder,
			verifierName+".public_inputs")

		var compiledCircuit *ap.CompiledCircuit
		var err error
		if curve == ecc.BLS12_381 {
			compiledCircuit, err = ap.Compile(&circuit, curve, setup.Trusted)
		} else {
			compiledCircuit, err = ap.Compile(&circuit, curve, setup.TestOnly)
		}
		if err != nil {
			t.Fatalf("\nerror compiling circuit: %v", err)
		}

		verifiedProof, err := compiledCircuit.Verify(&assignment)
		if err != nil {
			t.Fatalf("\nerror during verification: %v", err)
		}

		err = compiledCircuit.WritePuyaPyVerifier(puyaVerifierFilename)
		if err != nil {
			t.Fatalf("error writing PuyaPy verifier: %v", err)
		}

		err = verifiedProof.WriteProofAndPublicInputs(proofFilename,
			publicInputsFilename)
		if err != nil {
			t.Fatal(err)
		}

		err = CompileWithPuyapy(verifierName, artefactsFolder)
		if err != nil {
			t.Fatal(err)
		}

		app_id, err := DeployArc4AppIfNeeded(verifierName, artefactsFolder)
		if err != nil {
			t.Fatalf("error deploying verifier app to local network: %v", err)
		}

		simulate := true
		schema, err := ReadArc32Schema(filepath.Join(artefactsFolder,
			verifierName+".arc32.json"))

		if err != nil {
			t.Fatalf("failed to read application schema: %s", err)
		}
		result, err := CallVerifyMethod(app_id, nil, proofFilename,
			publicInputsFilename, schema, simulate)
		if err != nil {
			t.Fatalf("error calling verifier app: %v", err)
		}

		rawValue := result.RawReturnValue
		if len(rawValue) == 0 {
			t.Fatalf("verifier app returned empty value")
		}
		if rawValue[0] != 0x80 {
			t.Fatalf("Verifier app did not return true, but: %v\n",
				result.ReturnValue)
		}
	}
}

func TestAVMVerifierMutability(t *testing.T) {
	var circuit TestCircuit

	verifierName := "TestVerifierForMutability"
	puyaVerifierFilename := filepath.Join(artefactsFolder, verifierName+".py")

	compiledCircuit, err := ap.Compile(&circuit, ecc.BLS12_381, setup.Trusted)
	if err != nil {
		t.Fatalf("\nerror compiling circuit: %v", err)
	}

	err = compiledCircuit.WritePuyaPyVerifier(puyaVerifierFilename)
	if err != nil {
		t.Fatalf("error writing PuyaPy verifier: %v", err)
	}

	err = CompileWithPuyapy(verifierName, artefactsFolder)
	if err != nil {
		t.Fatal(err)
	}

	app_id, err := DeployArc4AppIfNeeded(verifierName, artefactsFolder)
	if err != nil {
		t.Fatalf("error deploying verifier app to local network: %v", err)
	}

	schema, err := ReadArc32Schema(filepath.Join(artefactsFolder, verifierName+".arc32.json"))

	if err != nil {
		t.Fatalf("failed to read application schema: %s", err)
	}

	_, err = ExecuteAbiCall(app_id, nil, schema, "make_immutable",
		types.NoOpOC, nil)
	if err != nil {
		t.Fatalf("error making verifier app immutable: %v", err)
	}

	// let's try to delete the verifier app, it should fail
	_, err = ExecuteAbiCall(app_id, nil, schema, "update", types.DeleteApplicationOC, nil)
	if err == nil {
		t.Fatalf("deleting immutable verifier app should have failed")
	}
}
