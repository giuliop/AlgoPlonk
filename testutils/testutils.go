// package tests contains tests and test helper functions
// To run the tests, a local network with default configuration is expected
// to be running.
// You can use algokit to start one with `algokit localnet start`
// Custom configuration can be set by changing the exposed variables at the top
// of the algosdkwrapper/setup.go file.
package testutils

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"
	sdk "github.com/giuliop/algoplonk/testutils/algosdkwrapper"
	"github.com/giuliop/algoplonk/utils"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
)

// TestCircuitWithGnark compiles a circuit and verifies a proof from an assignment
// using gnark (no interaction with the AVM)
func TestCircuitWithGnark(circuit frontend.Circuit, assignment frontend.Circuit,
	curve ecc.ID) (*ap.CompiledCircuit, *ap.VerifiedProof, error) {

	cc, err := ap.Compile(circuit, curve, setup.TestOnly)
	if err != nil {
		return nil, nil, fmt.Errorf("error compiling circuit: %v", err)
	}

	witness, err := frontend.NewWitness(assignment, curve.ScalarField())
	if err != nil {
		return cc, nil, fmt.Errorf("error creating full witness: %v", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		return cc, nil, fmt.Errorf("error creating public witness: %v", err)
	}

	proof, err := plonk.Prove(cc.Ccs, cc.Pk, witness)
	if err != nil {
		return cc, nil, fmt.Errorf("error creating plonk proof: %v", err)
	}
	err = plonk.Verify(proof, cc.Vk, publicWitness)
	if err != nil {
		return cc, nil, fmt.Errorf("error verifying plonk proof: %v", err)
	}

	return cc, &ap.VerifiedProof{Proof: proof, Witness: witness}, nil
}

// CreateDirectoryIfNeeded creates `dir` if it does not exist
func CreateDirectoryIfNeeded(dir string) error {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		err = os.Mkdir(dir, 0755)
		if err != nil {
			return fmt.Errorf("error creating folder: %v", err)
		}
	} else if !info.IsDir() {
		return fmt.Errorf("file %s exists but is not a directory", dir)
	}
	return nil
}

// CallVerifyMethod calls a verifier smart contract with the given proof and
// public inputs from file. If simulate is true, it simulates the call instead
// of sending it, adding the maximum extra opcode budget.
// A local network must be running
func CallVerifyMethod(appId uint64, proofFilename string, publicInputsFilename string,
	schema *sdk.Arc32Schema, simulate bool) (
	*transaction.ABIMethodResult, error) {

	proof, err := os.ReadFile(proofFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to read proof file: %v", err)
	}
	publicInputs, err := os.ReadFile(publicInputsFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to read public inputs file: %v", err)
	}
	args, err := utils.AbiEncodeProofAndPublicInputs(proof, publicInputs)
	if err != nil {
		return nil, fmt.Errorf("failed to encode proof and public inputs: %v", err)
	}
	return sdk.ExecuteAbiCall(appId, schema, "verify", types.NoOpOC, args, nil, nil, simulate)
}

// CallLogicSigVerifier makes an app call to appId's "verify" method signed by lsig
// with proof and public inputs as arguments, bundled in a transaction group
// to pool size and opcode budget.
// If simulate is true, it simulates the group instead of sending it.
// A local network must be running with default parameters
func CallLogicSigVerifier(appId uint64, schema *sdk.Arc32Schema,
	lsig *crypto.LogicSigAccount, proof []byte, publicInputs []byte, simulate bool,
) error {
	args, err := utils.AbiEncodeProofAndPublicInputs(proof, publicInputs)
	if err != nil {
		return fmt.Errorf("failed to encode proof and public inputs: %v", err)
	}
	signer := transaction.LogicSigAccountTransactionSigner{LogicSigAccount: *lsig}
	txnParams, err := sdk.BuildMethodCallParams(appId, schema, "verify", types.NoOpOC, args,
		nil, signer)
	if err != nil {
		return fmt.Errorf("failed to build method call params: %v", err)
	}
	txnParams.SuggestedParams.Fee = 0
	txnParams.SuggestedParams.FlatFee = true

	var atc = transaction.AtomicTransactionComposer{}
	if err := atc.AddMethodCall(*txnParams); err != nil {
		return fmt.Errorf("failed to add method call: %v", err)
	}
	err = sdk.AddDummyTrasactions(&atc, 9)
	if err != nil {
		return fmt.Errorf("failed to add dummy txns: %v", err)
	}
	_, err = sdk.ExecuteGroup(&atc, simulate)
	return err
}

// DeployAppWithVerifyMethod deploys an app with a "verify" method to test
// logicsig verifiers.
// A local network must be running with default parameters
func DeployAppWithVerifyMethod(workingDir string,
) (appId uint64, schema *sdk.Arc32Schema, err error) {
	appName := "Arc4AppWithVerifyMethod"
	appPythonCode := `
import typing
import algopy
from algopy.arc4 import (
	abimethod, DynamicArray, StaticArray, Bool, Byte, String
)

Bytes32: typing.TypeAlias = StaticArray[Byte, typing.Literal[32]]

class Arc4AppWithVerifyMethod(algopy.ARC4Contract):

	@abimethod(create='require')
	def create(self, name: String) -> None:
		"""Create the application"""
		self.app_name = name

	@abimethod(allow_actions=["UpdateApplication", "DeleteApplication"])
	def update(self) -> None:
		"""Update and delete the application"""
		return

	@abimethod
	def verify(
		self,
		proof: DynamicArray[Bytes32],
		public_inputs: DynamicArray[Bytes32],
		)-> Bool:
			return Bool(True)
`
	appCodePath := filepath.Join(workingDir, appName+".py")
	err = os.WriteFile(appCodePath, []byte(appPythonCode), 0644)
	if err != nil {
		return 0, nil, fmt.Errorf("error writing app code to file: %v", err)
	}
	err = utils.CompileWithPuyaPy(appCodePath, "")
	if err != nil {
		return 0, nil, fmt.Errorf("error compiling app code: %v", err)
	}
	appId, err = sdk.DeployArc4AppIfNeeded(appName, workingDir)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to deploy app: %v", err)
	}
	schema, err = sdk.ReadArc32Schema(filepath.Join(workingDir, appName+".arc32.json"))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read arc32 schema: %v", err)
	}
	return appId, schema, err
}
