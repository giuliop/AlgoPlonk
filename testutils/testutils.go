// package tests contains tests and test helper functions
// To run the tests, a local network with default configuration is expected
// to be running.
// You can use algokit to start one with `algokit localnet start`
// Custom configuration can be set by changing the exposed variables at the top
// of the algosdkwrapper/setup.go file.
package testutils

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"
	sdk "github.com/giuliop/algoplonk/testutils/algosdkwrapper"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"

	"os/exec"
)

// CompileWithPuyaPy compiles `filepath` with puyapy, with `options'.
// Leave `options` empty to not pass any options
func CompileWithPuyaPy(filepath string, options string) error {
	args := []string{"compile", "py", filepath}
	if options != "" {
		args = append(args, options)
	}
	cmd := exec.Command("algokit", args...)
	fmt.Printf("algokit %s\n", strings.Join(args, " "))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s\ncompilation failed : %s", out, err)
	}
	return nil
}

// RenamePuyaPyOutput renames puyapy output files, e.g.,
// 'oldname.approval.teal' is renamed to 'newname.approval.teal'.
// It looks in `dir` for the files to rename, looking for these files:
// oldname.approval.teal, oldname.clear.teal, oldname.arc32.json, oldname.teal
func RenamePuyaPyOutput(oldname string, newname string, dir string) error {
	suffixes := []string{"approval.teal", "clear.teal", "arc32.json", "teal",
		"approval.puya.map", "clear.puya.map", "puya.map"}
	renamedAtLeastOne := false
	for _, suffix := range suffixes {
		oldfile := filepath.Join(dir, oldname+"."+suffix)
		_, err := os.Stat(oldfile)
		switch {
		case err == nil:
			newfile := filepath.Join(dir, newname+"."+suffix)
			if err := os.Rename(oldfile, newfile); err != nil {
				return fmt.Errorf("failed to rename %s: %v", oldfile, err)
			}
			renamedAtLeastOne = true
		case os.IsNotExist(err):
			continue
		default:
			return fmt.Errorf("error accessing %s: %v", oldfile, err)
		}
	}
	if !renamedAtLeastOne {
		return fmt.Errorf("no files found to rename")
	}
	return nil
}

// Substitute replaces all instances of `mapping` keys with their values
// overwriting `filepath`
func Substitute(filepath string, mapping map[string]string) error {
	program, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("error reading %s: %v", filepath, err)
	}
	for key, value := range mapping {
		program = []byte(strings.ReplaceAll(string(program), key, value))
	}
	// overwrite the file
	err = os.WriteFile(filepath, program, 0644)
	if err != nil {
		return fmt.Errorf("error writing %s: %v", filepath, err)
	}
	return nil
}

// RandomBigInt returns a random big integer bigger than 1 of up to
// maxBits bits. If maxBits is less than 1, it defaults to 32.
func RandomBigInt(maxBits int64) *big.Int {
	if maxBits < 1 {
		maxBits = 32
	}
	var max *big.Int = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(maxBits), nil)
	for {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		if n.Cmp(big.NewInt(2)) > 0 {
			return n
		}
	}
}

// CompiledCircuitBytes contains the compiled circuit pre-serialized to bytes
type CompiledCircuitBytes struct {
	Ccs   []byte
	Pk    []byte
	Vk    []byte
	Curve ecc.ID
}

// SerializeCompiledCircuit serializes a compiled circuit to file
func SerializeCompiledCircuit(cc *ap.CompiledCircuit, filepath string) error {
	var ccsB, pkb, vkb bytes.Buffer
	cc.Ccs.WriteTo(&ccsB)
	cc.Pk.WriteTo(&pkb)
	cc.Vk.WriteTo(&vkb)

	c := CompiledCircuitBytes{
		Ccs:   ccsB.Bytes(),
		Pk:    pkb.Bytes(),
		Vk:    vkb.Bytes(),
		Curve: cc.Curve,
	}
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("error encoding compiled circuit: %v", err)
	}

	err := os.WriteFile(filepath, buf.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("error writing compiled circuit to file: %v", err)
	}

	return nil
}

// DeserializeCompiledCircuit deserializes a compiled circuit from file
func DeserializeCompiledCircuit(filepath string) (*ap.CompiledCircuit, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("error reading compiled circuit file: %v", err)
	}

	var c CompiledCircuitBytes
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("error decoding compiled circuit: %v", err)
	}

	cc := &ap.CompiledCircuit{
		Ccs:   plonk.NewCS(c.Curve),
		Pk:    plonk.NewProvingKey(c.Curve),
		Vk:    plonk.NewVerifyingKey(c.Curve),
		Curve: c.Curve,
	}
	ccsReader := bytes.NewReader(c.Ccs)
	pkReader := bytes.NewReader(c.Pk)
	vkReader := bytes.NewReader(c.Vk)

	if _, err := cc.Ccs.ReadFrom(ccsReader); err != nil {
		return nil, fmt.Errorf("error reading CCS data: %v", err)
	}
	if _, err := cc.Pk.ReadFrom(pkReader); err != nil {
		return nil, fmt.Errorf("error reading PK data: %v", err)
	}
	if _, err := cc.Vk.ReadFrom(vkReader); err != nil {
		return nil, fmt.Errorf("error reading VK data: %v", err)
	}

	return cc, nil
}

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

// ShouldRecompile returns true if sourcePath is more recent than outputPath
// or if it encounters an error
func ShouldRecompile(sourcePath, outputPath string) bool {
	sourceFile, err := os.Stat(sourcePath)
	if err != nil {
		return true
	}
	sourceModTime := sourceFile.ModTime()

	outputFile, err := os.Stat(outputPath)
	if err != nil {
		return true
	}
	outputModTime := outputFile.ModTime()

	return sourceModTime.After(outputModTime)
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
	args, err := AbiEncodeProofAndPublicInputs(proof, publicInputs)
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
	args, err := AbiEncodeProofAndPublicInputs(proof, publicInputs)
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
	err = CompileWithPuyaPy(appCodePath, "")
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

// AbiEncodeProofAndPublicInputs encodes the []byte proof and public inputs into the ABI
// format expected by the verifiers
func AbiEncodeProofAndPublicInputs(proof []byte, publicInputs []byte) ([]interface{}, error) {
	if len(proof)%32 != 0 || len(publicInputs)%32 != 0 {
		return nil, fmt.Errorf("proof and public inputs must be 32-byte aligned")
	}
	var proofAbi, publicInputsAbi [][]byte
	for i := 0; i < len(proof); i += 32 {
		proofAbi = append(proofAbi, proof[i:i+32])
	}
	for i := 0; i < len(publicInputs); i += 32 {
		publicInputsAbi = append(publicInputsAbi, publicInputs[i:i+32])
	}
	return []interface{}{proofAbi, publicInputsAbi}, nil
}
