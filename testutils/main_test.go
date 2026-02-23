package testutils

import (
	"fmt"
	"hash"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	mimc_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	mimc_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"
	sdk "github.com/giuliop/algoplonk/testutils/algosdkwrapper"
	"github.com/giuliop/algoplonk/utils"
	"github.com/giuliop/algoplonk/verifier"
)

const (
	artefactsFolder = "generated"
)

type HashFunc func(data ...[]byte) []byte

func init() {
	// if artefactsFolder does not exist, create it
	CreateDirectoryIfNeeded(artefactsFolder)
}

const MerkleTreeLevels = 16

type MerkleCircuit struct {
	RootHash frontend.Variable `gnark:",public"`
	Path     [MerkleTreeLevels + 1]frontend.Variable
	Index    frontend.Variable
}

func (circuit *MerkleCircuit) Define(api frontend.API) error {
	m := merkle.MerkleProof{
		RootHash: circuit.RootHash,
		Path:     circuit.Path[:],
	}

	h, _ := mimc.NewMiMC(api)
	m.VerifyProof(api, &h, circuit.Index)

	return nil
}

// TestLogicsigVerifier tests the verifier logicsig
// for both BLS12_381 and BN254 curves
func TestLogicsigVerifier(t *testing.T) {
	for _, curve := range []ecc.ID{ecc.BN254, ecc.BLS12_381} {
		hash := mimcHasher(curve)
		zeroHashes := buildZeroHashes(MerkleTreeLevels, hash)
		leaves := make([][]byte, 6)
		for i := range leaves {
			leaves[i] = []byte("leaf" + fmt.Sprint(i))
		}

		indexForProof := 3 // the fourth inserted leaf
		leafForProof := leaves[indexForProof]

		path := make([][]byte, MerkleTreeLevels+1)
		path[0] = leafForProof
		path[1] = hash(leaves[2])
		path[2] = hash(hash(leaves[0]), hash(leaves[1]))
		path[3] = hash(hash(hash(leaves[4]), hash(leaves[5])), zeroHashes[1])
		for i := 4; i < MerkleTreeLevels+1; i++ {
			path[i] = zeroHashes[i-1]
		}

		rootForProof := hash(path[2], hash(path[1], hash(path[0])))
		for i := 3; i <= MerkleTreeLevels; i++ {
			rootForProof = hash(rootForProof, path[i])
		}

		var circuit MerkleCircuit
		var assignment MerkleCircuit
		var pathForProof [MerkleTreeLevels + 1]frontend.Variable
		for i := range path {
			pathForProof[i] = path[i]
		}
		assignment.RootHash = rootForProof
		assignment.Path = pathForProof
		assignment.Index = indexForProof

		verifierName := "VerifierLogicSigForCurve" + curve.String()

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

		simulate := true

		testAppId, testAppSchema, err := DeployAppWithVerifyMethod(artefactsFolder)
		if err != nil {
			t.Fatalf("error deploying test verifier app to local network: %v", err)
		}

		err = CallLogicSigVerifier(testAppId, testAppSchema, verifierLogicSig, proof,
			publicInputs, simulate)
		if err != nil {
			t.Fatalf("error calling logicsig verifier: %v", err)
		}

		// now let's change the public inputs and see it fail
		publicInputs0 := publicInputs[0]
		if publicInputs[0] == 0 {
			publicInputs[0] = 1
		} else {
			publicInputs[0] = 0
		}
		err = CallLogicSigVerifier(testAppId, testAppSchema, verifierLogicSig, proof,
			publicInputs, simulate)
		if err == nil {
			t.Fatalf("Logicsig successful but was expected to fail")
		}
		if err != nil && !strings.Contains(err.Error(), "rejected by logic") {
			t.Fatalf("Unexpected error: %v", err)
		}

		// now let's change the proof and see it fail; we change the first g1 point of
		// proof by copying the second g1 point over it
		publicInputs[0] = publicInputs0 // restore the original value
		var g1PointBytes int
		switch curve {
		case ecc.BLS12_381:
			g1PointBytes = 96
		case ecc.BN254:
			g1PointBytes = 64
		default:
			t.Fatalf("unsupported curve")
		}

		for i := 0; i < g1PointBytes; i += 1 {
			proof[i] = proof[i+g1PointBytes]
		}

		err = CallLogicSigVerifier(testAppId, testAppSchema, verifierLogicSig, proof,
			publicInputs, simulate)
		if err == nil {
			t.Fatalf("Logicsig successful but was expected to fail")
		}
		if err != nil && !strings.Contains(err.Error(), "rejected by logic") {
			t.Fatalf("Unexpected error: %v", err)
		}
	}
}

// TestSmartContractVerifier tests the verifier smart contract
// for both BLS12_381 and BN254 curves
func TestSmartContractVerifier(t *testing.T) {
	for _, curve := range []ecc.ID{ecc.BN254, ecc.BLS12_381} {
		hash := mimcHasher(curve)
		zeroHashes := buildZeroHashes(MerkleTreeLevels, hash)
		leaves := make([][]byte, 6)
		for i := range leaves {
			leaves[i] = []byte("leaf" + fmt.Sprint(i))
		}

		indexForProof := 3 // the fourth inserted leaf
		leafForProof := leaves[indexForProof]

		path := make([][]byte, MerkleTreeLevels+1)
		path[0] = leafForProof
		path[1] = hash(leaves[2])
		path[2] = hash(hash(leaves[0]), hash(leaves[1]))
		path[3] = hash(hash(hash(leaves[4]), hash(leaves[5])), zeroHashes[1])
		for i := 4; i < MerkleTreeLevels+1; i++ {
			path[i] = zeroHashes[i-1]
		}

		rootForProof := hash(path[2], hash(path[1], hash(path[0])))
		for i := 3; i <= MerkleTreeLevels; i++ {
			rootForProof = hash(rootForProof, path[i])
		}

		var circuit MerkleCircuit
		var assignment MerkleCircuit
		var pathForProof [MerkleTreeLevels + 1]frontend.Variable
		for i := range path {
			pathForProof[i] = path[i]
		}
		assignment.RootHash = rootForProof
		assignment.Path = pathForProof
		assignment.Index = indexForProof

		verifierType := verifier.SmartContract
		verifierName := "VerifierSmartContractForCurve" + curve.String()

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

		err = compiledCircuit.WritePuyaPyVerifier(puyaVerifierFilename, verifierType)
		if err != nil {
			t.Fatalf("error writing PuyaPy verifier: %v", err)
		}

		err = verifiedProof.ExportProofAndPublicInputs(proofFilename, publicInputsFilename)
		if err != nil {
			t.Fatal(err)
		}

		err = utils.CompileWithPuyaPy(puyaVerifierFilename, "")
		if err != nil {
			t.Fatal(err)
		}
		err = utils.RenamePuyaPyOutput(verifier.DefaultFileName,
			verifierName, artefactsFolder)
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

		args, err := utils.ProofAndPublicInputsForAtomicComposer(proof, publicInputs)
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
		switch result.ReturnValue {
		case true:
			// expected
		case false:
			t.Fatal("verifier app returned false")
		default:
			t.Fatal("verifier app failed")
		}

		// now let's change the public inputs and see it fail
		publicInputs0 := publicInputs[0]
		if publicInputs[0] == 0 {
			publicInputs[0] = 1
		} else {
			publicInputs[0] = 0
		}
		result, err = sdk.ExecuteAbiCall(app_id, schema, "verify", types.NoOpOC,
			args, nil, nil, simulate)
		if err != nil {
			t.Fatalf("error calling verifier app: %v", err)
		}
		if result.DecodeError != nil {
			t.Fatalf("error decoding result: %v", result.DecodeError)
		}
		switch result.ReturnValue {
		case true:
			t.Fatalf("Verifier method successful but we expected it to fail")
		case false:
			// expected
		default:
			t.Fatal("verifier app failed")
		}

		// now let's change the proof and see it fail; we change the first g1 point of
		// proof by copying the second g1 point over it
		publicInputs[0] = publicInputs0 // restore the original value
		var g1PointBytes int
		switch curve {
		case ecc.BLS12_381:
			g1PointBytes = 96
		case ecc.BN254:
			g1PointBytes = 64
		default:
			t.Fatalf("unsupported curve")
		}

		for i := 0; i < g1PointBytes; i += 1 {
			proof[i] = proof[i+g1PointBytes]
		}

		result, err = sdk.ExecuteAbiCall(app_id, schema, "verify", types.NoOpOC,
			args, nil, nil, simulate)
		if err != nil {
			t.Fatalf("error calling verifier app: %v", err)
		}
		if err == nil {
			if result.DecodeError != nil {
				t.Fatalf("error decoding result: %v", result.DecodeError)
			}
			switch result.ReturnValue {
			case true:
				t.Fatalf("Verifier method successful but we expected it to fail")
			case false:
				// expected
			default:
				t.Fatal("verifier app failed")
			}
		}
	}
}

// mimcHash hasesh data matching the circuit MiMC hashing
func mimcHasher(curve ecc.ID) HashFunc {
	var m hash.Hash
	var mod *big.Int
	switch curve {
	case ecc.BN254:
		m = mimc_bn254.NewMiMC()
		mod = fr_bn254.Modulus()
	case ecc.BLS12_381:
		m = mimc_bls12381.NewMiMC()
		mod = fr_bls12381.Modulus()
	default:
		panic("unsupported curve")
	}
	return func(data ...[]byte) []byte {
		size := m.BlockSize()
		for _, d := range data {
			n := new(big.Int).SetBytes(d)
			n.Mod(n, mod)
			d = n.Bytes()
			if len(d) < size {
				d = n.FillBytes(make([]byte, size))
			}
			m.Write(d)
		}
		result := m.Sum(nil)
		m.Reset()
		return result
	}
}

// buildZeroHashes returns a list of uninitalized nodes for the merkle tree where
// zerorHashes[i] is the node at level i assuming all the children have the
// 0 value (i.e., they are uninitialized)
func buildZeroHashes(levels int, hash HashFunc) [][]byte {
	zeroHashes := make([][]byte, levels+1) // +1 to include root
	zeroHashes[0] = hash([]byte{0})
	for i := 1; i <= levels; i++ {
		zeroHashes[i] = hash(zeroHashes[i-1], zeroHashes[i-1])
	}
	return zeroHashes
}
