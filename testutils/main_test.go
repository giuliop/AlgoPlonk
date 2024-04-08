package testutils

import (
	"fmt"
	"hash"
	"math/big"
	"path/filepath"
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

func TestCircuitBothCurves(t *testing.T) {
	for _, curve := range []ecc.ID{ecc.BLS12_381, ecc.BN254} {
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

		verifierName := "TestVerifierForCurve" + curve.String()
		puyaVerifierFilename := filepath.Join(artefactsFolder, verifierName+".py")
		proofFilename := filepath.Join(artefactsFolder, verifierName+".proof")
		publicInputsFilename := filepath.Join(artefactsFolder,
			verifierName+".public_inputs")

		compiledCircuit, err := ap.Compile(&circuit, curve, setup.Trusted)
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
	var circuit MerkleCircuit

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

// mimcHash hasesh data matching the circuit MiMC hashing
func mimcHasher(curve ecc.ID) HashFunc {
	var m hash.Hash
	var mod *big.Int
	if curve == ecc.BN254 {
		m = mimc_bn254.NewMiMC()
		mod = fr_bn254.Modulus()
	} else if curve == ecc.BLS12_381 {
		m = mimc_bls12381.NewMiMC()
		mod = fr_bls12381.Modulus()
	} else {
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
