// This example defines a circuit that given a public root for a Merkle tree
// lets the Prover prove the presence in the tree of an element, wihtout
// revealing it.
//
// We compile the circuit with gnark, build and test a proof, generate an AVM
// verifier and compile it with puyapy, deploy it to the local network, and
// simulate on the AVM a proof verification of the generated proof
package main

import (
	"fmt"
	"log"
	"math/big"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	crypto_mimc "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"

	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"
	"github.com/giuliop/algoplonk/testutils"
	sdk "github.com/giuliop/algoplonk/testutils/algosdkwrapper"
	"github.com/giuliop/algoplonk/verifier"
)

// MerkleTreeLevels is the number of levels in the Merkle tree, excluding the root
const MerkleTreeLevels = 16

// MerkleCircuit verifies a Merkle proof for a public root.
// The prover supplies a secret index of the leaf node in the Merkle tree, and a
// Merkle proof as a path from the leaf (unhashed) up to and excluding the root.
// So Path[0] is the unhashed leaf, Path[1] is the hashed leaf sibling, and
// Path[i] is the sibling of the parent of Path[i-1].
// The circuit uses the MiMC hash function which is zk-SNARK friendly and keeps
// the circuit size small.
// gnark provides circuit implementations for MiMC and Merkle proof verification
// in its std library, so the circuit definition is very simple
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

func main() {
	// let's create a Merkle tree and a Merkle proof.
	// We insert 6 leaves in the tree and generate a proof for the 4th leaf.
	// The empty leaves have unintialized value zero
	hash := mimcHash
	zeroHashes := buildZeroHashes(MerkleTreeLevels)
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
	// let's assign our merkle proof to the zk circuit
	var assignment MerkleCircuit
	var pathForProof [MerkleTreeLevels + 1]frontend.Variable
	for i := range path {
		pathForProof[i] = path[i]
	}
	assignment.RootHash = rootForProof
	assignment.Path = pathForProof
	assignment.Index = indexForProof

	artefactsFolder := "generated"
	testutils.CreateDirectoryIfNeeded(artefactsFolder)

	verifierName := "MerkleVerifier"

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
	err = compiledCircuit.WritePuyaPyVerifier(puyaVerifierFilename)
	if err != nil {
		log.Fatalf("error writing PuyaPy verifier: %v", err)
	}

	fmt.Print("\nCompiling verifier app with puyapy: ")
	err = testutils.CompileWithPuyaPy(puyaVerifierFilename, "")
	if err != nil {
		log.Fatal(err)
	}
	err = testutils.RenamePuyaPyOutput(verifier.VerifierContractName,
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
	result, err := sdk.CallVerifyMethod(app_id, nil, proofFilename,
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

// mimcHash hasesh data matching the circuit MiMC hashing
func mimcHash(data ...[]byte) []byte {
	m := crypto_mimc.NewMiMC()
	size := m.BlockSize()
	for _, d := range data {
		n := new(big.Int).SetBytes(d)
		n.Mod(n, fr.Modulus())
		d = n.Bytes()
		if len(d) < size {
			d = n.FillBytes(make([]byte, size))
		}
		m.Write(d)
	}
	return m.Sum(nil)
}

// buildZeroHashes returns a list of uninitalized nodes for the merkle tree where
// zerorHashes[i] is the node at level i assuming all the children have the
// 0 value (i.e., they are uninitialized)
func buildZeroHashes(levels int) [][]byte {
	hash := mimcHash
	zeroHashes := make([][]byte, levels+1) // +1 to include root
	zeroHashes[0] = hash([]byte{0})
	for i := 1; i <= levels; i++ {
		zeroHashes[i] = hash(zeroHashes[i-1], zeroHashes[i-1])
	}
	return zeroHashes
}
