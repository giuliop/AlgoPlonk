// package tests contains tests and test helper functions
// To run the tests, a local network with default configuration is expected
// to be running.
// You can use algokit to start one with `algokit localnet start`
// Custom configuration can be set by changing the exposed variables at the top
// of the algosdkwrapper/setup.go file.
package testutils

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"

	"os/exec"
)

// CompileWithPuyapy compiles a python file with puyapy.
// Takes a name, which is the file name without the .py extension and the
// path to the directory where the file is located.
// It renames puyapy output files to match name, substituting the standard
// "Contract" prefix with name
func CompileWithPuyapy(name string, dir string) error {
	filename := filepath.Join(dir, name+".py")
	cmd := exec.Command("algokit", "compile", "py", filename)
	fmt.Printf("algokit compile py %s\n", filename)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s\ncompilation failed : %s", out, err)
	}
	err = os.Rename(filepath.Join(dir, "Contract.approval.teal"),
		filepath.Join(dir, name+".approval.teal"))
	if err != nil {
		return fmt.Errorf("failed to rename approval program: %v", err)
	}
	err = os.Rename(filepath.Join(dir, "Contract.clear.teal"),
		filepath.Join(dir, name+".clear.teal"))
	if err != nil {
		return fmt.Errorf("failed to rename clear program: %v", err)
	}
	err = os.Rename(filepath.Join(dir, "Contract.arc32.json"),
		filepath.Join(dir, name+".arc32.json"))
	if err != nil {
		return fmt.Errorf("failed to rename arc32 schema: %v", err)
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
