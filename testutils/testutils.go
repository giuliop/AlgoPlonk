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

	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"

	"os/exec"
)

// CompileWithPuyaPy compiles `filename` with puyapy, with `options'.
// Leave `options` empty to not pass any options
func CompileWithPuyaPy(filename string, options string) error {
	args := []string{"compile", "py", filename}
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
	suffixes := []string{"approval.teal", "clear.teal", "arc32.json", "teal"}
	for _, suffix := range suffixes {
		oldfile := filepath.Join(dir, oldname+"."+suffix)
		_, err := os.Stat(oldfile)
		switch {
		case err == nil:
			newfile := filepath.Join(dir, newname+"."+suffix)
			if err := os.Rename(oldfile, newfile); err != nil {
				return fmt.Errorf("failed to rename %s: %v", oldfile, err)
			}
		case os.IsNotExist(err):
			continue
		default:
			return fmt.Errorf("error accessing %s: %v", oldfile, err)
		}
	}
	return nil
}

// Substitute replaces all instances of `mapping` keys with their values
// overwriting `filename`
func Substitute(filename string, mapping map[string]string) error {
	program, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading %s: %v", filename, err)
	}
	for key, value := range mapping {
		program = []byte(strings.ReplaceAll(string(program), key, value))
	}
	// overwrite the file
	err = os.WriteFile(filename, program, 0644)
	if err != nil {
		return fmt.Errorf("error writing %s: %v", filename, err)
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
func SerializeCompiledCircuit(cc *ap.CompiledCircuit, filename string) error {
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

	err := os.WriteFile(filename, buf.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("error writing compiled circuit to file: %v", err)
	}

	return nil
}

// DeserializeCompiledCircuit deserializes a compiled circuit from file
func DeserializeCompiledCircuit(filename string) (*ap.CompiledCircuit, error) {
	data, err := os.ReadFile(filename)
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
