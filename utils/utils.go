// package utils contains functions and types to aid compilation and serialization /
// deserialization
package utils

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/algorand/avm-abi/abi"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	ap "github.com/giuliop/algoplonk"
)

// CompileWithPuyaPy compiles `filepath` with puyapy, with `options'.
// Leave `options` empty to not pass any options
func CompileWithPuyaPy(filepath string, options string) error {
	args := []string{"compile", "py", "-O0", filepath}
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

// shouldRecompile returns true if targetPath is more recent than any of the files in
// sourcePahts or if it encounters any error
func ShouldRecompile(targetPath string, sourcePaths ...string) bool {
	targetFile, err := os.Stat(targetPath)
	if err != nil {
		return true
	}
	targetModTime := targetFile.ModTime()

	for _, sourcePath := range sourcePaths {
		sourceFile, err := os.Stat(sourcePath)
		if err != nil {
			return true
		}
		sourceModTime := sourceFile.ModTime()
		if sourceModTime.After(targetModTime) {
			return true
		}
	}
	return false
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

// ProofAndPublicInputsForAtomicComposer takes a proof and public input binary blob and
// returns them in an []interface{} slice for AtomicTransactionComposer to make app args as
// expected by the verifiers
func ProofAndPublicInputsForAtomicComposer(proof []byte, publicInputs []byte,
) ([]interface{}, error) {

	if len(proof)%32 != 0 || len(publicInputs)%32 != 0 {
		return nil, fmt.Errorf("proof and public inputs must be 32-byte aligned")
	}
	proofAbi := chunks(proof)
	publicInputsAbi := chunks(publicInputs)

	return []interface{}{proofAbi, publicInputsAbi}, nil
}

// AbiEncodeProofAndPublicInputs takes a proof and public input binary blob and encodes them
// itto the ABI format expected by the verifiers
func AbiEncodeProofAndPublicInputs(proof []byte, publicInputs []byte) ([][]byte, error) {

	if len(proof)%32 != 0 || len(publicInputs)%32 != 0 {
		return nil, fmt.Errorf("proof and public inputs must be 32-byte aligned")
	}

	proofAbi := chunks(proof)
	publicInputsAbi := chunks(publicInputs)

	encodedProof, err := encodeARC4(proofAbi)
	if err != nil {
		return nil, fmt.Errorf("failed to encode proof: %v", err)
	}
	encodedPublicInputs, err := encodeARC4(publicInputsAbi)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public inputs: %v", err)
	}
	return [][]byte{encodedProof, encodedPublicInputs}, nil
}

// encodeARC4 encodes a proof or public inputs into the ABI format expected by the verifiers
func encodeARC4(input [][]byte) ([]byte, error) {
	arcType, err := abi.TypeOf("byte[32][]")
	if err != nil {
		return nil, fmt.Errorf("failed to define ABI type: %v", err)
	}
	interfaceArray := make([]interface{}, len(input))
	for i, b := range input {
		interfaceArray[i] = b
	}
	encoded, err := arcType.Encode(interfaceArray)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ARC4 array: %v", err)
	}
	return encoded, nil
}

// chunks splits a byte slice into 32-byte chunks
// it panics if the input slice is not 32-byte aligned
func chunks(data []byte) [][]byte {
	if len(data)%32 != 0 {
		panic("data must be 32-byte aligned")
	}
	var chunks [][]byte
	for i := 0; i < len(data); i += 32 {
		chunks = append(chunks, data[i:i+32])
	}
	return chunks
}
