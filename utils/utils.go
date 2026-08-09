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
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	ap "github.com/giuliop/algoplonk"
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
// oldname.approval.teal, oldname.clear.teal, oldname.arc56.json, oldname.teal
func RenamePuyaPyOutput(oldname string, newname string, dir string) error {
	suffixes := []string{"approval.teal", "clear.teal", "arc56.json", "teal",
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
	if err := recomputeKZGVerifyingKeyLines(cc); err != nil {
		return nil, fmt.Errorf("error preparing KZG verifying keys: %v", err)
	}

	return cc, nil
}

// KZG pairing lines are derived from the verifying key's G2 points. Recompute
// them instead of trusting serialized derived data, and repair compiled circuits
// serialized by versions that persisted zero-valued lines.
func recomputeKZGVerifyingKeyLines(cc *ap.CompiledCircuit) error {
	switch cc.Curve {
	case ecc.BN254:
		pk, ok := cc.Pk.(*plonk_bn254.ProvingKey)
		if !ok {
			return fmt.Errorf("unexpected BN254 proving key type")
		}
		if pk.Vk == nil {
			return fmt.Errorf("BN254 proving key has no verifying key")
		}
		vk, ok := cc.Vk.(*plonk_bn254.VerifyingKey)
		if !ok {
			return fmt.Errorf("unexpected BN254 verifying key type")
		}
		if err := recomputeBN254KZGVerifyingKeyLines("proving key", &pk.Vk.Kzg); err != nil {
			return err
		}
		if err := recomputeBN254KZGVerifyingKeyLines("verifying key", &vk.Kzg); err != nil {
			return err
		}
	case ecc.BLS12_381:
		pk, ok := cc.Pk.(*plonk_bls12381.ProvingKey)
		if !ok {
			return fmt.Errorf("unexpected BLS12-381 proving key type")
		}
		if pk.Vk == nil {
			return fmt.Errorf("BLS12-381 proving key has no verifying key")
		}
		vk, ok := cc.Vk.(*plonk_bls12381.VerifyingKey)
		if !ok {
			return fmt.Errorf("unexpected BLS12-381 verifying key type")
		}
		if err := recomputeBLS12381KZGVerifyingKeyLines("proving key", &pk.Vk.Kzg); err != nil {
			return err
		}
		if err := recomputeBLS12381KZGVerifyingKeyLines("verifying key", &vk.Kzg); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported curve: %v", cc.Curve)
	}
	return nil
}

func recomputeBN254KZGVerifyingKeyLines(label string, vk *kzg_bn254.VerifyingKey) error {
	if vk.G1.IsInfinity() {
		return fmt.Errorf("BN254 %s KZG G1 is infinity", label)
	}
	for i := range vk.G2 {
		if vk.G2[i].IsInfinity() {
			return fmt.Errorf("BN254 %s KZG G2[%d] is infinity", label, i)
		}
		vk.Lines[i] = bn254.PrecomputeLines(vk.G2[i])
	}
	return nil
}

func recomputeBLS12381KZGVerifyingKeyLines(label string,
	vk *kzg_bls12381.VerifyingKey,
) error {
	if vk.G1.IsInfinity() {
		return fmt.Errorf("BLS12-381 %s KZG G1 is infinity", label)
	}
	for i := range vk.G2 {
		if vk.G2[i].IsInfinity() {
			return fmt.Errorf("BLS12-381 %s KZG G2[%d] is infinity", label, i)
		}
		vk.Lines[i] = bls12381.PrecomputeLines(vk.G2[i])
	}
	return nil
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
