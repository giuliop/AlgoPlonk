package algoplonk

import (
	"fmt"
	"io"
	"os"

	"github.com/giuliop/algoplonk/setup"
	"github.com/giuliop/algoplonk/verifier"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

// CompiledCircuit is a compiled circuit with its proving and verifying keys
type CompiledCircuit struct {
	Ccs   constraint.ConstraintSystem
	Pk    plonk.ProvingKey
	Vk    plonk.VerifyingKey
	Curve ecc.ID
}

// VerifiedProof is a proof and its witness, generated after verifying the proof
type VerifiedProof struct {
	Proof   plonk.Proof
	Witness witness.Witness
}

// Compile generates a CompiledCircuit from a circuit definiton and a curve id.
// The curves supported by the AVM are ecc.BN254 and ecc.BLS12_381.
// setupConf specifies whether to run a `Trusted` setup or a `TestOnly' setup,
// the latter not suitable for production.
func Compile(circuit frontend.Circuit, curve ecc.ID, setupConf setup.Conf) (
	*CompiledCircuit, error) {
	if curve != ecc.BN254 && curve != ecc.BLS12_381 {
		return nil, fmt.Errorf("unsupported curve: %v", curve)
	}
	ccs, err := frontend.Compile(curve.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("error compiling circuit: %v", err)
	}
	provingKey, verifyingKey, err := setup.Run(ccs, curve, setupConf)
	if err != nil {
		return nil, fmt.Errorf("error setting up Plonk: %v", err)
	}
	return &CompiledCircuit{ccs, provingKey, verifyingKey, curve}, nil
}

// WritePuyaPyVerifier writes to file python code that the PuyaPy compiler can
// compile to a smart contract verifier for the circuit.
func (cc *CompiledCircuit) WritePuyaPyVerifier(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer file.Close()

	// TODO: update WritePuyaPy to take canUpdate and canDelete
	err = verifier.WritePuyaPy(cc.Vk, file)
	if err != nil {
		err = fmt.Errorf("error writing PuyaPy contract: %v", err)
	}
	return err
}

// Verify generates a proof from a circuit assignment and verifies it
// using gnark
func (cc *CompiledCircuit) Verify(assignment frontend.Circuit,
) (*VerifiedProof, error) {
	witness, err := frontend.NewWitness(assignment, cc.Curve.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("error creating witness: %v", err)
	}
	publicInputs, err := witness.Public()
	if err != nil {
		return nil, fmt.Errorf("error creating public inputs: %v", err)
	}
	proof, err := plonk.Prove(cc.Ccs, cc.Pk, witness)
	if err != nil {
		return nil, fmt.Errorf("error creating Plonk proof: %v", err)
	}
	err = plonk.Verify(proof, cc.Vk, publicInputs)
	if err != nil {
		return nil, fmt.Errorf("error verifying Plonk proof: %v", err)
	}
	return &VerifiedProof{proof, witness}, nil
}

// ExportProofAndPublicInputs writes a proof and its public inputs to files
// as binary blobs for the AVM verifier
func (vp *VerifiedProof) ExportProofAndPublicInputs(proofFileName string,
	publicInputsFileName string) error {

	proofFile, err := os.Create(proofFileName)
	if err != nil {
		return fmt.Errorf("error creating proof file: %v", err)
	}
	defer proofFile.Close()

	publicInputsFile, err := os.Create(publicInputsFileName)
	if err != nil {
		return fmt.Errorf("error creating public inputs file: %v", err)
	}
	defer publicInputsFile.Close()

	err = vp.WriteProof(proofFile)
	if err != nil {
		return err
	}
	err = vp.WritePublicInputs(publicInputsFile)
	if err != nil {
		return err
	}
	return nil
}

// WriteProof writes a proof as a binary blob that can be passed to AVM verifiers
func (vp *VerifiedProof) WriteProof(w io.Writer) error {
	data := MarshalProof(vp.Proof)
	_, err := w.Write(data)
	if err != nil {
		return fmt.Errorf("error writing proof: %v", err)
	}
	return nil
}

// WritePublicInputs writes the public inputs as a binary blob that can be passed
// to AVM verifiers
func (vp *VerifiedProof) WritePublicInputs(w io.Writer) error {
	data, err := MarshalPublicInputs(vp.Witness)
	if err != nil {
		return fmt.Errorf("error extracting public inputs: %v", err)
	}
	_, err = w.Write(data)
	if err != nil {
		return fmt.Errorf("error writing public inputs: %v", err)
	}
	return err
}
