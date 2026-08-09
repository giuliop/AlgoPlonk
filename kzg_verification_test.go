package algoplonk_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"
)

type kzgOpeningCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *kzgOpeningCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

func TestTrustedSetupRejectsCorruptedKZGOpening(t *testing.T) {
	tests := []struct {
		name  string
		curve ecc.ID
		setup setup.Name
	}{
		{"BN254", ecc.BN254, setup.PerpetualPowersOfTauBN254},
		{"BLS12-381", ecc.BLS12_381, setup.EthereumKzgCeremonyBLS12381},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cc, err := ap.Compile(&kzgOpeningCircuit{}, test.curve, test.setup)
			if err != nil {
				t.Fatalf("error compiling circuit: %v", err)
			}

			verifiedProof, err := cc.Verify(&kzgOpeningCircuit{X: 3, Y: 9})
			if err != nil {
				t.Fatalf("error creating honest proof: %v", err)
			}
			publicWitness, err := verifiedProof.Witness.Public()
			if err != nil {
				t.Fatalf("error creating public witness: %v", err)
			}

			switch proof := verifiedProof.Proof.(type) {
			case *plonk_bn254.Proof:
				proof.BatchedProof.H.Double(&proof.BatchedProof.H)
			case *plonk_bls12381.Proof:
				proof.BatchedProof.H.Double(&proof.BatchedProof.H)
			default:
				t.Fatalf("unexpected proof type %T", proof)
			}

			if err := plonk.Verify(verifiedProof.Proof, cc.Vk, publicWitness); err == nil {
				t.Fatal("proof with corrupted KZG opening was accepted")
			}
		})
	}
}
