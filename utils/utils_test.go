package utils

import (
	"math/big"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"
)

func TestRecomputeKZGVerifyingKeyLines(t *testing.T) {
	t.Run("BN254", func(t *testing.T) {
		cc := newBN254KZGTestCircuit()
		pk := cc.Pk.(*plonk_bn254.ProvingKey)
		vk := cc.Vk.(*plonk_bn254.VerifyingKey)

		if err := recomputeKZGVerifyingKeyLines(cc); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for i := range vk.Kzg.G2 {
			expected := bn254.PrecomputeLines(vk.Kzg.G2[i])
			if !reflect.DeepEqual(vk.Kzg.Lines[i], expected) ||
				!reflect.DeepEqual(pk.Vk.Kzg.Lines[i], expected) {
				t.Errorf("incorrect precomputed lines for G2[%d]", i)
			}
		}
	})

	t.Run("BLS12-381", func(t *testing.T) {
		cc := newBLS12381KZGTestCircuit()
		pk := cc.Pk.(*plonk_bls12381.ProvingKey)
		vk := cc.Vk.(*plonk_bls12381.VerifyingKey)

		if err := recomputeKZGVerifyingKeyLines(cc); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for i := range vk.Kzg.G2 {
			expected := bls12381.PrecomputeLines(vk.Kzg.G2[i])
			if !reflect.DeepEqual(vk.Kzg.Lines[i], expected) ||
				!reflect.DeepEqual(pk.Vk.Kzg.Lines[i], expected) {
				t.Errorf("incorrect precomputed lines for G2[%d]", i)
			}
		}
	})
}

func TestRecomputeKZGVerifyingKeyLinesRejectsInfinity(t *testing.T) {
	t.Run("BN254", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(*ap.CompiledCircuit)
		}{
			{"proving key G1", func(cc *ap.CompiledCircuit) {
				cc.Pk.(*plonk_bn254.ProvingKey).Vk.Kzg.G1 = bn254.G1Affine{}
			}},
			{"proving key G2[0]", func(cc *ap.CompiledCircuit) {
				cc.Pk.(*plonk_bn254.ProvingKey).Vk.Kzg.G2[0] = bn254.G2Affine{}
			}},
			{"proving key G2[1]", func(cc *ap.CompiledCircuit) {
				cc.Pk.(*plonk_bn254.ProvingKey).Vk.Kzg.G2[1] = bn254.G2Affine{}
			}},
			{"verifying key G1", func(cc *ap.CompiledCircuit) {
				cc.Vk.(*plonk_bn254.VerifyingKey).Kzg.G1 = bn254.G1Affine{}
			}},
			{"verifying key G2[0]", func(cc *ap.CompiledCircuit) {
				cc.Vk.(*plonk_bn254.VerifyingKey).Kzg.G2[0] = bn254.G2Affine{}
			}},
			{"verifying key G2[1]", func(cc *ap.CompiledCircuit) {
				cc.Vk.(*plonk_bn254.VerifyingKey).Kzg.G2[1] = bn254.G2Affine{}
			}},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				cc := newBN254KZGTestCircuit()
				test.mutate(cc)
				if err := recomputeKZGVerifyingKeyLines(cc); err == nil {
					t.Fatal("expected infinity point to be rejected")
				}
			})
		}
	})

	t.Run("BLS12-381", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(*ap.CompiledCircuit)
		}{
			{"proving key G1", func(cc *ap.CompiledCircuit) {
				cc.Pk.(*plonk_bls12381.ProvingKey).Vk.Kzg.G1 = bls12381.G1Affine{}
			}},
			{"proving key G2[0]", func(cc *ap.CompiledCircuit) {
				cc.Pk.(*plonk_bls12381.ProvingKey).Vk.Kzg.G2[0] = bls12381.G2Affine{}
			}},
			{"proving key G2[1]", func(cc *ap.CompiledCircuit) {
				cc.Pk.(*plonk_bls12381.ProvingKey).Vk.Kzg.G2[1] = bls12381.G2Affine{}
			}},
			{"verifying key G1", func(cc *ap.CompiledCircuit) {
				cc.Vk.(*plonk_bls12381.VerifyingKey).Kzg.G1 = bls12381.G1Affine{}
			}},
			{"verifying key G2[0]", func(cc *ap.CompiledCircuit) {
				cc.Vk.(*plonk_bls12381.VerifyingKey).Kzg.G2[0] = bls12381.G2Affine{}
			}},
			{"verifying key G2[1]", func(cc *ap.CompiledCircuit) {
				cc.Vk.(*plonk_bls12381.VerifyingKey).Kzg.G2[1] = bls12381.G2Affine{}
			}},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				cc := newBLS12381KZGTestCircuit()
				test.mutate(cc)
				if err := recomputeKZGVerifyingKeyLines(cc); err == nil {
					t.Fatal("expected infinity point to be rejected")
				}
			})
		}
	})
}

type serializedKZGCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *serializedKZGCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

func TestDeserializeCompiledCircuitRepairsKZGVerifyingKeyLines(t *testing.T) {
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
			cc, err := ap.Compile(&serializedKZGCircuit{}, test.curve, test.setup)
			if err != nil {
				t.Fatalf("error compiling circuit: %v", err)
			}
			verifiedProof, err := cc.Verify(&serializedKZGCircuit{X: 3, Y: 9})
			if err != nil {
				t.Fatalf("error creating honest proof: %v", err)
			}
			publicWitness, err := verifiedProof.Witness.Public()
			if err != nil {
				t.Fatalf("error creating public witness: %v", err)
			}

			zeroKZGVerifyingKeyLines(cc)
			path := filepath.Join(t.TempDir(), "compiled-circuit.bin")
			if err := SerializeCompiledCircuit(cc, path); err != nil {
				t.Fatalf("error serializing compiled circuit: %v", err)
			}
			loaded, err := DeserializeCompiledCircuit(path)
			if err != nil {
				t.Fatalf("error deserializing compiled circuit: %v", err)
			}

			switch proof := verifiedProof.Proof.(type) {
			case *plonk_bn254.Proof:
				proof.BatchedProof.H.Double(&proof.BatchedProof.H)
			case *plonk_bls12381.Proof:
				proof.BatchedProof.H.Double(&proof.BatchedProof.H)
			default:
				t.Fatalf("unexpected proof type %T", proof)
			}
			if err := plonk.Verify(verifiedProof.Proof, loaded.Vk, publicWitness); err == nil {
				t.Fatal("proof with corrupted KZG opening was accepted after artifact repair")
			}
		})
	}
}

func newBN254KZGTestCircuit() *ap.CompiledCircuit {
	_, _, g1, g2 := bn254.Generators()
	var g2Alpha bn254.G2Affine
	g2Alpha.ScalarMultiplication(&g2, big.NewInt(7))
	pk := &plonk_bn254.ProvingKey{Vk: &plonk_bn254.VerifyingKey{}}
	vk := &plonk_bn254.VerifyingKey{}
	pk.Vk.Kzg.G1 = g1
	pk.Vk.Kzg.G2 = [2]bn254.G2Affine{g2, g2Alpha}
	vk.Kzg.G1 = g1
	vk.Kzg.G2 = [2]bn254.G2Affine{g2, g2Alpha}
	return &ap.CompiledCircuit{Pk: pk, Vk: vk, Curve: ecc.BN254}
}

func newBLS12381KZGTestCircuit() *ap.CompiledCircuit {
	_, _, g1, g2 := bls12381.Generators()
	var g2Alpha bls12381.G2Affine
	g2Alpha.ScalarMultiplication(&g2, big.NewInt(7))
	pk := &plonk_bls12381.ProvingKey{Vk: &plonk_bls12381.VerifyingKey{}}
	vk := &plonk_bls12381.VerifyingKey{}
	pk.Vk.Kzg.G1 = g1
	pk.Vk.Kzg.G2 = [2]bls12381.G2Affine{g2, g2Alpha}
	vk.Kzg.G1 = g1
	vk.Kzg.G2 = [2]bls12381.G2Affine{g2, g2Alpha}
	return &ap.CompiledCircuit{Pk: pk, Vk: vk, Curve: ecc.BLS12_381}
}

func zeroKZGVerifyingKeyLines(cc *ap.CompiledCircuit) {
	switch cc.Curve {
	case ecc.BN254:
		zero := [2][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{}
		cc.Pk.(*plonk_bn254.ProvingKey).Vk.Kzg.Lines = zero
		cc.Vk.(*plonk_bn254.VerifyingKey).Kzg.Lines = zero
	case ecc.BLS12_381:
		zero := [2][2][len(bls12381.LoopCounter) - 1]bls12381.LineEvaluationAff{}
		cc.Pk.(*plonk_bls12381.ProvingKey).Vk.Kzg.Lines = zero
		cc.Vk.(*plonk_bls12381.VerifyingKey).Kzg.Lines = zero
	}
}
