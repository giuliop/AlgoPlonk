package utils

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	plonk_bls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	ap "github.com/giuliop/algoplonk"
)

func TestRecomputeKZGVerifyingKeyLines(t *testing.T) {
	t.Run("BN254", func(t *testing.T) {
		_, _, _, g2 := bn254.Generators()
		var g2Alpha bn254.G2Affine
		g2Alpha.ScalarMultiplication(&g2, big.NewInt(7))

		pk := &plonk_bn254.ProvingKey{Vk: &plonk_bn254.VerifyingKey{}}
		vk := &plonk_bn254.VerifyingKey{}
		pk.Vk.Kzg.G2 = [2]bn254.G2Affine{g2, g2Alpha}
		vk.Kzg.G2 = [2]bn254.G2Affine{g2, g2Alpha}
		cc := &ap.CompiledCircuit{Pk: pk, Vk: vk, Curve: ecc.BN254}

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
		_, _, _, g2 := bls12381.Generators()
		var g2Alpha bls12381.G2Affine
		g2Alpha.ScalarMultiplication(&g2, big.NewInt(7))

		pk := &plonk_bls12381.ProvingKey{Vk: &plonk_bls12381.VerifyingKey{}}
		vk := &plonk_bls12381.VerifyingKey{}
		pk.Vk.Kzg.G2 = [2]bls12381.G2Affine{g2, g2Alpha}
		vk.Kzg.G2 = [2]bls12381.G2Affine{g2, g2Alpha}
		cc := &ap.CompiledCircuit{Pk: pk, Vk: vk, Curve: ecc.BLS12_381}

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
