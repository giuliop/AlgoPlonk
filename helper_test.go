package algoplonk

import (
	"bytes"
	"testing"

	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	plonk_bls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
)

func TestMarshalBls12381ProofEncodesInfinityForAVM(t *testing.T) {
	proof := new(plonk_bls12381.Proof)
	proof.BatchedProof.ClaimedValues = make([]fr_bls12381.Element, 6)

	blob := marshalPlonkBls12381Proof(proof)
	if got, want := len(blob), 1056; got != want {
		t.Fatalf("proof length is %d, want %d", got, want)
	}
	if !bytes.Equal(blob, make([]byte, len(blob))) {
		t.Fatal("BLS12-381 point at infinity is not encoded as AVM (0,0)")
	}
}
