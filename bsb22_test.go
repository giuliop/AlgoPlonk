package algoplonk_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	plonk_bls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"
)

// bsb22Circuit commits to its private input nbCommitments times via the
// BSB22 commitment scheme (frontend.Committer).
type bsb22Circuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable

	nbCommitments int
}

func (c *bsb22Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, api.Mul(c.Y, c.Y))
	committer, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("compiler does not support Commit")
	}
	for range c.nbCommitments {
		cmt, err := committer.Commit(c.Y, c.X)
		if err != nil {
			return err
		}
		api.AssertIsDifferent(cmt, 0)
	}
	return nil
}

// TestBsb22ProofMarshalling proves circuits with one and two BSB22
// commitments (verifying them with gnark locally) and checks that the
// marshalled proof blob has the layout the generated verifiers expect:
// the base proof words followed by all qcp(zeta) openings, then all
// commitment points.
func TestBsb22ProofMarshalling(t *testing.T) {
	for _, curve := range []ecc.ID{ecc.BN254, ecc.BLS12_381} {
		for _, n := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s-n%d", curve, n), func(t *testing.T) {
				circuit := &bsb22Circuit{nbCommitments: n}
				assignment := &bsb22Circuit{X: 9, Y: 3}

				cc, err := ap.Compile(circuit, curve, setup.TestOnlySetup(curve))
				if err != nil {
					t.Fatalf("error compiling circuit: %v", err)
				}
				// Verify runs gnark's native prover and verifier
				vp, err := cc.Verify(assignment)
				if err != nil {
					t.Fatalf("error proving/verifying: %v", err)
				}

				blob := ap.MarshalProof(vp.Proof)

				var baseWords, pointBytes int
				var claimedValues [][]byte
				var commitments [][]byte
				switch curve {
				case ecc.BN254:
					baseWords, pointBytes = 24, 64
					proof := vp.Proof.(*plonk_bn254.Proof)
					if len(proof.Bsb22Commitments) != n {
						t.Fatalf("expected %d commitments, got %d",
							n, len(proof.Bsb22Commitments))
					}
					for i := range n {
						cv := proof.BatchedProof.ClaimedValues[6+i].Bytes()
						claimedValues = append(claimedValues, cv[:])
						pt := proof.Bsb22Commitments[i].RawBytes()
						commitments = append(commitments, pt[:])
					}
				case ecc.BLS12_381:
					baseWords, pointBytes = 33, 96
					proof := vp.Proof.(*plonk_bls12381.Proof)
					if len(proof.Bsb22Commitments) != n {
						t.Fatalf("expected %d commitments, got %d",
							n, len(proof.Bsb22Commitments))
					}
					for i := range n {
						cv := proof.BatchedProof.ClaimedValues[6+i].Bytes()
						claimedValues = append(claimedValues, cv[:])
						pt := proof.Bsb22Commitments[i].RawBytes()
						commitments = append(commitments, pt[:])
					}
				}

				wantLen := baseWords*32 + n*32 + n*pointBytes
				if len(blob) != wantLen {
					t.Fatalf("expected proof blob of %d bytes, got %d",
						wantLen, len(blob))
				}

				// all qcp(zeta) openings first ...
				for i := range n {
					start := (baseWords + i) * 32
					if !bytes.Equal(blob[start:start+32], claimedValues[i]) {
						t.Errorf("qcp_%d(zeta) mismatch at word %d",
							i, baseWords+i)
					}
				}
				// ... then all commitment points
				pointsStart := (baseWords + n) * 32
				for i := range n {
					start := pointsStart + i*pointBytes
					if !bytes.Equal(blob[start:start+pointBytes], commitments[i]) {
						t.Errorf("Bsb22 commitment %d mismatch at offset %d",
							i, start)
					}
				}
			})
		}
	}
}
