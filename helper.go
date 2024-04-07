package algoplonk

import (
	"fmt"

	"github.com/consensys/gnark/backend/plonk"
	plonk_bls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/backend/witness"
)

// marshalPlonkBn254Proof marshals a Plonk proof to a binary blob
func marshalProof(proof plonk.Proof) []byte {
	var data []byte
	switch _proof := proof.(type) {
	case *plonk_bn254.Proof:
		data = _proof.MarshalSolidity()
	case *plonk_bls12381.Proof:
		data = marshalPlonkBls12381Proof(_proof)
	default:
		panic("unrecognized proof type")
	}
	return data
}

// marshalPlonkBls12381Proof marshals a BLS12-381 proof to a binary blob
func marshalPlonkBls12381Proof(proof *plonk_bls12381.Proof) []byte {
	res := make([]byte, 0, 1024)

	// [3][32]byte l_com_x
	// [3][32]byte r_com_x
	// [3][32]byte o_com_x
	var tmp96 [96]byte
	for i := 0; i < 3; i++ {
		tmp96 = proof.LRO[i].RawBytes()
		res = append(res, tmp96[:]...)
	}

	// [3][32]byte h1
	// [3][32]byte h2
	// [3][32]byte h3
	for i := 0; i < 3; i++ {
		tmp96 = proof.H[i].RawBytes()
		res = append(res, tmp96[:]...)
	}
	var tmp32 [32]byte

	// [32]byte l_at_zeta;
	// [32]byte r_at_zeta;
	// [32]byte o_at_zeta;
	// [32]byte s1_at_zeta;
	// [32]byte s2_at_zeta;
	for i := 2; i < 7; i++ {
		tmp32 = proof.BatchedProof.ClaimedValues[i].Bytes()
		res = append(res, tmp32[:]...)
	}

	// [3][32]byte grand_product_commitment
	tmp96 = proof.Z.RawBytes()
	res = append(res, tmp96[:]...)

	// [32]byte grand_product_at_zeta_omega;
	tmp32 = proof.ZShiftedOpening.ClaimedValue.Bytes()
	res = append(res, tmp32[:]...)

	// [32]byte quotient_polynomial_at_zeta;
	// [32]byte linearization_polynomial_at_zeta;
	tmp32 = proof.BatchedProof.ClaimedValues[0].Bytes()
	res = append(res, tmp32[:]...)
	tmp32 = proof.BatchedProof.ClaimedValues[1].Bytes()
	res = append(res, tmp32[:]...)

	// [3][32]byte opening_at_zeta_proof
	tmp96 = proof.BatchedProof.H.RawBytes()
	res = append(res, tmp96[:]...)

	// [3][32]byte opening_at_zeta_omega_proof
	tmp96 = proof.ZShiftedOpening.H.RawBytes()
	res = append(res, tmp96[:]...)

	// [][32]byte selector_commit_api_at_zeta;
	// [][96]byte wire_committed_commitments;
	if len(proof.Bsb22Commitments) > 0 {
		for i := 0; i < len(proof.Bsb22Commitments); i++ {
			tmp32 = proof.BatchedProof.ClaimedValues[7+i].Bytes()
			res = append(res, tmp32[:]...)
		}
		for _, bc := range proof.Bsb22Commitments {
			tmp96 = bc.RawBytes()
			res = append(res, tmp96[:]...)
		}
	}

	return res
}

func extractPublicInputs(witness witness.Witness) ([]byte, error) {
	public, err := witness.Public()
	if err != nil {
		return nil, fmt.Errorf("error extracting public witness: %v", err)
	}
	// MarshalBinary packs public witness data as per gnark binary format
	// (all big-endian):
	//   - 4 bytes uint32 :number of public variables
	//   - 4 bytes uint32 :number of secret variables
	//   - 4 bytes uint32 :number of total variables
	//   - a byte array for each variables, public first, then private,
	//	   in the same order as in the circuit definition, of the same size as
	//     the field modulus
	data, err := public.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("error marshaling public witness: %v", err)
	}
	// we now remove the first 12 bytes, to keep only the public inputs
	return data[12:], nil
}
