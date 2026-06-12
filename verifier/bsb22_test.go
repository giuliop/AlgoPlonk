package verifier

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// bsb22TestCircuit commits to its private input nbCommitments times via the
// BSB22 commitment scheme (frontend.Committer).
type bsb22TestCircuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable

	nbCommitments int
}

func (c *bsb22TestCircuit) Define(api frontend.API) error {
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

func testVkWithCommitments(t *testing.T, curve ecc.ID, nbCommitments int,
) plonk.VerifyingKey {
	t.Helper()
	circuit := &bsb22TestCircuit{nbCommitments: nbCommitments}
	ccs, err := frontend.Compile(curve.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compiling circuit: %v", err)
	}
	srs, lag, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("creating srs: %v", err)
	}
	_, vk, err := plonk.Setup(ccs, srs, lag)
	if err != nil {
		t.Fatalf("plonk setup: %v", err)
	}
	return vk
}

func renderVerifier(t *testing.T, vk plonk.VerifyingKey, ct ContractType) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WritePythonCode(vk, ct, &buf); err != nil {
		t.Fatalf("rendering verifier: %v", err)
	}
	return buf.String()
}

// TestTemplatesWithoutCommitments verifies that circuits without BSB22
// commitments generate no commitment-gate code.
func TestTemplatesWithoutCommitments(t *testing.T) {
	for _, curve := range []ecc.ID{ecc.BN254, ecc.BLS12_381} {
		vk := testVkWithCommitments(t, curve, 0)
		for _, ct := range []ContractType{LogicSig, SmartContract} {
			code := renderVerifier(t, vk, ct)
			for _, marker := range []string{"QCP", "BSB_COM", "hash_fr"} {
				if strings.Contains(code, marker) {
					t.Errorf("%s %v: unexpected %q in code without commitments",
						curve, ct, marker)
				}
			}
		}
	}
}

// TestTemplatesWithCommitments verifies the commitment-gate code generated
// for circuits with one and two BSB22 commitments: proof length, the grouped
// proof tail (all qcp(zeta) scalars first, then all commitment points), the
// Fiat-Shamir transcript insertions, and the hash-to-field helper.
func TestTemplatesWithCommitments(t *testing.T) {
	tests := []struct {
		curve         ecc.ID
		contract      ContractType
		nbCommitments int
		want          []string
		dontWant      []string
	}{
		{
			curve: ecc.BN254, contract: LogicSig, nbCommitments: 1,
			want: []string{
				"assert proof.length == 27 * 32",
				"QCP_0_AT_Z = proof[768:800]",
				"BSB_COM_0 = proof[800:864]",
				"or BigUInt.from_bytes(QCP_0_AT_Z) >= q",
				"+ VK_QK + VK_QCP_0 + public_inputs",
				"+ beta_pre + BSB_COM_0 + GRAND_PRODUCT",
				"+ VK_S1 + VK_S2 + VK_QCP_0 + linearized_poly_at_z_bytes",
				"+ S2_AT_Z + QCP_0_AT_Z + GRAND_PRODUCT_AT_Z_OMEGA",
				"ec.scalar_mul(EC.BN254g1, BSB_COM_0, QCP_0_AT_Z)",
				"ec.scalar_mul(EC.BN254g1, VK_QCP_0, r_acc.bytes)",
				"def hash_fr(p: Bytes) -> BigUInt:",
			},
			dontWant: []string{"QCP_1", "BSB_COM_1"},
		},
		{
			curve: ecc.BN254, contract: LogicSig, nbCommitments: 2,
			want: []string{
				"assert proof.length == 30 * 32",
				"QCP_0_AT_Z = proof[768:800]",
				"QCP_1_AT_Z = proof[800:832]",
				"BSB_COM_0 = proof[832:896]",
				"BSB_COM_1 = proof[896:960]",
				"+ VK_QK + VK_QCP_0 + VK_QCP_1 + public_inputs",
				"+ beta_pre + BSB_COM_0 + BSB_COM_1 + GRAND_PRODUCT",
				"+ S2_AT_Z + QCP_0_AT_Z + QCP_1_AT_Z + GRAND_PRODUCT_AT_Z_OMEGA",
			},
		},
		{
			curve: ecc.BN254, contract: SmartContract, nbCommitments: 2,
			want: []string{
				"assert proof.length == 30",
				"QCP_0_AT_Z = proof[24].bytes",
				"QCP_1_AT_Z = proof[25].bytes",
				"BSB_COM_0 = proof[26].bytes + proof[27].bytes",
				"BSB_COM_1 = proof[28].bytes + proof[29].bytes",
				"+ VK_QK + VK_QCP_0 + VK_QCP_1 + public_inputs_bytes",
				"def hash_fr(p: Bytes) -> BigUInt:",
			},
		},
		{
			curve: ecc.BLS12_381, contract: LogicSig, nbCommitments: 1,
			want: []string{
				"assert proof.length == 37 * 32",
				"QCP_0_AT_Z = proof[1056:1088]",
				"BSB_COM_0 = proof[1088:1184]",
				"VK_QCP_0_fs = Bytes.from_hex(",
				"+ VK_QK_fs + VK_QCP_0_fs + public_inputs",
				"+ beta_pre + fs(BSB_COM_0) + fs(GRAND_PRODUCT)",
				"+ VK_S1_fs + VK_S2_fs + VK_QCP_0_fs",
				"+ S2_AT_Z + QCP_0_AT_Z",
				"hash_fr(fs(BSB_COM_0))",
				"ec.scalar_mul(EC.BLS12_381g1, BSB_COM_0, QCP_0_AT_Z)",
				"ec.scalar_mul(EC.BLS12_381g1, VK_QCP_0, r_acc.bytes)",
				"def hash_fr(p: Bytes) -> BigUInt:",
			},
		},
		{
			curve: ecc.BLS12_381, contract: LogicSig, nbCommitments: 2,
			want: []string{
				"assert proof.length == 41 * 32",
				"QCP_0_AT_Z = proof[1056:1088]",
				"QCP_1_AT_Z = proof[1088:1120]",
				"BSB_COM_0 = proof[1120:1216]",
				"BSB_COM_1 = proof[1216:1312]",
			},
		},
		{
			curve: ecc.BLS12_381, contract: SmartContract, nbCommitments: 2,
			want: []string{
				"assert proof.length == 41",
				"QCP_0_AT_Z = proof[33].bytes",
				"QCP_1_AT_Z = proof[34].bytes",
				"BSB_COM_0 = proof[35].bytes + proof[36].bytes + proof[37].bytes",
				"BSB_COM_1 = proof[38].bytes + proof[39].bytes + proof[40].bytes",
				"+ beta_pre + fs(BSB_COM_0) + fs(BSB_COM_1) + fs(GRAND_PRODUCT)",
				"def hash_fr(p: Bytes) -> BigUInt:",
			},
		},
	}

	vks := map[string]plonk.VerifyingKey{}
	vkFor := func(curve ecc.ID, n int) plonk.VerifyingKey {
		key := fmt.Sprintf("%s-%d", curve, n)
		if vk, ok := vks[key]; ok {
			return vk
		}
		vk := testVkWithCommitments(t, curve, n)
		vks[key] = vk
		return vk
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%s-%v-n%d", tt.curve, tt.contract, tt.nbCommitments)
		t.Run(name, func(t *testing.T) {
			code := renderVerifier(t, vkFor(tt.curve, tt.nbCommitments), tt.contract)
			for _, want := range tt.want {
				if !strings.Contains(code, want) {
					t.Errorf("missing %q in generated code", want)
				}
			}
			for _, dontWant := range tt.dontWant {
				if strings.Contains(code, dontWant) {
					t.Errorf("unexpected %q in generated code", dontWant)
				}
			}
		})
	}
}
