package verifier

import (
	"io"
	"strings"
	"testing"

	"github.com/consensys/gnark/backend/plonk"
	plonk_bls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
)

func TestInvertTemplatesPreserveXCoordinate(t *testing.T) {
	tests := []struct {
		name   string
		tmpl   string
		xDecl  string
		want   string
		legacy string
	}{
		{
			name:   "logic sig BN254",
			tmpl:   tmplLogicSigVerifierBn254,
			xDecl:  "x = p[:32]",
			want:   "return x + UInt256(neg_y).bytes",
			legacy: "x = BigUInt.from_bytes(p[:32])",
		},
		{
			name:   "smart contract BN254",
			tmpl:   tmplSmartContractVerifierBn254,
			xDecl:  "x = p[:32]",
			want:   "return x + UInt256(neg_y).bytes",
			legacy: "x = BigUInt.from_bytes(p[:32])",
		},
		{
			name:   "logic sig BLS12-381",
			tmpl:   tmplLogicSigVerifierBls12_381,
			xDecl:  "x = p[:48]",
			want:   "return x + (bzero(48) | (neg_y).bytes)",
			legacy: "x = BigUInt.from_bytes(p[:48])",
		},
		{
			name:   "smart contract BLS12-381",
			tmpl:   tmplSmartContractVerifierBls12_381,
			xDecl:  "x = p[:48]",
			want:   "return x + (bzero(48) | (neg_y).bytes)",
			legacy: "x = BigUInt.from_bytes(p[:48])",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.tmpl, tt.xDecl) {
				t.Fatalf("invert helper does not preserve x-coordinate bytes")
			}
			if !strings.Contains(tt.tmpl, tt.want) {
				t.Fatalf("invert helper does not return the original x-coordinate bytes")
			}
			if strings.Contains(tt.tmpl, tt.legacy) {
				t.Fatalf("invert helper still decodes x-coordinate")
			}
		})
	}
}

func TestBls12381TemplatesEncodeInfinityForFiatShamir(t *testing.T) {
	for name, tmpl := range map[string]string{
		"logic sig":      tmplLogicSigVerifierBls12_381,
		"smart contract": tmplSmartContractVerifierBls12_381,
	} {
		t.Run(name, func(t *testing.T) {
			for _, want := range []string{
				"return setbit_bytes(p, 1, True)",
				"UInt256(zeta).bytes + fs(lin_poly_com)",
				"sha256(fs(digest) + fs(BATCH_OPENING_AT_Z) + fs(GRAND_PRODUCT)",
				"+ fs(OPENING_AT_Z_OMEGA) + UInt256(zeta).bytes",
			} {
				if !strings.Contains(tmpl, want) {
					t.Errorf("missing %q", want)
				}
			}
			if strings.Contains(tmpl, "setbit_bytes(p, 0, True)") {
				t.Error("infinity encoding sets 0x80 instead of gnark's 0x40 flag")
			}
		})
	}
}

func TestWritePythonCodeRejectsInvalidContractType(t *testing.T) {
	for name, vk := range map[string]plonk.VerifyingKey{
		"BN254":     new(plonk_bn254.VerifyingKey),
		"BLS12-381": new(plonk_bls12381.VerifyingKey),
	} {
		t.Run(name, func(t *testing.T) {
			if err := WritePythonCode(vk, ContractType(2), io.Discard); err == nil {
				t.Fatal("expected invalid contract type to be rejected")
			}
		})
	}
}
