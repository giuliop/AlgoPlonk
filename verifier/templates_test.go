package verifier

import (
	"strings"
	"testing"
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
