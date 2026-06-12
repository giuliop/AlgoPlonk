package verifier

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"text/template"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fp_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fp_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
)

// ContractType is an enum type for the type of contract to generate
type ContractType int

const (
	LogicSig ContractType = iota
	SmartContract
)

// DefaultFileName is the prefix for filenames created by PuyaPy when compiling
// the logicsig or smart contrct verifiers (e.g., Verifier.approval.teal)
const DefaultFileName = "Verifier"

// WritePythonCode generates the python code for a verifier logicsig or smart contract
// (as specified by outputType), based on the provided verifying key and writes it
// to  provided writer. The python code can be compiled with the PuyaPy compiler
func WritePythonCode(vk plonk.VerifyingKey, outputType ContractType, w io.Writer) error {
	var funcMap template.FuncMap
	var templ string
	switch vk.(type) {

	case *plonk_bn254.VerifyingKey:
		funcMap = template.FuncMap{
			"inc": func(i int) int {
				return i + 1
			},
			"add": templateAdd,
			"mul": templateMul,
			"contractName": func() string {
				return DefaultFileName
			},
			"frstr": func(x fr_bn254.Element) string {
				bv := new(big.Int)
				x.BigInt(bv)
				return bv.String()
			},
			"fpstr": func(x fp_bn254.Element) string {
				bv := new(big.Int)
				x.BigInt(bv)
				return bv.String()
			},
			"hex": func(p bn254.G1Affine) string {
				b := p.RawBytes()
				return hex.EncodeToString(b[:])
			},
		}
		if outputType == LogicSig {
			templ = tmplLogicSigVerifierBn254
		} else {
			templ = tmplSmartContractVerifierBn254
		}

	case *plonk_bls12381.VerifyingKey:
		funcMap = template.FuncMap{
			"inc": func(i int) int {
				return i + 1
			},
			"add": templateAdd,
			"mul": templateMul,
			"contractName": func() string {
				return DefaultFileName
			},
			"frstr": func(x fr_bls12381.Element) string {
				bv := new(big.Int)
				x.BigInt(bv)
				return bv.String()
			},
			"fpstr": func(x fp_bls12381.Element) string {
				bv := new(big.Int)
				x.BigInt(bv)
				return bv.String()
			},
			"hex": func(p bls12381.G1Affine) string {
				b := p.RawBytes()
				if p.IsInfinity() {
					// the first byte is 0x40 to indicate infinity,
					// but we want it set to 0x00 for the verifier
					b[0] = 0x00
				}
				return hex.EncodeToString(b[:])
			},
			"hexEncoded": func(p bls12381.G1Affine) string {
				b := p.RawBytes()
				return hex.EncodeToString(b[:])
			},
		}
		if outputType == LogicSig {
			templ = tmplLogicSigVerifierBls12_381
		} else {
			templ = tmplSmartContractVerifierBls12_381
		}

	default:
		return errors.New("unsupported curve")
	}

	t, err := template.New("t").Funcs(funcMap).Parse(templ)
	if err != nil {
		return err
	}
	return t.Execute(w, vk)
}

// templateAdd and templateMul provide integer arithmetic to the templates,
// e.g. to compute proof offsets for the BSB22 commitment data whose position
// depends on the number of commitments.
func templateAdd(a, b any) int {
	return toInt(a) + toInt(b)
}

func templateMul(a, b any) int {
	return toInt(a) * toInt(b)
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case uint64:
		return int(n)
	default:
		panic(fmt.Sprintf("unsupported integer type %T in template", v))
	}
}
