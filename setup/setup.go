package setup

import (
	"bytes"
	"embed"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
)

// Conf specified what setup to run, either trusted as per doc.go or a test only
// setup not suitable for production.
type Conf int

const (
	Trusted Conf = iota
	TestOnly
)

// Run sets up a plonk system using either a trusted or test only setup,
// as specified by the setup parameter.
func Run(ccs constraint.ConstraintSystem, curve ecc.ID, setup Conf) (
	plonk.ProvingKey, plonk.VerifyingKey, error) {

	numGates := uint64(ccs.GetNbConstraints() + ccs.GetNbPublicVariables())
	numGates = ecc.NextPowerOfTwo(numGates)

	var srs kzg.SRS
	var err error

	switch curve {
	case ecc.BLS12_381:
		if setup == Trusted {
			srs, err = trustedSetupBLS12381(numGates + 5)
		} else if setup == TestOnly {
			srs, err = kzg_bls12381.NewSRS(numGates+5, big.NewInt(-1))
		}
	case ecc.BN254:
		if setup == Trusted {
			return nil, nil, fmt.Errorf("trusted setup not available for BN254")
		} else if setup == TestOnly {
			srs, err = kzg_bn254.NewSRS(numGates+5, big.NewInt(-1))
		}
	default:
		return nil, nil, fmt.Errorf("unsupported curve: %v", curve)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("error creating SRS:  %v", err)
	}

	return plonk.Setup(ccs, srs)
}

//go:embed bls12_381/pk.bin bls12_381/vk.bin
var embeddedFiles embed.FS

// trustedSetupBLS12381 returns trusted parameters for BLS12-381.
func trustedSetupBLS12381(size uint64) (*kzg_bls12381.SRS, error) {
	if size < 2 {
		return nil, fmt.Errorf("size must be at least 2")
	}
	var srs kzg_bls12381.SRS

	G1s, err := embeddedFiles.ReadFile("bls12_381/pk.bin")
	if err != nil {
		return nil, fmt.Errorf("error opening pk.bin file: %v", err)
	}

	// the first 4 bytes of the file are the size of the G1 array
	G1s = G1s[:4+size*bls12381.SizeOfG1AffineCompressed]

	LenG1Params := G1s[:4]
	LenG1ParamsN := uint64(binary.BigEndian.Uint32(LenG1Params))
	if LenG1ParamsN < size {
		return nil, fmt.Errorf("you required %d G1 parameters, but only %d are "+
			"available", size, LenG1ParamsN)
	}

	newSize := make([]byte, 4)
	binary.BigEndian.PutUint32(newSize, uint32(size))
	copy(G1s[:4], newSize)

	srs.Pk.ReadFrom(bytes.NewReader(G1s))

	vkData, err := embeddedFiles.ReadFile("bls12_381/vk.bin")
	if err != nil {
		return nil, fmt.Errorf("error opening vk.bin file: %v", err)
	}
	srs.Vk.ReadFrom(bytes.NewReader(vkData))

	return &srs, nil
}
