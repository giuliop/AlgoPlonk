package setup

import (
	"bytes"
	"embed"
	"encoding/binary"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/test/unsafekzg"
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

	if setup == TestOnly {
		srs, lagrangeSrs, err := unsafekzg.NewSRS(ccs)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating test SRS:  %v", err)
		}
		return plonk.Setup(ccs, srs, lagrangeSrs)
	}

	// setup == Trusted
	var srs, lagrangeSrs kzg.SRS

	numGates := uint64(ccs.GetNbConstraints() + ccs.GetNbPublicVariables())
	numGates = ecc.NextPowerOfTwo(numGates) + 3

	switch curve {
	case ecc.BLS12_381:
		_srs, err := trustedSetupBLS12381(numGates)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating SRS:  %v", err)
		}
		srs = _srs
		_lagrangeSrs := &kzg_bls12381.SRS{Vk: _srs.Vk}
		lagrangeG1, err := kzg_bls12381.ToLagrangeG1(
			_srs.Pk.G1[:len(_srs.Pk.G1)-3])
		if err != nil {
			return nil, nil, fmt.Errorf("error creating lagrange G1:  %v", err)
		}
		_lagrangeSrs.Pk.G1 = lagrangeG1
		lagrangeSrs = _lagrangeSrs

	case ecc.BN254:
		_srs, err := trustedSetupBN254(numGates)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating SRS:  %v", err)
		}
		srs = _srs
		_lagrangeSrs := &kzg_bn254.SRS{Vk: _srs.Vk}
		lagrangeG1, err := kzg_bn254.ToLagrangeG1(_srs.Pk.G1[:len(_srs.Pk.G1)-3])
		if err != nil {
			return nil, nil, fmt.Errorf("error creating lagrange G1:  %v", err)
		}
		_lagrangeSrs.Pk.G1 = lagrangeG1
		lagrangeSrs = _lagrangeSrs

	default:
		return nil, nil, fmt.Errorf("unsupported curve: %v", curve)
	}

	return plonk.Setup(ccs, srs, lagrangeSrs)
}

//go:embed bls12_381/pk.bin bls12_381/vk.bin bn254/pk.bin bn254/vk.bin
var embeddedFiles embed.FS

// trustedSetupBLS12381 returns trusted parameters for BLS12-381
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

// trustedSetupBN254 returns trusted parameters for BN254
func trustedSetupBN254(size uint64) (*kzg_bn254.SRS, error) {
	if size < 2 {
		return nil, fmt.Errorf("size must be at least 2")
	}
	var srs kzg_bn254.SRS

	G1s, err := embeddedFiles.ReadFile("bn254/pk.bin")
	if err != nil {
		return nil, fmt.Errorf("error opening pk.bin file: %v", err)
	}

	// the first 4 bytes of the file are the size of the G1 array
	G1s = G1s[:4+size*bn254.SizeOfG1AffineCompressed]

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

	vkData, err := embeddedFiles.ReadFile("bn254/vk.bin")
	if err != nil {
		return nil, fmt.Errorf("error opening vk.bin file: %v", err)
	}
	srs.Vk.ReadFrom(bytes.NewReader(vkData))

	return &srs, nil
}
