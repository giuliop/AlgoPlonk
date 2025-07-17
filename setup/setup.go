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

// Name specifies a setup among the available trusted setups, or a test only
// setup not suitable for production. By convention, the setup name ends with
// "BN254" or "BLS12_381" to indicate the curve used
type Name int

// Available setups. To add a new setup you need to:
// 1. Add a new Name constant below with the appropriate name
// 2. Add a new entry in the Setups map below with the appropriate curve and NamePath
// 3. Create the setup/<NamePath> directory with the trusted setup files pk.bin and vk.bin
// 4. Embed the files in the binary using go:embed, as shown below
const (
	PerpetualPowersOfTauBN254 Name = iota
	EthereumKzgCeremonyBLS12381
	DuskBLS12381
	TestOnlyBN254
	TestOnlyBLS12381
)

// Setup contains the parameters for a trusted or test only setup.
// If Trusted is true, NamePath is the dir of the embedded files containing the trusted
// setup parameters: <NamePath>/pk.bin and <NamePath>/vk.bin
// If Trusted is false, NamePath is ignored and a test-only setup is created using unsafekzg,
// this is NOT suitable for production.
type Setup struct {
	Curve    ecc.ID // the elliptic curve used by the setup
	NamePath string // the embedded file name containing the setup
	Trusted  bool   // whether this is a test only setup
}

// Setups is a map of available setups, indexed by their Name.
var Setups = map[Name]Setup{
	PerpetualPowersOfTauBN254: {
		Curve:    ecc.BN254,
		NamePath: "PerpetualPowersOfTauBN254",
		Trusted:  true,
	},
	EthereumKzgCeremonyBLS12381: {
		Curve:    ecc.BLS12_381,
		NamePath: "EethereumKzgCeremonyBLS12_381",
		Trusted:  true,
	},
	DuskBLS12381: {
		Curve:    ecc.BLS12_381,
		NamePath: "DuskBLS12_381",
		Trusted:  true,
	},
	TestOnlyBN254: {
		Curve:    ecc.BN254,
		NamePath: "test_only",
		Trusted:  false,
	},
	TestOnlyBLS12381: {
		Curve:    ecc.BLS12_381,
		NamePath: "test_only",
		Trusted:  false,
	},
}

// We embed the trusted setup files in the binary using go:embed
//
//go:embed EethereumKzgCeremonyBLS12_381/pk.bin
//go:embed EethereumKzgCeremonyBLS12_381/vk.bin
//go:embed PerpetualPowersOfTauBN254/pk.bin
//go:embed PerpetualPowersOfTauBN254/vk.bin
//go:embed DuskBLS12_381/pk.bin
//go:embed DuskBLS12_381/vk.bin
var embeddedFiles embed.FS

// Run sets up a plonk system using either a trusted or test only setup,
// as specified by the setup parameter.
func Run(ccs constraint.ConstraintSystem, setupConfig Name) (
	plonk.ProvingKey, plonk.VerifyingKey, error) {

	setup := Setups[setupConfig]
	if !setup.Trusted {
		srs, lagrangeSrs, err := unsafekzg.NewSRS(ccs)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating test SRS:  %v", err)
		}
		return plonk.Setup(ccs, srs, lagrangeSrs)
	}

	// setup.Trusted == true
	var srs, lagrangeSrs kzg.SRS

	numGates := uint64(ccs.GetNbConstraints() + ccs.GetNbPublicVariables())
	numGates = ecc.NextPowerOfTwo(numGates) + 3

	switch setup.Curve {
	case ecc.BLS12_381:
		_srs, err := trustedSetupBLS12381(numGates, setup.NamePath)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating SRS:  %v", err)
		}
		srs = _srs
		_lagrangeSrs := &kzg_bls12381.SRS{Vk: _srs.Vk}
		lagrangeG1, err := kzg_bls12381.ToLagrangeG1(_srs.Pk.G1[:len(_srs.Pk.G1)-3])
		if err != nil {
			return nil, nil, fmt.Errorf("error creating lagrange G1:  %v", err)
		}
		_lagrangeSrs.Pk.G1 = lagrangeG1
		lagrangeSrs = _lagrangeSrs

	case ecc.BN254:
		_srs, err := trustedSetupBN254(numGates, setup.NamePath)
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
		return nil, nil, fmt.Errorf("unsupported curve: %v", setup.Curve)
	}

	return plonk.Setup(ccs, srs, lagrangeSrs)
}

func TestOnlySetup(curve ecc.ID) Name {
	switch curve {
	case ecc.BLS12_381:
		return TestOnlyBLS12381
	case ecc.BN254:
		return TestOnlyBN254
	default:
		panic(fmt.Sprintf("unsupported curve: %v", curve))
	}
}

// trustedSetupBLS12381 returns trusted parameters for BLS12-381
func trustedSetupBLS12381(size uint64, setupName string) (*kzg_bls12381.SRS, error) {

	G1s, vkData, err := loadTrustedSetupBytes(setupName, size,
		bls12381.SizeOfG1AffineCompressed)
	if err != nil {
		return nil, fmt.Errorf("error loading trusted setup files: %v", err)
	}

	var srs kzg_bls12381.SRS
	srs.Pk.ReadFrom(bytes.NewReader(G1s))
	srs.Vk.ReadFrom(bytes.NewReader(vkData))

	return &srs, nil
}

// trustedSetupBN254 returns trusted parameters for BN254
func trustedSetupBN254(size uint64, setupName string) (*kzg_bn254.SRS, error) {

	G1s, vkData, err := loadTrustedSetupBytes(setupName, size,
		bn254.SizeOfG1AffineCompressed)
	if err != nil {
		return nil, fmt.Errorf("error loading trusted setup files: %v", err)
	}

	var srs kzg_bn254.SRS
	srs.Pk.ReadFrom(bytes.NewReader(G1s))
	srs.Vk.ReadFrom(bytes.NewReader(vkData))

	return &srs, nil
}

// loadTrustedSetupBytes loads the trusted setup parameters from the embedded filesystem.
func loadTrustedSetupBytes(filename string, g1Count uint64, g1CompressedSize uint64,
) (g1Bytes []byte, vkBytes []byte, err error) {

	if g1Count < 2 {
		return nil, nil, fmt.Errorf("need at least 2 G1 points")
	}

	pkPath := fmt.Sprintf("%s/pk.bin", filename)
	vkPath := fmt.Sprintf("%s/vk.bin", filename)

	g1Bytes, err = embeddedFiles.ReadFile(pkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening %s: %w", pkPath, err)
	}

	vkBytes, err = embeddedFiles.ReadFile(vkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening %s: %w", vkPath, err)
	}

	// the first 4 bytes of the pk.bin file are the size of the G1 array
	// we check if the file is large enough to hold the required number of G1 elements
	// both by checking the length of the file and by checking the first 4 bytes
	bytesNeeded := 4 + g1Count*g1CompressedSize
	declaredG1Count := uint64(binary.BigEndian.Uint32(g1Bytes[:4]))
	if uint64(len(g1Bytes)) < bytesNeeded || declaredG1Count < g1Count {
		return nil, nil, fmt.Errorf("pk.bin too small for %d elements", g1Count)
	}
	g1Bytes = g1Bytes[:bytesNeeded]
	binary.BigEndian.PutUint32(g1Bytes[:4], uint32(g1Count))

	return g1Bytes, vkBytes, nil
}
