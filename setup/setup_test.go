package setup

import (
	"encoding/hex"
	"fmt"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func TestTrustedSetupPerpetualPowersOfTauBN254(t *testing.T) {
	const size = 5
	setup := Setups[PerpetualPowersOfTauBN254]
	srs, err := trustedSetupBN254(size, setup.NamePath)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(srs.Pk.G1) != size {
		t.Errorf("expected %d G1 elements, got %d", size, len(srs.Pk.G1))
	}
	// check srs.Pk.G1[0], srs.Vk.G2[0] are the G1, G2 bn254 generators
	_, _, g1Gen, g2Gen := bn254.Generators()
	if !srs.Pk.G1[0].Equal(&g1Gen) {
		t.Errorf("different g1 generator: %v | %v", srs.Pk.G1[0], g1Gen)
	}
	if !srs.Vk.G2[0].Equal(&g2Gen) {
		t.Errorf("different g2 generator: %v | %v", srs.Vk.G2[0], g2Gen)
	}
}

func TestTrustedSetupDuskBLS12381(t *testing.T) {
	const size = 5
	setup := Setups[DuskBLS12381]
	srs, err := trustedSetupBLS12381(size, setup.NamePath)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(srs.Pk.G1) != size {
		t.Errorf("expected %d G1 elements, got %d", size, len(srs.Pk.G1))
	}
	checkG1 := [size]bls12381.G1Affine{}
	checkG1Strings := [size]string{
		"0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
		"0xb00634601c69f919549b3a284249cee53e7be4cf96f05a8ceceec6c74a0a2bc5cb21a6b060bff4c11eb3382c0ca98325",
		"0xb74090b6c7ad1daee5dcea5a70e0e0dd774b8308fe7e0084031ee84457de0d6f665cd55d81cbb5f650b66eccf6e4cd31",
		"0x81704091e4770cdf58699eca0569d99d6d001b4191d380e8dd26feddcacafa9d2425f834fe61061af349fd18facc3744",
		"0xb3f9536dba87c1b6bf29142b58f1760ebdbea7a5a5c92c2e2a221e903937d3da6098ebf1125cc1c8de82f234ad698001",
	}

	for i, g1 := range srs.Pk.G1 {
		checkBytes, err := hex.DecodeString(checkG1Strings[i][2:])
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		err = checkG1[i].Unmarshal(checkBytes)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !g1.Equal(&checkG1[i]) {
			g1Bytes := g1.Bytes()
			g1Hex := hex.EncodeToString(g1Bytes[:])

			t.Errorf("different g1: %s | %s for G1[%d]", g1Hex, checkG1Strings[i], i)
		}
		// Modify the first three bits to make it an uncompressed X
		checkG1[i].X.SetString(zeroFirstThreeBits(checkG1Strings[i]))
		if !g1.X.Equal(&checkG1[i].X) {
			t.Errorf("different g1.X: %v | %v for G1[%d]", g1.X, checkG1[i].X, i)
		}
	}

	// check srs.Pk.G1[0], srs.Vk.G2[0] are the G1, G2 bls12-381 generators
	_, _, g1Gen, g2Gen := bls12381.Generators()
	if !srs.Pk.G1[0].Equal(&g1Gen) {
		t.Errorf("different g1 generator: %v | %v", srs.Pk.G1[0], g1Gen)
	}
	if !srs.Vk.G2[0].Equal(&g2Gen) {
		t.Errorf("different g2 generator: %v | %v", srs.Vk.G2[0], g2Gen)
	}

	checkG2 := [2]bls12381.G2Affine{}
	checkG2Strings := [2]string{
		"0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
		"0x8fd840491fe66a0cc60f45930d88a9b562136137f78260648ce6a4bf5d31849f18de090e2644780d2bf6b42e208422760fabe7238383b48bd61f25125a0d093306ef5511550312e2c1a9fb985e21ce1bf71b1fb0565c3b54836463eb1f043d48",
	}
	for i, g2 := range srs.Vk.G2 {
		checkBytes, err := hex.DecodeString(checkG2Strings[i][2:])
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		err = checkG2[i].Unmarshal(checkBytes)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !g2.Equal(&checkG2[i]) {
			g2Bytes := g2.Bytes()
			g2Hex := hex.EncodeToString(g2Bytes[:])

			t.Errorf("different g2: %s | %s for G2[%d]", g2Hex, checkG2Strings[i], i)
		}
		checkG2[i].X.SetString(checkG2Strings[i][2+96:],
			zeroFirstThreeBits(checkG2Strings[i])[2:98])
		if !g2.X.Equal(&checkG2[i].X) {
			t.Errorf("different g2.X: %v | %v for G2[%d]", g2.X, checkG2[i].X, i)
		}
	}
	if !srs.Vk.G1.Equal(&checkG1[0]) {
		t.Errorf("different Vk.G1 %v | %v", srs.Vk.G1, checkG1[0])
	}

	const size2 = 32768
	srs, err = trustedSetupBLS12381(size2, setup.NamePath)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(srs.Pk.G1) != size2 {
		t.Errorf("expected %d G1 elements, got %d", size2, len(srs.Pk.G1))
	}

	// let's check the last element
	lastG1CheckString := "0x872d03410917bae2f3536a750ad10f7b7173d89fa27026afe5c0b2e08697eed244a6798ed833826198628058e3c8b0d9"
	checkBytes, err := hex.DecodeString(lastG1CheckString[2:])
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	g1Check := bls12381.G1Affine{}
	err = g1Check.Unmarshal(checkBytes)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	g1 := srs.Pk.G1[size2-1]
	if !g1.Equal(&g1Check) {
		g1Bytes := g1.Bytes()
		g1Hex := hex.EncodeToString(g1Bytes[:])

		g1CheckBytes := g1Check.Bytes()
		g1CheckHex := hex.EncodeToString(g1CheckBytes[:])

		t.Errorf("different g1: %v | %v for G1[%d]]", g1Hex, g1CheckHex, size2-1)
	}

	for i, g2 := range srs.Vk.G2 {
		checkBytes, err := hex.DecodeString(checkG2Strings[i][2:])
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		err = checkG2[i].Unmarshal(checkBytes)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !g2.Equal(&checkG2[i]) {
			t.Errorf("different g2: %v | %v for G2[%d]", g2, checkG1[i], i)
		}
	}
	if !srs.Vk.G1.Equal(&checkG1[0]) {
		t.Errorf("different Vk.G1 %v | %v", srs.Vk.G1, checkG1[0])

	}
}

func TestTrustedSetupEethereumKzgCeremonyBLS12_381(t *testing.T) {
	const size = 5
	setup := Setups[EthereumKzgCeremonyBLS12381]
	srs, err := trustedSetupBLS12381(size, setup.NamePath)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(srs.Pk.G1) != size {
		t.Errorf("expected %d G1 elements, got %d", size, len(srs.Pk.G1))
	}
	checkG1 := [size]bls12381.G1Affine{}
	checkG1Strings := [size]string{
		"0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
		"0xabb83706b7f96c1ef21649124cd01ac58ec3cf19fbe7ba8e172b5f9e0facb354f3da4877946c24f17411cb551e0c24df",
		"0xa15cb49e7b66d0c94e46613780adcbe141adf7e2c16ec29e996a6be41c92bfc11bfee4188cbb6bdfe90ef4eb8268f1db",
		"0x8c5e0672d24677f430d729fc8e96cae3a62b1c67997e88d71600d8e1f1954ec04742d79f804345f8e60d11873d18d0d4",
		"0xb0feedf1a6c84c6470dcecf26cd95c1258c6c744eb3556ae9e864545d4d4e1c1cb9aaf52265e0df4e0c726b2e9d00045",
	}

	for i, g1 := range srs.Pk.G1 {
		checkBytes, err := hex.DecodeString(checkG1Strings[i][2:])
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		err = checkG1[i].Unmarshal(checkBytes)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !g1.Equal(&checkG1[i]) {
			t.Errorf("different g1: %v | %v for G1[%d]", g1, checkG1[i], i)
		}
		// Modify the first three bits to make it an uncompressed X
		checkG1[i].X.SetString(zeroFirstThreeBits(checkG1Strings[i]))
		if !g1.X.Equal(&checkG1[i].X) {
			t.Errorf("different g1.X: %v | %v for G1[%d]", g1.X, checkG1[i].X, i)
		}
	}

	// check srs.Pk.G1[0], srs.Vk.G2[0] are the G1, G2 bls12-381 generators
	_, _, g1Gen, g2Gen := bls12381.Generators()
	if !srs.Pk.G1[0].Equal(&g1Gen) {
		t.Errorf("different g1 generator: %v | %v", srs.Pk.G1[0], g1Gen)
	}
	if !srs.Vk.G2[0].Equal(&g2Gen) {
		t.Errorf("different g2 generator: %v | %v", srs.Vk.G2[0], g2Gen)
	}

	checkG2 := [2]bls12381.G2Affine{}
	checkG2Strings := [2]string{
		"0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
		"0xa78b94342f7d47a92f8618d0cf60cd3f8c77279ffafb2f0d71e4be074979f1b2f536007e9dcd236abaabcac3769930791224556839c0c3b5bf3f3bad9727dfc5c3326539883a6b798bef5302776ede7b939374a236e96658b269c3f4a2ea859e",
	}
	for i, g2 := range srs.Vk.G2 {
		checkBytes, err := hex.DecodeString(checkG2Strings[i][2:])
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		err = checkG2[i].Unmarshal(checkBytes)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !g2.Equal(&checkG2[i]) {
			t.Errorf("different g2: %v | %v for G2[%d]", g2, checkG1[i], i)
		}
		checkG2[i].X.SetString(checkG2Strings[i][2+96:],
			zeroFirstThreeBits(checkG2Strings[i])[2:98])
		if !g2.X.Equal(&checkG2[i].X) {
			t.Errorf("different g2.X: %v | %v for G2[%d]", g2.X, checkG2[i].X, i)
		}
	}
	if !srs.Vk.G1.Equal(&checkG1[0]) {
		t.Errorf("different Vk.G1 %v | %v", srs.Vk.G1, checkG1[0])
	}

	const size2 = 32768
	srs, err = trustedSetupBLS12381(size2, setup.NamePath)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(srs.Pk.G1) != size2 {
		t.Errorf("expected %d G1 elements, got %d", size2, len(srs.Pk.G1))
	}

	// let's check the last element
	lastG1CheckString := "0xb2cd3d87b1af48bb6f3c23d765d6ef21a7c6ca2e5e23b0c4feb20559aaf8b06f69d5a0ff7df5f90f7e3aa0225e7ddff6"
	checkBytes, err := hex.DecodeString(lastG1CheckString[2:])
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	g1Check := bls12381.G1Affine{}
	err = g1Check.Unmarshal(checkBytes)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	g1 := srs.Pk.G1[size2-1]
	if !g1.Equal(&g1Check) {
		t.Errorf("different g1: %v | %v for G1[%d]]", g1, g1Check, size2-1)
	}

	for i, g2 := range srs.Vk.G2 {
		checkBytes, err := hex.DecodeString(checkG2Strings[i][2:])
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		err = checkG2[i].Unmarshal(checkBytes)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !g2.Equal(&checkG2[i]) {
			t.Errorf("different g2: %v | %v for G2[%d]", g2, checkG1[i], i)
		}
	}
	if !srs.Vk.G1.Equal(&checkG1[0]) {
		t.Errorf("different Vk.G1 %v | %v", srs.Vk.G1, checkG1[0])

	}
}

// zeroFirstThreeBits sets the first three bits of the first byte of the given
// hexadecimal string to 0.
func zeroFirstThreeBits(hexString string) string {
	hexBytes, err := hex.DecodeString(hexString[2:]) // Remove "0x" prefix
	if err != nil {
		fmt.Println("Error decoding hexadecimal string:", err)
		return hexString
	}

	hexBytes[0] &= 0x1F
	newHexString := "0x" + hex.EncodeToString(hexBytes)

	return newHexString
}
