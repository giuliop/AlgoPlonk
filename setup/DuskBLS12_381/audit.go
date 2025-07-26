package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
)

const (
	// The maximum number of tau powers computed in the Dusk Trusted Setup
	FILE_MAX_TAU_POWERS = 1 << 21

	// The size of G1 affine points in compressed form
	G1_AFFINE_COMPRESSED_SIZE = 48

	// The size of G2 affine points in compressed form
	G2_AFFINE_COMPRESSED_SIZE = 96

	// Hash size at the beginning of the response file
	HASH_SIZE = 64
)

type Point struct {
	Data []byte
	Type string
}

func extractG1Points(responseBytes []byte) []Point {
	var g1Points []Point
	offset := HASH_SIZE // Skip the 64-byte hash at the beginning

	// Extract powers of tau in G1 (τ^0, τ^1, τ^2, ..., τ^DUSK_MAX_TAU_POWERS)
	for i := 0; i <= FILE_MAX_TAU_POWERS; i++ {
		if offset+G1_AFFINE_COMPRESSED_SIZE > len(responseBytes) {
			log.Printf("Warning: Not enough data for G1 point %d", i)
			break
		}

		pointData := make([]byte, G1_AFFINE_COMPRESSED_SIZE)
		copy(pointData, responseBytes[offset:offset+G1_AFFINE_COMPRESSED_SIZE])

		g1Points = append(g1Points, Point{
			Data: pointData,
			Type: fmt.Sprintf("G1_tau_%d", i),
		})

		offset += G1_AFFINE_COMPRESSED_SIZE
	}

	return g1Points
}

func extractG2Points(responseBytes []byte) []Point {
	var g2Points []Point

	// Calculate offset for G2 generator
	// G2 generator position: ((FILE_MAX_TAU_POWERS << 1) - 1) * G1_AFFINE_COMPRESSED_SIZE + 64
	g2Offset := ((FILE_MAX_TAU_POWERS<<1)-1)*G1_AFFINE_COMPRESSED_SIZE + HASH_SIZE

	// Extract G2 generator
	if g2Offset+G2_AFFINE_COMPRESSED_SIZE <= len(responseBytes) {
		g2Data := make([]byte, G2_AFFINE_COMPRESSED_SIZE)
		copy(g2Data, responseBytes[g2Offset:g2Offset+G2_AFFINE_COMPRESSED_SIZE])

		g2Points = append(g2Points, Point{
			Data: g2Data,
			Type: "G2_generator",
		})
	} else {
		log.Println("Warning: Not enough data for G2 generator")
	}

	// Extract tau * G2 generator
	tauG2Offset := g2Offset + G2_AFFINE_COMPRESSED_SIZE
	if tauG2Offset+G2_AFFINE_COMPRESSED_SIZE <= len(responseBytes) {
		tauG2Data := make([]byte, G2_AFFINE_COMPRESSED_SIZE)
		copy(tauG2Data, responseBytes[tauG2Offset:tauG2Offset+G2_AFFINE_COMPRESSED_SIZE])

		g2Points = append(g2Points, Point{
			Data: tauG2Data,
			Type: "G2_tau_generator",
		})
	} else {
		log.Println("Warning: Not enough data for tau * G2 generator")
	}

	return g2Points
}

// run the audit
func main() {
	// Open the transcript.json file
	_, err := os.Stat("response")
	if err != nil {
		log.Fatalf("Error checking existance of response: %v\n"+
			"Refer to doc.go for instructions on how to download the file.", err)
		return
	}
	file, err := os.Open("response")
	if err != nil {
		log.Fatal("Error opening response:", err)
		return
	}
	defer file.Close()

	responseBytes, err := os.ReadFile("response")
	if err != nil {
		log.Fatalf("error reading response file: %v", err)
	}

	g1Points := extractG1Points(responseBytes)

	// Create the pk.audit file
	file, err = os.Create("pk.audit")
	if err != nil {
		log.Fatalf("error creating pk.audit file: %v", err)
	}
	defer file.Close()

	// Write the length of G1Powers as a 4-byte big-endian integer
	length := uint32(len(g1Points))
	err = binary.Write(file, binary.BigEndian, length)
	if err != nil {
		log.Fatalf("error writing length to file: %v", err)
	}

	// Convert and write each G1Power
	for _, g1Power := range g1Points {
		bytes := g1Power.Data

		if err != nil {
			log.Fatalf("error decoding hex string: %v", err)
		}

		// Ensure bytes slice is 48 bytes long
		if len(bytes) != 48 {
			log.Fatalf("decoded hex is not 48 bytes long")
		}

		// Write the 48-byte sequence to the file
		_, err = file.Write(bytes)
		if err != nil {
			log.Fatalf("error writing G1Power to file: %v", err)
		}
	}

	// Create the vk.audit file
	file, err = os.Create("vk.audit")
	if err != nil {
		log.Fatalf("error creating vk.audit file: %v", err)
	}
	defer file.Close()

	g2Points := extractG2Points(responseBytes)

	// Convert and write the first two G2Powers
	for _, g2Power := range g2Points {
		bytes := g2Power.Data

		// Ensure bytes slice is 96 bytes long
		if len(bytes) != 96 {
			log.Fatalf("decoded hex is not 96 bytes long")
		}

		// Write the 96-byte sequence to the file
		_, err = file.Write(bytes)
		if err != nil {
			log.Fatalf("error writing G2Power to file: %v", err)
		}
	}
	// Convert and write the first G1Power
	bytes := g1Points[0].Data

	_, err = file.Write(bytes)
	if err != nil {
		log.Fatalf("error writing G1Power to file: %v", err)
	}

	// check the files match
	pk, err := os.ReadFile("pk.bin")
	if err != nil {
		log.Fatalf("error reading pk.bin: %v", err)
	}
	pkAudit, err := os.ReadFile("pk.audit")
	if err != nil {
		log.Fatalf("error reading pk.audit: %v", err)
	}
	if string(pk) != string(pkAudit) {
		log.Fatalf("pk.bin and pk.audit files do not match")
	}
	vk, err := os.ReadFile("vk.bin")
	if err != nil {
		log.Fatalf("error reading vk.bin: %v", err)
	}
	vkAudit, err := os.ReadFile("vk.audit")
	if err != nil {
		log.Fatalf("error reading vk.audit: %v", err)
	}
	if string(vk) != string(vkAudit) {
		log.Fatalf("vk.bin and vk.audit files do not match")
	}
	fmt.Println("Audit successful")
}
