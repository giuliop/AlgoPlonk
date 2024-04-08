package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// Define a struct to match the JSON structure of transcript.json
type Transcript struct {
	NumG1Powers int `json:"numG1Powers"`
	NumG2Powers int `json:"numG2Powers"`
	PowersOfTau struct {
		G1Powers []string `json:"G1Powers"`
		G2Powers []string `json:"G2Powers"`
	} `json:"powersOfTau"`
}

type TranscriptFile struct {
	Transcripts []Transcript `json:"transcripts"`
}

// run the audit
func main() {
	// Open the transcript.json file
	_, err := os.Stat("transcript.json")
	if err != nil {
		log.Fatalf("Error checking existance of transcript.json: %v\n"+
			"Refer to doc.go for instructions on how to download the file.", err)
		return
	}
	file, err := os.Open("transcript.json")
	if err != nil {
		log.Fatal("Error opening transcript.json:", err)
		return
	}
	defer file.Close()

	// Decode the JSON file into the struct
	var transcriptFile TranscriptFile
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&transcriptFile)
	if err != nil {
		log.Fatalf("Error decoding JSON: %v\nMaybe you downloaded the html page "+
			"instead of the file?\n", err)
		return
	}

	// Filter for the transcript with "numG1Powers": 32768
	var tsc Transcript
	for _, transcript := range transcriptFile.Transcripts {
		if transcript.NumG1Powers == 32768 {
			tsc = transcript
			break
		}
	}
	if tsc.NumG1Powers == 0 {
		log.Fatal("Desired transcript not found")
		return
	}

	// Create the pk.audit file
	file, err = os.Create("pk.audit")
	if err != nil {
		log.Fatalf("error creating pk.audit file: %v", err)
	}
	defer file.Close()

	// Write the length of G1Powers as a 4-byte big-endian integer
	length := uint32(len(tsc.PowersOfTau.G1Powers))
	err = binary.Write(file, binary.BigEndian, length)
	if err != nil {
		log.Fatalf("error writing length to file: %v", err)
	}

	// Convert and write each G1Power
	for _, g1Power := range tsc.PowersOfTau.G1Powers {
		// Remove the "0x" prefix and decode the hex string
		bytes, err := hex.DecodeString(g1Power[2:])
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

	// Convert and write the first two G2Powers
	for _, g2Power := range tsc.PowersOfTau.G2Powers[:2] {
		// Remove the "0x" prefix and decode the hex string
		bytes, err := hex.DecodeString(g2Power[2:])
		if err != nil {
			log.Fatalf("error decoding hex string: %v", err)
		}

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
	bytes, _ := hex.DecodeString(tsc.PowersOfTau.G1Powers[0][2:])
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
