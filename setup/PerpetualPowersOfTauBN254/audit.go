package main

import (
	"fmt"
	"log"
	"os"

	gp "github.com/mdehoog/gnark-ptau"
)

func main() {
	// Open the .ptau file
	filename := "powersOfTau28_hez_final_18.ptau"
	_, err := os.Stat(filename)
	if err != nil {
		log.Fatalf("Error checking existance of %s: %v\n"+
			"Refer to doc.go for instructions on how to download the file.",
			filename, err)
		return
	}
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("error opening %s: %v", filename, err)
	}

	srs, err := gp.ToSRS(file)
	if err != nil {
		log.Fatalf("error converting to SRS: %v", err)
	}

	// Create the pk.audit file
	pkFile, err := os.Create("pk.audit")
	if err != nil {
		log.Fatalf("error creating pk.audit file: %v", err)
	}
	defer file.Close()

	// Write pk to the file
	srs.Pk.WriteTo(pkFile)

	// Create the vk.audit file
	vkFile, err := os.Create("vk.audit")
	if err != nil {
		log.Fatalf("error creating vk.audit file: %v", err)
	}
	defer file.Close()

	// Write vk to the file
	srs.Vk.WriteTo(vkFile)

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
