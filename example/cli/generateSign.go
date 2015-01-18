package main

import "crypto/rand"
import "encoding/hex"
import "flag"
import "fmt"
import "log"
import "github.com/Alkorin/u2f-server-go/SignRequest"

func main() {
	// Parse args
	var appId string
	var keyHandle string

	flag.StringVar(&appId, "appId", "", "applicationId")
	flag.StringVar(&keyHandle, "keyHandle", "", "keyHandle")
	flag.Parse()

	if appId == "" {
		log.Fatal("Error: applicationId is required (--appId)")
	}
	if keyHandle == "" {
		log.Fatal("Error: keyHandle is required (--keyHandle)")
	}

	// Generate random
	challenge := make([]byte, 32)
	rand.Read(challenge)

	// Generate structure and output json
	r := SignRequest.New(
		appId,
		keyHandle,
		"", // Optionnal here
		challenge,
	)

	fmt.Printf("Generated challenge: %s\n", hex.EncodeToString(challenge))
	fmt.Printf("SignRequest: %s\n", r.Generate())
}
