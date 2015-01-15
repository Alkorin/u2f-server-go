package main

import "crypto/rand"
import "encoding/hex"
import "flag"
import "fmt"
import "log"
import "github.com/Alkorin/u2f-server-go/RegisterRequest"

func main() {
	// Parse args
	var appId string

	flag.StringVar(&appId, "appId", "", "applicationId")
	flag.Parse()

	if appId == "" {
		log.Fatal("Error: applicationId is required (--appId)")
	}

	// Generate random
	challenge := make([]byte, 32)
	rand.Read(challenge)

	// Generate structure and output json
	r := RegisterRequest.New(
		appId,
		challenge,
	)

	fmt.Printf("Generated challenge: %s\n", hex.EncodeToString(challenge))
	fmt.Printf("RegisterRequest: %s\n", r.Generate())
}
