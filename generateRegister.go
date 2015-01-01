package main

import "crypto/rand"
import "encoding/json"
import "flag"
import "log"
import "os"
import "github.com/Alkorin/u2f-server-go/websafebase64"

type Register struct {
	Version   string `json:"version"`
	AppId     string `json:"appId"`
	Challenge string `json:"challenge"`
}

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
	json, _ := json.Marshal(Register{
		Version:   "U2F_V2",
		AppId:     appId,
		Challenge: websafebase64.Encode(challenge),
	})

	os.Stdout.Write(json)
}
