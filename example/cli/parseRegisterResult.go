package main

import "encoding/hex"
import "encoding/json"
import "flag"
import "fmt"
import "github.com/Alkorin/u2f-server-go/RegisterRequest"
import "io/ioutil"
import "log"
import "os"

func main() {
	// Parse args
	var appId string
	var challengeHex string

	flag.StringVar(&appId, "appId", "", "applicationId")
	flag.StringVar(&challengeHex, "challenge", "", "challenge")
	flag.Parse()

	if appId == "" {
		log.Fatal("Error: applicationId is required (--appId)")
	}
	if challengeHex == "" {
		log.Fatal("Error: challenge is required (--challenge)")
	}
	challenge, _ := hex.DecodeString(challengeHex)

	bytes, _ := ioutil.ReadAll(os.Stdin)

	if len(bytes) == 0 {
		log.Fatal("Error: empty stdin")
	}

	// Decode JSON input
	var registerResponse RegisterRequest.RegisterResponse
	err := json.Unmarshal(bytes, &registerResponse)
	if err != nil {
		log.Fatal("Unable to parse JSON : " + err.Error())
	}

	r := RegisterRequest.New(appId, challenge)
	registerResonse, err := r.ValidateRegisterResponse(registerResponse)
	if err != nil {
		fmt.Println("KO : " + err.Error())
	} else {
		fmt.Printf("Success\n")
		fmt.Printf("KeyHandle: %s\n", registerResonse.KeyHandle)
		fmt.Printf("PublicKey:\n%s\n", registerResonse.UserPublicKey)
	}
}
