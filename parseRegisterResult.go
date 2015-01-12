package main

import "encoding/hex"
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

	r := RegisterRequest.New(appId, challenge)
	registerResonse, err := r.ValidateRegisterResponse(bytes)
	if err != nil {
		fmt.Println("KO : " + err.Error())
	} else {
		fmt.Printf("Success\n")
		fmt.Printf("KeyHandle: %s\n", registerResonse.KeyHandle)
		fmt.Printf("PublicKey:\n%s\n", registerResonse.UserPublicKey)
	}
}
