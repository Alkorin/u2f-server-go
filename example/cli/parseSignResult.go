package main

import "encoding/hex"
import "encoding/json"
import "flag"
import "fmt"
import "github.com/Alkorin/u2f-server-go/SignRequest"
import "io/ioutil"
import "log"
import "os"

func main() {
	// Parse args
	var appId string
	var challengeHex string
	var publicKey string

	flag.StringVar(&appId, "appId", "", "applicationId")
	flag.StringVar(&challengeHex, "challenge", "", "challenge")
	flag.StringVar(&publicKey, "publicKey", "", "publicKey")
	flag.Parse()

	if appId == "" {
		log.Fatal("Error: applicationId is required (--appId)")
	}
	if challengeHex == "" {
		log.Fatal("Error: challenge is required (--challenge)")
	}
	challenge, _ := hex.DecodeString(challengeHex)
	if publicKey == "" {
		log.Fatal("Error: publicKey is required (--publicKey)")
	}

	bytes, _ := ioutil.ReadAll(os.Stdin)

	if len(bytes) == 0 {
		log.Fatal("Error: empty stdin")
	}

	// Decode JSON input
	var signResponse SignRequest.SignResponse
	err := json.Unmarshal(bytes, &signResponse)
	if err != nil {
		log.Fatal("Unable to parse JSON : " + err.Error())
	}

	s := SignRequest.New(appId, "", publicKey, challenge)
	result, err := s.ValidateSignResponse(signResponse)
	if err != nil {
		fmt.Println("KO : " + err.Error())
	} else {
		fmt.Println("Success")
		fmt.Printf("Counter: %d\n", result.Counter)
	}
}
