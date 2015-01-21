package main

import "encoding/hex"
import "encoding/json"
import "flag"
import "fmt"
import "io/ioutil"
import "net/http"
import "net/http/cgi"
import "github.com/Alkorin/u2f-server-go/SignRequest"

func main() {
	var daemon bool

	// Parse args
	flag.BoolVar(&daemon, "daemon", false, "Daemon")
	flag.Parse()

	// Handle queries
	http.HandleFunc("/", authenticate)
	if daemon {
		// Listen HTTP
		fmt.Println("Mode daemon")
		http.ListenAndServe(":8080", nil)
	} else {
		// Answer as CGI
		cgi.Serve(nil)
	}
}

func authenticate(w http.ResponseWriter, r *http.Request) {

	// Load Body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse Body
	params := new(struct {
		ApplicationId string
		ChallengeHex  string `json:"challenge"`
		PublicKey     string
		SignResponse  SignRequest.SignResponse
	})
	err = json.Unmarshal(body, &params)
	if err != nil {
		http.Error(w, "Unable to parse JSON : "+err.Error(), http.StatusBadRequest)
		return
	}

	// Check params
	if params.ApplicationId == "" {
		http.Error(w, "Missing applicationId", http.StatusBadRequest)
		return
	}
	if params.ChallengeHex == "" {
		http.Error(w, "Missing challenge", http.StatusBadRequest)
		return
	}
	challenge, err := hex.DecodeString(params.ChallengeHex)
	if err != nil {
		http.Error(w, "Invalid challenge", http.StatusBadRequest)
		return
	}

	signRequest := SignRequest.New(params.ApplicationId, "", params.PublicKey, challenge)
	response, err := signRequest.ValidateSignResponse(params.SignResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	output, err := json.Marshal(struct {
		ClientData string `json:"clientData"`
		Counter    uint32 `json:"signatures"`
	}{response.ClientDataJSON, response.Counter})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(output)
}
