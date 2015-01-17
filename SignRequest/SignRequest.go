package SignRequest

import "encoding/json"
import "github.com/Alkorin/u2f-server-go/websafebase64"

type SignRequest struct {
	appId     string
	keyHandle string
	publicKey string
	challenge []byte
}

func New(appId string, keyHandle string, publicKey string, challenge []byte) SignRequest {

	s := SignRequest{
		appId:     appId,
		keyHandle: keyHandle,
		publicKey: publicKey,
		challenge: challenge,
	}
	return s
}

// Return SignRequest as a JSON []byte to send to an U2F key
func (r *SignRequest) Generate() []byte {

	json, _ := json.Marshal(struct {
		Version   string `json:"version"`
		AppId     string `json:"appId"`
		KeyHandle string `json:"keyHandle"`
		Challenge string `json:"challenge"`
	}{
		"U2F_V2",
		r.appId,
		r.keyHandle,
		websafebase64.Encode(r.challenge),
	})
	return json
}
