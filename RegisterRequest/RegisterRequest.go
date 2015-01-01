package RegisterRequest

import "encoding/json"
import "github.com/Alkorin/u2f-server-go/websafebase64"

type RegisterRequest struct {
	appId     string
	challenge []byte
}

func New(appId string, challenge []byte) RegisterRequest {

	r := RegisterRequest{
		appId:     appId,
		challenge: challenge,
	}

	return r
}

// Return RegisterRequest as a JSON []byte to send to an U2F key
func (r *RegisterRequest) Generate() []byte {
	json, _ := json.Marshal(struct {
		Version   string `json:"version"`
		AppId     string `json:"appId"`
		Challenge string `json:"challenge"`
	}{
		"U2F_V2",
		r.appId,
		websafebase64.Encode(r.challenge),
	})
	return json
}
