package websafebase64

import "strings"
import "encoding/base64"

// Encode data using websafe-base64 without '=' padding
func Encode(data []byte) string {
	return strings.Trim(base64.URLEncoding.EncodeToString(data), "=")
}

// Decode websafe-base64 string without '=' padding
func Decode(data string) ([]byte, error) {

	// Websafe base64 doesn't have padding, append it (len should be %4)
	if pad := 4 - len(data)%4; pad != 4 {
		data += strings.Repeat("=", pad)
	}

	return base64.URLEncoding.DecodeString(data)
}
