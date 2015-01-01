package websafebase64

import "strings"
import "encoding/base64"

func Encode(data []byte) string {
	return strings.Trim(base64.URLEncoding.EncodeToString(data), "=")
}
