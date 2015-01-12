package RegisterRequest

import "crypto/x509"
import "crypto/sha256"
import "encoding/binary"
import "encoding/hex"
import "encoding/json"
import "encoding/pem"
import "errors"
import "github.com/Alkorin/u2f-server-go/websafebase64"

type RegisterRequest struct {
	appId     string
	challenge []byte
}

type RegisterResponseSuccess struct {
	ClientDataJson string
	KeyHandle      string
	UserPublicKey  string
	Certificate    *x509.Certificate
}

type RegistrationData struct {
	UserPublicKey []byte
	KeyHandle     []byte
	Certificate   *x509.Certificate
	Signature     []byte
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

// Validate a RegisterResponse against this RegisterRequest
func (r *RegisterRequest) ValidateRegisterResponse(data []byte) (*RegisterResponseSuccess, error) {

	// Parse JSON data
	registerResponse := new(struct {
		RegistrationData string `json:"registrationData"`
		ClientData       string `json:"clientData"`
	})
	err := json.Unmarshal(data, &registerResponse)
	if err != nil {
		return nil, errors.New("Unable to parse JSON : " + err.Error())
	}

	clientDataJson, err := websafebase64.Decode(registerResponse.ClientData)
	if err != nil {
		return nil, errors.New("Unable to decode ClientData : " + err.Error())
	}

	// Verify Challenge
	clientData := new(struct {
		Challenge string `json:"challenge"`
	})
	err = json.Unmarshal(clientDataJson, clientData)
	if err != nil {
		return nil, errors.New("Unable to decode ClientDataJson : " + err.Error())
	}
	if clientData.Challenge != websafebase64.Encode(r.challenge) {
		return nil, errors.New("Invalid Challenge")
	}

	// Extract registration fields
	registrationData, err := parseRegistrationData(registerResponse.RegistrationData)
	if err != nil {
		return nil, errors.New("Unable to decode registrationData : " + err.Error())
	}

	// Verify Signature
	appId256 := sha256.Sum256([]byte(r.appId))
	clientData256 := sha256.Sum256(clientDataJson)
	dataToSign := []byte{0}
	dataToSign = append(dataToSign, appId256[:]...)
	dataToSign = append(dataToSign, clientData256[:]...)
	dataToSign = append(dataToSign, registrationData.KeyHandle...)
	dataToSign = append(dataToSign, registrationData.UserPublicKey...)

	err = registrationData.Certificate.CheckSignature(
		x509.ECDSAWithSHA256,
		dataToSign,
		registrationData.Signature)
	if err != nil {
		return nil, errors.New("Invalid signature")
	}

	// Compute PEM key
	userPublicKeyPem, err := getPemFromPublicKey(registrationData.UserPublicKey)
	if err != nil {
		return nil, err
	}

	return &RegisterResponseSuccess{
		ClientDataJson: string(clientDataJson),
		UserPublicKey:  userPublicKeyPem,
		KeyHandle:      websafebase64.Encode(registrationData.KeyHandle),
	}, nil
}

// http://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-u2f-raw-message-formats-ps-20141009.html#registration-response-message-success
func parseRegistrationData(s string) (*RegistrationData, error) {

	data, err := websafebase64.Decode(s)
	if err != nil {
		return nil, err
	}

	// A reserved byte [1 byte], which for legacy reasons has the value 0x05.
	reservedByte, data := data[0], data[1:]
	if reservedByte != '\x05' {
		return nil, errors.New("Invalid reservedByte")
	}

	// A user public key [65 bytes]. This is the (uncompressed) x,y-representation of a curve point on the P-256 NIST elliptic curve.
	userPublicKey, data := data[:65], data[65:]

	// A key handle length byte [1 byte], which specifies the length of the key handle (see below).
	keyHandleLength, data := data[0], data[1:]

	// A key handle [length specified in previous field].
	keyHandle, data := data[0:keyHandleLength], data[keyHandleLength:]

	// An attestation certificate [variable length]. This is a certificate in X.509 DER format.
	DERLength, err := getDERLength(data)
	if err != nil {
		return nil, err
	}
	DERCertificate, data := data[0:DERLength], data[DERLength:]
	certificate, err := x509.ParseCertificate(DERCertificate)
	if err != nil {
		return nil, err
	}

	// The remaining bytes in the message are a signature. This is a ECDSA (see [ECDSA-ANSI] in bibliography) signature (on P-256)
	signature := data

	return &RegistrationData{
		UserPublicKey: userPublicKey,
		KeyHandle:     keyHandle,
		Certificate:   certificate,
		Signature:     signature,
	}, nil
}

func getPemFromPublicKey(b []byte) (string, error) {

	// DER Header for an ECDSA public key
	derHeaderHex :=
		"3059" + // Sequence 89 bytes
			"3013" + // Sequence 19 bytes
			"0607" + // Object Identifier 7 bytes
			"2a8648ce3d0201" + // 1.2.840.10045.2.1 (ecPublicKey)
			"0608" + // Object Identifier 8 bytes
			"2a8648ce3d030107" + // 1.2.840.10045.3.1.7 (P-256)
			"034200" // Bit String 520 bytes

		// Construct DER
	derHeader, _ := hex.DecodeString(derHeaderHex)
	der := append(derHeader, b...)

	// Verify key
	_, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "INVALID", err
	}

	// Generate PEM
	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	return string(pem), nil
}

func getDERLength(data []byte) (uint, error) {

	firstByte := data[0]
	if firstByte != '\x30' {
		return 0, errors.New("Invalid DER certificate")
	}

	if firstLengthByte := data[1]; firstLengthByte < 0x81 {
		return uint(firstLengthByte) + 2, nil
	} else if firstLengthByte == 0x81 {
		return uint(data[2]) + 3, nil
	} else if firstLengthByte == 0x82 {
		return uint(binary.BigEndian.Uint16(data[2:4])) + 4, nil
	} else {
		return 0, errors.New("Invalid DER length")
	}
}
