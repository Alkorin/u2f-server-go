package SignRequest

import "crypto/elliptic"
import "crypto/ecdsa"
import "crypto/sha256"
import "errors"
import "encoding/asn1"
import "encoding/binary"
import "encoding/json"
import "encoding/pem"
import "github.com/Alkorin/u2f-server-go/websafebase64"
import "math/big"

type SignRequest struct {
	appId     string
	keyHandle string
	publicKey string
	challenge []byte
}

type SignResponse struct {
	SignatureData string
	ClientData    string
}

type SignSuccess struct {
	ClientDataJson string
	Counter        uint32
	UserPresence   byte
}

type SignatureData struct {
	userPresence byte
	counter      []byte
	signature    []byte
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
func (s *SignRequest) Generate() []byte {

	json, _ := json.Marshal(struct {
		Version   string `json:"version"`
		AppId     string `json:"appId"`
		KeyHandle string `json:"keyHandle"`
		Challenge string `json:"challenge"`
	}{
		"U2F_V2",
		s.appId,
		s.keyHandle,
		websafebase64.Encode(s.challenge),
	})
	return json
}

// Validate a SignResponse against this SignRequest
func (s *SignRequest) ValidateSignResponse(signResponse SignResponse) (*SignSuccess, error) {

	clientDataJson, err := websafebase64.Decode(signResponse.ClientData)
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
	if clientData.Challenge != websafebase64.Encode(s.challenge) {
		return nil, errors.New("Invalid Challenge")
	}

	// Extract registration fields
	signatureData, err := parseSignatureData(signResponse.SignatureData)
	if err != nil {
		return nil, errors.New("Unable to decode signatureData : " + err.Error())
	}

	// Verify signature
	appId256 := sha256.Sum256([]byte(s.appId))
	clientData256 := sha256.Sum256(clientDataJson)
	dataToSign := []byte{}
	dataToSign = append(dataToSign, appId256[:]...)
	dataToSign = append(dataToSign, signatureData.userPresence)
	dataToSign = append(dataToSign, signatureData.counter...)
	dataToSign = append(dataToSign, clientData256[:]...)

	result, err := checkSignature(sha256.Sum256(dataToSign), s.publicKey, signatureData.signature)
	if err != nil {
		return nil, errors.New("Unable to parse signature : " + err.Error())
	}
	if result == false {
		return nil, errors.New("Invalid signature")
	}

	return &SignSuccess{
		Counter:        binary.BigEndian.Uint32(signatureData.counter),
		ClientDataJson: string(clientDataJson),
		UserPresence:   signatureData.userPresence,
	}, nil
}

// http://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-u2f-raw-message-formats-ps-20141009.html#authentication-response-message-success
func parseSignatureData(s string) (*SignatureData, error) {

	data, err := websafebase64.Decode(s)
	if err != nil {
		return nil, err
	}

	// A user presence byte [1 byte]. Bit 0 is set to 1, which means that user presence was verified
	userPresence, data := data[0], data[1:]
	if userPresence != '\x01' {
		return nil, errors.New("Invalid user presence")
	}

	// A counter [4 bytes]. This is the big-endian representation of a counter value that the U2F token increments every time it performs an authentication operation.
	counter, data := data[0:4], data[4:]

	// A signature. This is a ECDSA signature (on P-256).
	signature := data

	return &SignatureData{
		userPresence: userPresence,
		counter:      counter,
		signature:    signature,
	}, nil
}

func checkSignature(data [32]byte, publicKeyPem string, signature []byte) (bool, error) {

	// Parse publicKey
	publicKey, err := ECDSAPublicKeyFromPem(publicKeyPem)
	if err != nil {
		return false, err
	}

	// Parse signature
	var signatureData = new(struct {
		R, S *big.Int
	})
	_, err = asn1.Unmarshal(signature, signatureData)
	if err != nil {
		return false, err
	}

	// Valid Signature
	return ecdsa.Verify(publicKey, data[:], signatureData.R, signatureData.S), nil
}

func ECDSAPublicKeyFromPem(PEMString string) (*ecdsa.PublicKey, error) {

	// Decode PEM
	publicKeyPem, _ := pem.Decode([]byte(PEMString))
	if publicKeyPem == nil || publicKeyPem.Type != "PUBLIC KEY" {
		return nil, errors.New("Invalid publicKey")
	}

	// Decode ASN.1 data
	var publicKey = new(struct {
		Algo struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		BitString asn1.BitString
	})
	_, err := asn1.Unmarshal(publicKeyPem.Bytes, publicKey)
	if err != nil {
		return nil, err
	}

	// Decode Point
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey.BitString.RightAlign())
	if x == nil {
		return nil, errors.New("Failed to unmarshal elliptic curve point")
	}

	// Return public key
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}
