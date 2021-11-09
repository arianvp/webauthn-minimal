package webauthn

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
)

type AuthenticatorFlags byte

const (
	FlagUserPresent  AuthenticatorFlags = 1 << iota // FlagUserPresent Bit 00000001 in the byte sequence. Tells us if user is present
	_                                               // Reserved
	FlagUserVerified                                // FlagUserVerified Bit 00000100 in the byte sequence. Tells us if user is verified by the authenticator using a biometric or PIN
)

type AuthenticatorData struct {
	RPIDHash [32]byte
	Flags    AuthenticatorFlags
	Count    uint32
	// ignore other fields
}

type AuthenticatorResponse struct {
	ClientDataJSON    []byte `json:"clientDataJSON"`
	AuthenticatorData []byte `json:"authenticatorData"` // getAuthenticatorData()
}

type COSEAlgorithmIdentifier int32

const (
	ES256 COSEAlgorithmIdentifier = -7
	EdDSA COSEAlgorithmIdentifier = -8
	ES384 COSEAlgorithmIdentifier = -35
	ES512 COSEAlgorithmIdentifier = -36
	PS256 COSEAlgorithmIdentifier = -37
	RS256 COSEAlgorithmIdentifier = -257
)

type AuthenticatorAttestationResponse struct {
	AuthenticatorResponse
	Transports         []string                `json:"transports"`         // getTransports()
	PublicKey          []byte                  `json:"publicKey"`          // getPublicKey()
	PublicKeyAlgorithm COSEAlgorithmIdentifier `json:"publicKeyAlgorithm"` // getPublicKeyAlgorithm()
}

type ClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

type AuthenticatorAssertionResponse struct {
	AuthenticatorResponse
	Signature  []byte `json:"signature"`
	UserHandle []byte `json:"userHandle"`
}

type CreatePublicKeyCredential struct {
	Type     string                           `json:"type"`
	Id       string                           `json:"id"`
	RawId    []byte                           `json:"rawId"`
	Response AuthenticatorAttestationResponse `json:"response"`
}

type GetPublicKeyCredential struct {
	Type     string                         `json:"type"`
	Id       string                         `json:"id"`
	RawId    []byte                         `json:"rawId"`
	Response AuthenticatorAssertionResponse `json:"response"`
}

type PublicKeyCredentialDescriptor struct {
	Type       string
	Id         string
	Transports []string
}

func (r *AuthenticatorAttestationResponse) ParsePublicKey() (crypto.PublicKey, error) {
	return x509.ParsePKIXPublicKey(r.PublicKey)
}

// registration: steps 6 to 14
// assertion: steps 10 to 16
func (r *AuthenticatorResponse) Verify(typ, challenge, rpID, origin string, verifyUser bool) error {
	// 6 / 10
	var clientData ClientData
	if err := json.Unmarshal(r.ClientDataJSON, &clientData); err != nil {
		return err
	}
	// 7 / 11
	if clientData.Type != typ {
		return errors.New("type mismatch")
	}
	// 8 / 12
	if clientData.Challenge != challenge {
		return errors.New("challenge mismatch")
	}
	// 9 / 13
	if clientData.Origin != origin {
		return errors.New("origin mismatch")
	}
	var authentiatorData AuthenticatorData
	if err := binary.Read(bytes.NewReader(r.AuthenticatorData), binary.BigEndian, &authentiatorData); err != nil {
		return err
	}
	// 12 / 14
	if authentiatorData.RPIDHash != sha256.Sum256([]byte(rpID)) {
		return errors.New("rpID hash mismatch")
	}
	// 13 / 15
	if authentiatorData.Flags&FlagUserPresent == 0 {
		return errors.New("user not present")
	}
	// 14 / 16
	if verifyUser && authentiatorData.Flags&FlagUserVerified == 0 {
		return errors.New("user not verified")
	}
	return nil
}

func (attestation *AuthenticatorAttestationResponse) Verify(challenge, rpID, origin string, verifyUser bool, pubKeyCredParams []COSEAlgorithmIdentifier) error {
	// steps 6 to 14
	if err := attestation.AuthenticatorResponse.Verify("webauthn.create", challenge, rpID, origin, verifyUser); err != nil {
		return err
	}
	// 15. Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
	found := false
	for _, v := range pubKeyCredParams {
		if found = v == attestation.PublicKeyAlgorithm; found {
			break
		}
	}
	if !found {
		return errors.New("publicKeyAlgorithm was not one of pubKeyCredParams")
	}
	return nil
}

// steps 10 to 21
func (response *AuthenticatorAssertionResponse) Verify(challenge, rpID, origin string, verifyUser bool, attestationResponse *AuthenticatorAttestationResponse) error {
	// steps 10 to 16
	if err := response.AuthenticatorResponse.Verify("webauthn.get", challenge, rpID, origin, verifyUser); err != nil {
		return err
	}
	// 17. WONTFIX: Extensions
	publicKey, err := attestationResponse.ParsePublicKey()
	if err != nil {
		return err
	}
	// 18. Let hash be the result of computing a hash over the cData using SHA-256.
	hash := sha256.Sum256(response.ClientDataJSON)
	// 19. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
	signed := append(response.AuthenticatorData, hash[:]...)
	if err := checkSignature(attestationResponse.PublicKeyAlgorithm, signed, response.Signature, publicKey); err != nil {
		return err
	}
	// 20. TODO: Check storedSignCount
	// 21. If all the above steps are successful, continue with the authentication ceremony as appropriate
	return nil
}
