package webauthn

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

type AuthenticatorFlags byte

const (
	FlagUserPresent  AuthenticatorFlags = 1 << iota // FlagUserPresent Bit 00000001 in the byte sequence. Tells us if user is present
	_                                               // Reserved
	FlagUserVerified                                // FlagUserVerified Bit 00000100 in the byte sequence. Tells us if user is verified by the authenticator using a biometric or PIN
	FlagBackupEligibility
	FlagBackupState
	_
	FlagAttestedCredentialData
	FlagExtensionData
)

type AuthenticatorData struct {
	RPIDHash [32]byte
	Flags    AuthenticatorFlags
	Count    uint32
	// ignore other fields
}

func ParseAndVerifyAuthenticatorData(r io.Reader, rpID string, flags AuthenticatorFlags) (*AuthenticatorData, error) {
	authData := new(AuthenticatorData)
	if err := binary.Read(r, binary.BigEndian, authData); err != nil {
		return nil, err
	}
	// 12 / 14
	if authData.RPIDHash != sha256.Sum256([]byte(rpID)) {
		return nil, errors.New("rpID hash mismatch")
	}

	// 13 / 15 |  14 / 16
	if authData.Flags&flags == 0 {
		return nil, errors.New("flags did not match")
	}
	return authData, nil
}

type ClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}

type AuthenticatorResponse struct {
	ClientDataJSON []byte `json:"clientDataJSON"`
	// Though this field is not present in AuthenticatorAttestationResponse
	// usually as it's part of the attestationObject, we still include it here
	// as the client might call the
	// AuthenticatorAttestationResponse.prototype.getAuthenticatorData()
	// function to extract the authenticator data directly. This is useful in
	// cases where you are not interested in attestation like when registering a
	// Passkey.
	AuthenticatorData []byte `json:"authenticatorData"` // getAuthenticatorData()
}

// registration: steps 6 to 14
// assertion: steps 10 to 16
func (r *AuthenticatorResponse) Verify(typ, challenge, rpID, origin string, flags AuthenticatorFlags) error {
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

	_, err := ParseAndVerifyAuthenticatorData(bytes.NewReader(r.AuthenticatorData), rpID, FlagUserPresent|FlagAttestedCredentialData|flags)
	if err != nil {
		return err
	}

	return nil
}

type AuthenticatorAttestationResponse struct {
	AuthenticatorResponse
	Transports         []string                `json:"transports"`         // getTransports()
	PublicKey          []byte                  `json:"publicKey"`          // getPublicKey()
	PublicKeyAlgorithm COSEAlgorithmIdentifier `json:"publicKeyAlgorithm"` // getPublicKeyAlgorithm()
}

func (r *AuthenticatorAttestationResponse) ParsePublicKey() (crypto.PublicKey, error) {
	return x509.ParsePKIXPublicKey(r.PublicKey)
}

func (r *AuthenticatorAttestationResponse) Verify(challenge, rpID, origin string, flags AuthenticatorFlags, pubKeyCredParams []COSEAlgorithmIdentifier) error {
	// steps 6 to 14
	if err := r.AuthenticatorResponse.Verify("webauthn.create", challenge, rpID, origin, FlagUserPresent|flags); err != nil {
		return err
	}
	// 15. Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
	found := false
	for _, v := range pubKeyCredParams {
		if found = v == r.PublicKeyAlgorithm; found {
			break
		}
	}
	if !found {
		return errors.New("publicKeyAlgorithm was not one of pubKeyCredParams")
	}
	return nil
}

type AuthenticatorAssertionResponse struct {
	AuthenticatorResponse
	// Signature is signed over append(sha256())
	Signature  []byte `json:"signature"`
	UserHandle []byte `json:"userHandle"`
}

// steps 10 to 21
func (response *AuthenticatorAssertionResponse) Verify(challenge, rpID, origin string, flags AuthenticatorFlags, storedSignCount uint, attestationResponse *AuthenticatorAttestationResponse) error {
	// steps 10 to 16
	if err := response.AuthenticatorResponse.Verify("webauthn.get", challenge, rpID, origin, flags); err != nil {
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

type Credential struct {
	Id                 []byte
	PublicKey          []byte
	PublicKeyAlgorithm COSEAlgorithmIdentifier
	Transports         []string
	Flags              AuthenticatorFlags
}

type CreatePublicKeyCredential struct {
	Type     string                           `json:"type"`
	Id       string                           `json:"id"`
	RawId    []byte                           `json:"rawId"`
	Response AuthenticatorAttestationResponse `json:"response"`
}

func (cred *CreatePublicKeyCredential) Describe() PublicKeyCredentialDescriptor {
	return PublicKeyCredentialDescriptor{
		Type:       cred.Type,
		Id:         cred.RawId,
		Transports: cred.Response.Transports,
	}
}

type GetPublicKeyCredential struct {
	Type     string                         `json:"type"`
	Id       string                         `json:"id"`
	RawId    []byte                         `json:"rawId"`
	Response AuthenticatorAssertionResponse `json:"response"`
}

type PublicKeyCredentialParameters struct {
	Type      string                  `json:"type"`
	Algorithm COSEAlgorithmIdentifier `json:"alg"`
}

type PublicKeyCredentialDescriptor struct {
	Type       string   `json:"type"`
	Id         []byte   `json:"id"`
	Transports []string `json:"transports"`
}

type PublicKeyCredentialEntity struct {
	Name string `json:"name"`
}

type PublicKeyCredentialRpEntity struct {
	Id string `json:"id"`
}

type PublicKeyCredentialUserEntity struct {
	PublicKeyCredentialEntity
	Id          []byte `json:"id"`
	DisplayName string
}

type CredentialCreationOptions struct {
	PublicKey PublicKeyCredentialCreationOptions `json:"publicKey"`
}

type AuthenticatorSelectionCriteria struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment"`
	ResidentKey             string `json:"residentKey"`
	UserVerification        string `json:"userVerification"`
}
type PublicKeyCredentialCreationOptions struct {
	RelyingParty                  PublicKeyCredentialRpEntity     `json:"rp"`
	User                          PublicKeyCredentialUserEntity   `json:"user"`
	Challenge                     []byte                          `json:"challenge"`
	PublicKeyCredentialParameters []PublicKeyCredentialParameters `json:"pubKeyCredParams"`

	Timeout                        uint64                          `json:"timeout"`
	ExcludeCredentials             []PublicKeyCredentialDescriptor `json:"excludeCredentials"`
	AuthenticatorSelectionCriteria AuthenticatorSelectionCriteria  `json:"authenticatorSelection"`
}

type CredentialRequestOptions struct {
	PublicKey PublicKeyCredentialRequestOptions `json:"publicKey"`
}

type PublicKeyCredentialRequestOptions struct {
}
