package webauthn

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"

	"github.com/fxamacker/cbor/v2"
)

type Base64URLString []byte

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

type AuthenticatorDataHeader struct {
	RPIDHash [32]byte
	Flags    AuthenticatorFlags
	Count    uint32
}

type AttestedCredentialDataHeader struct {
	AAGUID             [16]byte
	CredentialIDLength uint16
}

type AttestedCredentialData struct {
	AttestedCredentialDataHeader
	CredentialID        []byte
	CredentialPublicKey []byte
}
type AuthenticatorData struct {
	AuthenticatorDataHeader
	AttestedCredentialData
	ExtensionData []byte
	// ignore other fields
}

func ParseAndVerifyAuthenticatorData(r io.Reader, rpID string, flags AuthenticatorFlags) (*AuthenticatorData, error) {
	authData := new(AuthenticatorData)

	if err := binary.Read(r, binary.BigEndian, authData.AuthenticatorDataHeader); err != nil {
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

	// Decode credentials
	if authData.Flags&FlagAttestedCredentialData != 0 {

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
	ClientDataJSON Base64URLString `json:"clientDataJSON"`
}

func ParseAndVerifyClientData(clientDataJSON []byte, typ, challenge, rpID, origin string) (*ClientData, error) {
	// 6 / 10
	var clientData ClientData
	if err := json.Unmarshal(clientDataJSON, &clientData); err != nil {
		return nil, err
	}

	// 7 / 11
	if clientData.Type != typ {
		return nil, errors.New("type mismatch")
	}
	// 8 / 12
	if clientData.Challenge != challenge {
		return nil, errors.New("challenge mismatch")
	}
	// 9 / 13
	if clientData.Origin != origin {
		return nil, errors.New("origin mismatch")
	}
	return &clientData, nil
}

type AuthenticatorAttestationResponse struct {
	AuthenticatorResponse
	Transports        []string        `json:"transports,omitempty"` // getTransports()
	AttestationObject Base64URLString `json:"attestationObject"`
}

type AttestationObject struct {
	Format               string          `cbor:"fmt"`
	AttestationStatement cbor.RawMessage `cbor:"attStmt"`
	AuthenticatorData    []byte          `cbor:"authData"`
}

func ParseAndVerifyAttestationObject(attObject []byte) (*AttestationObject, error) {
	var attestationObject AttestationObject
	if err := cbor.Unmarshal(attObject, &attestationObject); err != nil {
		return nil, err
	}
	return &attestationObject, nil
}

func (r *AuthenticatorAttestationResponse) Verify(challenge, rpID, origin string, flags AuthenticatorFlags, pubKeyCredParams []COSEAlgorithmIdentifier) (*Credential, error) {
	// steps 6 to 14
	if _, err := ParseAndVerifyClientData(r.ClientDataJSON, "webauthn.create", challenge, rpID, origin); err != nil {
		return nil, err
	}

	attObject, err := ParseAndVerifyAttestationObject(r.AttestationObject)
	if err != nil {
		return nil, err
	}

	authData, err := ParseAndVerifyAuthenticatorData(bytes.NewReader(attObject.AuthenticatorData), rpID, flags)
	if err != nil {
		return nil, err
	}
	publicKeyBytes := authData.AttestedCredentialData.CredentialPublicKey
	publicKey, alg, err := ParsePublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	// 15. Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.

	found := false
	for _, v := range pubKeyCredParams {
		if found = v == alg; found {
			break
		}
	}
	if !found {
		return nil, errors.New("publicKeyAlgorithm was not one of pubKeyCredParams")
	}
	return &Credential{
		ID:                 authData.AttestedCredentialData.CredentialID,
		PublicKeyAlgorithm: alg,
		PublicKey:          publicKey,
		Transports:         r.Transports,
	}, nil
}

type AuthenticatorAssertionResponse struct {
	AuthenticatorResponse
	AuthenticatorData Base64URLString `json:"authenticatorData"`
	// Signature is signed over append(sha256())
	Signature  Base64URLString `json:"signature"`
	UserHandle Base64URLString `json:"userHandle,omitempty"`
}

// steps 10 to 21
func (r *AuthenticatorAssertionResponse) Verify(challenge, rpID, origin string, flags AuthenticatorFlags, credential *Credential) (uint32, error) {
	// steps 10 to 16
	if _, err := ParseAndVerifyClientData(r.ClientDataJSON, "webauthn.get", challenge, rpID, origin); err != nil {
		return 0, err
	}

	authData, err := ParseAndVerifyAuthenticatorData(bytes.NewReader(r.AuthenticatorData), rpID, flags)
	if err != nil {
		return 0, err
	}

	// 17. WONTFIX: Extensions

	// 18. Let hash be the result of computing a hash over the cData using SHA-256.
	hash := sha256.Sum256(r.ClientDataJSON)
	// 19. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
	signed := append(r.AuthenticatorData, hash[:]...)
	if err := credential.VerifySignature(signed, r.Signature); err != nil {
		return 0, err
	}

	// 21. If all the above steps are successful, continue with the authentication ceremony as appropriate
	return authData.Count, nil
}

type Credential struct {
	ID                 []byte
	PublicKey          crypto.PublicKey
	PublicKeyAlgorithm COSEAlgorithmIdentifier
	Transports         []string
}

func (c *Credential) VerifySignature(signed, signature []byte) error {
	return VerifySignature(c.PublicKey, c.PublicKeyAlgorithm, signed, signature)
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
