package passkey

import (
	"github.com/arianvp/webauthn-minimal/webauthn"
	"github.com/google/uuid"
)

type CredentialId []byte
type PasskeyRegistration struct{}
type Passkey struct {
	credential webauthn.Credential
}

func StartRegistration(
	rpID string,
	rpName string,
	userHandle uuid.UUID,
	userName,
	userDisplayName string,
	excludeCredentials []Passkey,
) (*webauthn.PublicKeyCredentialCreationOptions, *PasskeyRegistration, error) {
	excludeCredentials_ := make([]webauthn.PublicKeyCredentialDescriptor, len(excludeCredentials))
	for i, v := range excludeCredentials {
		excludeCredentials_[i] = webauthn.PublicKeyCredentialDescriptor{
			Type:       "public-key",
			Id:         v.credential.Id,
			Transports: v.credential.Transports,
		}
	}
	creationOptions := &webauthn.PublicKeyCredentialCreationOptions{
		RelyingParty: webauthn.PublicKeyCredentialRpEntity{
			Id: rpID,
		},
		User: webauthn.PublicKeyCredentialUserEntity{
			PublicKeyCredentialEntity: webauthn.PublicKeyCredentialEntity{
				Name: userName,
			},
			Id:          userHandle[:],
			DisplayName: userDisplayName,
		},
		Challenge: []byte{0},
		PublicKeyCredentialParameters: []webauthn.PublicKeyCredentialParameters{
			{
				Type:      "public-key",
				Algorithm: webauthn.ES256,
			},
		},
		Timeout:                        1600,
		ExcludeCredentials:             []webauthn.PublicKeyCredentialDescriptor{},
		AuthenticatorSelectionCriteria: webauthn.AuthenticatorSelectionCriteria{},
	}
	return creationOptions, &PasskeyRegistration{}, nil
}

func FinishRegistration(state *PasskeyRegistration) (*Passkey, error) {
	return nil, nil
}
