package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestRegisterTypeMismatch(t *testing.T) {
	challenge := "lol"
	rpID := "localhost"
	origin := "https://localhost"
	clientData := ClientData{
		Type:        "webauthn.get",
		Challenge:   "lol2",
		Origin:      origin,
		CrossOrigin: false,
	}

	var response AuthenticatorAttestationResponse

	// Step 6
	response.ClientDataJSON = []byte("{")
	err := response.Verify(challenge, rpID, origin, false, []COSEAlgorithmIdentifier{})
	if err == nil {
		t.Error("expected failure")
	}

	response.ClientDataJSON, _ = json.Marshal(clientData)

	// Step 7
	err = response.Verify(challenge, rpID, origin, false, []COSEAlgorithmIdentifier{})
	if err == nil {
		t.Error("Expected failure")
	}
	if err.Error() != "type mismatch" {
		t.Error("expected specific error")
	}
	clientData.Type = "webauthn.create"
	response.ClientDataJSON, _ = json.Marshal(clientData)
	err = response.Verify(challenge, rpID, origin, false, []COSEAlgorithmIdentifier{})
	if err != nil && err.Error() == "type mismatch" {
		t.Error("Expected a different error or no error at all")
	}

	// step 8
	err = response.Verify(challenge, rpID, origin, false, []COSEAlgorithmIdentifier{})
	if err.Error() != "challenge mismatch" {
		t.Error("Expected challenge mismatch")
	}
	clientData.Challenge = challenge
	response.ClientDataJSON, _ = json.Marshal(clientData)
	err = response.Verify(challenge, rpID, origin, false, []COSEAlgorithmIdentifier{})
	if err != nil && err.Error() == "challenge mismatch" {
		t.Error("Expected a different error or no error at all")
	}

	// Step 9
	err = response.Verify(challenge, rpID, "lol", false, []COSEAlgorithmIdentifier{})
	if err != nil && err.Error() != "origin mismatch" {
		t.Error("Expected origin mismatch")
	}

	var authenticatorData AuthenticatorData
	authenticatorData.RPIDHash = sha256.Sum256([]byte(rpID))
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, authenticatorData)

}

func TestRegisterChallengeMismatch(t *testing.T) {
}

func TestAuthenticatorData(t *testing.T) {
	rpIDHash := sha256.Sum256([]byte("hello"))
	flags := FlagUserPresent | FlagUserVerified

	buf := make([]byte, 0, 37)
	buf = append(buf, rpIDHash[:]...)
	buf = append(buf, byte(flags))
	buf = append(buf, []byte{0xa, 0xb, 0xc, 0xd}...)
	buf = append(buf, []byte{123, 232, 23}...)

	var data AuthenticatorData
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, &data); err != nil {
		t.Fatal(err)
	}

	if data.RPIDHash != rpIDHash {
		t.Error("rpID mismatch")
	}
	if data.Flags != flags {
		t.Error("flag mismatch")
	}
	if data.Count != 0x0a0b0c0d {
		t.Error("count mismatch")
	}

	bufWriter := new(bytes.Buffer)
	if err := binary.Write(bufWriter, binary.BigEndian, &data); err != nil {
		t.Fatal(err)
	}

}

func TestFuzz(t *testing.T) {

}
