package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

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
