package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

type COSEKeyType int

const (
	OKP COSEKeyType = 1
	EC2 COSEKeyType = 2
	RSA COSEKeyType = 3
)

type PublicKeyData struct {
	KeyType   COSEKeyType             `cbor:"1,keyasint" json:"kty"`
	Algorithm COSEAlgorithmIdentifier `cbor:"3,keyasint" json:"alg"`
	Curve     COSEEllipticCurve       `cbor:"-1,keyasint,omitempty" json:"crv"`
	XCoord    []byte                  `cbor:"-2,keyasint,omitempty" json:"x"`
	YCoord    []byte                  `cbor:"-3,keyasint,omitempty" json:"y"`
	// Modulus   []byte                  `cbor:"-1,keyasint,omitempty" json:"n"`
	// Exponent  []byte                  `cbor:"-2,keyasint,omitempty" json:"e"`
}

// The COSE Elliptic Curves
// https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
type COSEEllipticCurve int

const (
	// EC2 NIST P-256 also known as secp256r1
	P256    COSEEllipticCurve = 1
	P384    COSEEllipticCurve = 2
	Ed25519 COSEEllipticCurve = 6
)

type COSEAlgorithmIdentifier int64

const (
	EdDSA COSEAlgorithmIdentifier = -8
	ES256 COSEAlgorithmIdentifier = -7
	ES384 COSEAlgorithmIdentifier = -35
	PS256 COSEAlgorithmIdentifier = -37
	RS256 COSEAlgorithmIdentifier = -257
)

type PublicKey struct {
	crypto.PublicKey
	Algorithm COSEAlgorithmIdentifier
}

func ParsePublicKey(publicKeyBytes []byte) (PublicKey, error) {
	keyData := new(PublicKeyData)
	if err := cbor.Unmarshal(publicKeyBytes, keyData); err != nil {
		return PublicKey{}, err
	}
	return COSEKeyToPublicKey(keyData)
}

func COSEKeyToPublicKey(keyData *PublicKeyData) (publicKey PublicKey, err error) {
	switch keyData.KeyType {
	case OKP:
		switch keyData.Curve {
		case Ed25519:
			publicKey.PublicKey = ed25519.PublicKey(keyData.XCoord)
			switch keyData.Algorithm {
			case EdDSA:
				publicKey.Algorithm = keyData.Algorithm
				return
			default:
				err = fmt.Errorf("invalid algorithm %d for curve %d", keyData.Algorithm, keyData.Curve)
				return
			}
		default:
			err = fmt.Errorf("invalid curve %d for key type %d", keyData.Curve, keyData.KeyType)
			return
		}
	case EC2:
		var curve elliptic.Curve
		switch keyData.Curve {
		case P256:
			switch keyData.Algorithm {
			case ES256:
				publicKey.Algorithm = keyData.Algorithm
			default:
				err = fmt.Errorf("invalid algorithm %d for curve %d", keyData.Algorithm, keyData.Curve)
				return
			}
			curve = elliptic.P256()
		case P384:
			switch keyData.Algorithm {
			case ES384:
				publicKey.Algorithm = keyData.Algorithm
			default:
				err = fmt.Errorf("invalid algorithm %d for curve %d", keyData.Algorithm, keyData.Curve)
				return
			}
			curve = elliptic.P384()
		default:
			err = fmt.Errorf("invalid curve %d for key type %d", keyData.Curve, keyData.KeyType)
			return
		}
		publicKey.PublicKey = &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(keyData.XCoord),
			Y:     new(big.Int).SetBytes(keyData.YCoord),
		}
		return

	// TODO Fix RSA
	/*case RSA:
	switch keyData.Algorithm {
	case PS256:
	case RS256:
		publicKey.Algorithm = keyData.Algorithm
	default:
		err = fmt.Errorf("invalid algorithm %d for key type %d", keyData.Algorithm, keyData.KeyType)
		return
	}
	publicKey.PublicKey = &rsa.PublicKey{
		N: new(big.Int).SetBytes(keyData.Modulus),
		E: int(uint(keyData.Exponent[2]) | uint(keyData.Exponent[1])<<8 | uint(keyData.Exponent[0])<<16),
	}
	return*/
	default:
		err = fmt.Errorf("unknown key type %d", keyData.KeyType)
		return
	}
}

func getHashAlgorithm(alg COSEAlgorithmIdentifier) (crypto.Hash, error) {
	switch alg {
	case ES256:
		return crypto.SHA256, nil
	case PS256:
		return crypto.SHA256, nil
	case RS256:
		return crypto.SHA256, nil
	case EdDSA:
		return 0, nil
	case ES384:
		return crypto.SHA384, nil
	default:
		return 0, fmt.Errorf("unknown COSEAlgorithmIdentifier: %d", alg)

	}
}

func (publicKey *PublicKey) VerifySignature(signed, signature []byte) error {
	hashType, err := getHashAlgorithm(publicKey.Algorithm)
	if err != nil {
		return err
	}
	h := hashType.New()
	h.Write(signed)
	signed = h.Sum(nil)
	switch pub := publicKey.PublicKey.(type) {
	case *rsa.PublicKey:
		switch publicKey.Algorithm {
		case PS256:
			return rsa.VerifyPSS(pub, hashType, signed, signature, &rsa.PSSOptions{})
		case RS256:
			return rsa.VerifyPKCS1v15(pub, hashType, signed, signature)
		default:
			return fmt.Errorf("rsa: unsupported alg %d", publicKey.Algorithm)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, signed, signature) {
			return errors.New("ecdsa: Invalid signature")
		}
	case ed25519.PublicKey:
		switch publicKey.Algorithm {
		case EdDSA:
			if !ed25519.Verify(pub, signed, signature) {
				return errors.New("ed25519: invalid signature")
			}
		default:
			return fmt.Errorf("ed25519: unsupported alg %d", publicKey.Algorithm)
		}
	default:
		return errors.New("unsupported public key")
	}
	return nil
}
