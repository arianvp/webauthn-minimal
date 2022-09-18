package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
)

func getCurve(alg COSEAlgorithmIdentifier) elliptic.Curve {
	return nil
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
		return crypto.SHA256, nil
	case ES384:
		return crypto.SHA384, nil
	case ES512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unknown COSEAlgorithmIdentifier: %d", alg)

	}
}

func checkSignature(alg COSEAlgorithmIdentifier, signed, signature []byte, publicKey crypto.PublicKey) error {
	hashType, err := getHashAlgorithm(alg)
	if err != nil {
		return err
	}
	h := hashType.New()
	h.Write(signed)
	signed = h.Sum(nil)
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		switch alg {
		case PS256:
			return rsa.VerifyPSS(pub, hashType, signed, signature, &rsa.PSSOptions{})
		case RS256:
			return rsa.VerifyPKCS1v15(pub, hashType, signed, signature)
		default:
			return fmt.Errorf("rsa: unsupported alg %d", alg)
		}
	case *ecdsa.PublicKey:
		switch alg {
		case ES256, ES384, ES512:
			if pub.Curve != getCurve(alg) {
				// TODO: should this  check happen earlier?
				return errors.New("ecdsa: Unexpected curve")
			}
			if !ecdsa.VerifyASN1(pub, signed, signature) {
				return errors.New("ecdsa: Invalid signature")
			}
		default:
			return fmt.Errorf("ecdsa: unsupported alg %d", alg)
		}
	case ed25519.PublicKey:
		switch alg {
		case EdDSA:
			if !ed25519.Verify(pub, signed, signature) {
				return errors.New("ed25519: invalid signature")
			}
		default:
			return fmt.Errorf("ed25519: unsupported alg %d", alg)
		}
	default:
		return errors.New("unsupported public key")
	}
	return nil
}
