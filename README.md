# Webauthn-minimial

Webauthn-minimal is an implementation of a Webauthn L2 Relying Party using only the go standard library.

It uses the utility functons `getPublicKey()`, `getPublicKeyAlgorithm()`, and
`getAuthenticatorData()` From the Webauthn L2 spec [5.2.1.1. Easily accessing
credential data](https://www.w3.org/TR/webauthn-2/#sctn-public-key-easy) to be
able to skip doing any complicated parsing of public key formats like COSE or
CBOR at all.  This allows us to make a webauthn implementation using just the
`crypto` package in Go.

The downside is that attestation is not possible to implement (as that requires
you to do the parsing of the public key material during registration). But many
people do not need attestation for their usecase.

The result is a small, opinionated, easily auditable implementation of a
Relying Party. This hopefully contributes to the overall security of the
implementation.

Downside is that not all browsers implement the L2 spec yet. So far only Chrome
and Edge seem supported.
