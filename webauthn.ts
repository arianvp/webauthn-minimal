interface  L2AuthenticatorAttestationResponse extends AuthenticatorAttestationResponse {
  getPublicKey() : BufferSource;
  getAuthenticatorData() : BufferSource;
  getPublicKeyAlgorithm() : COSEAlgorithmIdentifier;
  getTransports() : [string];
}




// A simple version of create augmented w
async function create(publicKey : PublicKeyCredentialCreationOptions) {
  let credential = await navigator.credentials.create({publicKey}) as PublicKeyCredential;

  let response = credential.response as L2AuthenticatorAttestationResponse;

  response.getPublicKey();
}