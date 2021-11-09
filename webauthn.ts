interface L2PublicKeyCredential extends PublicKeyCredential {
  response : L2AuthenticatorAttestationResponse
}
interface  L2AuthenticatorAttestationResponse extends AuthenticatorAttestationResponse {
  getPublicKey() : BufferSource;
  getAuthenticatorData() : BufferSource;
  getPublicKeyAlgorithm() : COSEAlgorithmIdentifier;
  getTransports() : [string];
}

// A simple version of create augmented w
export async function create(publicKey : PublicKeyCredentialCreationOptions) : Promise<L2PublicKeyCredential> {
  return await navigator.credentials.create({publicKey}) as L2PublicKeyCredential
}


