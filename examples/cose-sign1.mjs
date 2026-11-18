// COSE_Sign1 - the CBOR counterpart of a JWS, used by WebAuthn, ISO mdoc
// and EUDI credentials. Ed25519 here; pycose verifies what this writes.
import crypto from 'node:crypto';
import { cose } from 'cryptographic-formats';

const key = crypto.generateKeyPairSync('ed25519');
const payload = new TextEncoder().encode('hello COSE');

// Header labels are integers: 1 = alg, 4 = kid. -8 = EdDSA.
const p = cose.sign1_prepare({
  protected: [[1, -8]],
  unprotected: [[4, new TextEncoder().encode('key-1')]],
  payload
});
const message = cose.sign1_assemble(p,
  new Uint8Array(crypto.sign(null, p.bytes, key.privateKey)));

// Verifying: the Sig_structure is rebuilt from the bytes that arrived.
const m = cose.sign1_decode(message);
const ok = crypto.verify(null, cose.sign1_signing_input(m),
  key.publicKey, m.signature);

console.log(m.alg, ok);                                // EdDSA true
