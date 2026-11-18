// Build a self-signed certificate, sign it with node:crypto, read it back
// and verify it. cryptographic-formats writes and reads the bytes; node signs.
import crypto from 'node:crypto';
import { x509, x509_build, pem } from 'cryptographic-formats';

const key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const spki = key.publicKey.export({ type: 'spki', format: 'der' });

// 1. prepare: the TBSCertificate - the bytes the signature covers.
const tbs = x509_build.prepare({
  serial:     crypto.randomBytes(16),
  issuer:     [{ commonName: 'Example CA' }],
  subject:    [{ commonName: 'Example CA' }],
  validity:   { not_before: new Date(), not_after: new Date(Date.now() + 864e5) },
  public_key: spki,
  signature_algorithm:  'ecdsaWithSHA256',
  extensions: {
    basicConstraints: { ca: true },
    keyUsage:         ['keyCertSign', 'cRLSign'],
    subjectAltName:   [{ dns: 'ca.example.com' }]
  }
});

// 2. The caller signs. 3. assemble: the signature goes back in.
const sig = crypto.sign('sha256', tbs.bytes, key.privateKey);
const der = x509_build.assemble(tbs, sig);
const text = pem.encode(der, 'CERTIFICATE');

// Reading: the parsed certificate keeps the ORIGINAL signed bytes.
const cert = x509.from_der(pem.decode_one(text, 'CERTIFICATE').der);

console.log(x509.name_to_string(cert.subject));        // CN=Example CA
console.log(cert.signature_algorithm);                 // ecdsaWithSHA256
console.log(x509.hostname_matches(cert, 'ca.example.com'));  // true

const ok = crypto.verify('sha256', cert.tbs_bytes,
  crypto.createPublicKey({ key: Buffer.from(cert.public_key.der), format: 'der',
                           type: 'spki' }),
  cert.signature);
console.log(ok);                                       // true
