// Identify a key file, then move the key between formats: PEM/DER, JWK
// and OpenSSH - with the SSH fingerprint ssh-keygen would print.
import crypto from 'node:crypto';
import { sniff, jwk, spki, ssh } from 'cryptographic-formats';

const pem_text = crypto.generateKeyPairSync('ed25519')
  .publicKey.export({ type: 'spki', format: 'pem' });

// sniff says what it found - check `format` before using `value`.
const found = sniff(pem_text);
console.log(found.format, found.label);        // spki PUBLIC KEY
if (found.format !== 'spki') throw new Error('not a public key');
const key = found.value;                       // { algorithm, curve, point, ... }

// The same key, three more ways.
const j = jwk.from_key(key);                   // { kty: 'OKP', crv: 'Ed25519', x }
const der = spki.to_der(jwk.to_key(j));        // back to SubjectPublicKeyInfo
const line = ssh.key_to_text(key, 'me@host');  // ssh-ed25519 AAAA... me@host

console.log(j.kty, j.crv);                                    // OKP Ed25519
console.log(Buffer.from(der).equals(Buffer.from(key.der)));   // true
console.log(line.split(' ')[0]);                              // ssh-ed25519

// Fingerprint, in the format ssh-keygen prints: SHA-256 over the key's
// wire encoding - which the library supplies, so nothing else gets hashed.
const fp = ssh.fingerprint_sha256(crypto.createHash('sha256')
  .update(ssh.fingerprint_input(ssh.key_from_text(line))).digest());
console.log(fp.startsWith('SHA256:'));                        // true
