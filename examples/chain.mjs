// Choosing the issuer of a certificate from several candidates - the step
// where hand-built chain code goes wrong. cryptographic-formats does not build or
// validate paths; this shows the checks a caller makes with what it reads.
//
// Three candidates share the issuer's NAME and KEY, which is ordinary: a CA
// re-issues its certificate when it expires, and cross-signs it under an
// older root. Every one of them verifies the leaf's signature. Only one
// should be picked.
import crypto from 'node:crypto';
import { x509, x509_build } from 'cryptographic-formats';

const DAY = 864e5;
const now = Date.now();
const ca_key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const ca_spki = ca_key.publicKey.export({ type: 'spki', format: 'der' });

function issue(parts, signer, hash) {
  const tbs = x509_build.prepare(Object.assign({
    serial: crypto.randomBytes(8),
    signature_algorithm: hash === 'sha1' ? 'ecdsaWithSHA1' : 'ecdsaWithSHA256'
  }, parts));
  return x509.from_der(x509_build.assemble(tbs,
    crypto.sign(hash, tbs.bytes, signer)));
}

const ca_name = [{ commonName: 'Example CA' }];
const ca_parts = (from, to) => ({
  issuer: ca_name, subject: ca_name, public_key: ca_spki,
  validity: { not_before: new Date(from), not_after: new Date(to) },
  extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] }
});

const candidates = {
  expired:  issue(ca_parts(now - 400 * DAY, now - DAY), ca_key.privateKey, 'sha256'),
  sha1:     issue(ca_parts(now - DAY, now + 300 * DAY), ca_key.privateKey, 'sha1'),
  current:  issue(ca_parts(now - DAY, now + 300 * DAY), ca_key.privateKey, 'sha256')
};

const leaf_key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const leaf = issue({
  issuer: ca_name, subject: [{ commonName: 'www.example.com' }],
  public_key: leaf_key.publicKey.export({ type: 'spki', format: 'der' }),
  validity: { not_before: new Date(now - DAY), not_after: new Date(now + 90 * DAY) },
  extensions: { subjectAltName: [{ dns: 'www.example.com' }] }
}, ca_key.privateKey, 'sha256');

function signed_by(cert, issuer) {
  const key = crypto.createPublicKey({ key: Buffer.from(issuer.public_key.der),
    format: 'der', type: 'spki' });
  return crypto.verify(cert.signature_params.hash, cert.tbs_bytes, key,
    cert.signature);
}

// What this verifier enforces. A critical extension outside it means the
// certificate must be refused (RFC 5280 4.2) - reading one is not enforcing it.
const ENFORCED = ['basicConstraints', 'keyUsage', 'subjectAltName', 'extKeyUsage', 'nameConstraints'];

// The checks, in order. Each one alone lets a wrong candidate through.
function usable_issuers(cert, pool, when) {
  return Object.keys(pool).filter((k) => {
    const c = pool[k];
    return x509.name_matches(cert.issuer, c.subject) &&   // RFC 5280 7.1, not bytes
           x509.validity_contains(c, when) &&             // OpenSSL skips expired ones
           x509.unenforced_critical(c, ENFORCED).length === 0 &&
           signed_by(cert, c);
  });
}

const found = usable_issuers(leaf, candidates, new Date());
console.log(found.join(','));                           // sha1,current

// The signature on the leaf verifies under every candidate - the key is the
// same. What separates them is the candidate's OWN signature: below the
// trust anchor, OpenSSL at node:tls's default level refuses SHA-1 (error 68).
// Prefer the candidates whose own signature is not weak.
const best = found.filter((k) => !candidates[k].signature_params.weak);
console.log(best.join(','));                            // current
console.log(candidates.sha1.signature_params.weak);     // true
