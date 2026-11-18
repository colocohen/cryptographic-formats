// Sign a document as CMS SignedData (PKCS#7 - what S/MIME, code signing
// and RFC 3161 timestamps are built on), then verify it the way a
// recipient would. `openssl cms -verify` accepts the result.
import crypto from 'node:crypto';
import { x509, x509_build, cms, cms_build } from 'cryptographic-formats';

// A signer certificate, as in certificate.mjs.
const key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const tbs = x509_build.prepare({
  serial: crypto.randomBytes(16),
  issuer: [{ commonName: 'Signer' }], subject: [{ commonName: 'Signer' }],
  validity: { not_before: new Date(), not_after: new Date(Date.now() + 864e5) },
  public_key: key.publicKey.export({ type: 'spki', format: 'der' }),
  signature_algorithm: 'ecdsaWithSHA256',
  extensions: { keyUsage: ['digitalSignature'] }
});
const cert = x509.from_der(x509_build.assemble(tbs,
  crypto.sign('sha256', tbs.bytes, key.privateKey)));

// Signing. ⚠ Two hashes: the content's digest goes into a signed
// attribute, and the signature covers the attributes (p.bytes).
const content = Buffer.from('the document');
const p = cms_build.prepare({
  content, certificate: cert, digest: 'sha256',
  signature_algorithm: 'ecdsaWithSHA256',
  content_digest: crypto.createHash('sha256').update(content).digest()
});
const der = cms_build.assemble(p, crypto.sign('sha256', p.bytes, key.privateKey));

// Verifying.
const msg = cms.from_der(der);
const signer = msg.signers[0];
const plan = cms.verification_plan(msg, signer);
// With signedAttrs - what cms_build writes - there are two checks, in order.
if (plan.kind !== 'signed-attrs') throw new Error('expected signedAttrs');

const content_ok = cms.digest_matches(signer,
  crypto.createHash(plan.digest).update(plan.content_bytes).digest());
const signer_cert = cms.certificate_for(msg, signer);
const sig_ok = crypto.verify(plan.digest, plan.bytes,
  crypto.createPublicKey({ key: Buffer.from(signer_cert.public_key.der),
                           format: 'der', type: 'spki' }),
  signer.signature);

console.log(content_ok && sig_ok);                     // true
