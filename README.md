# cryptographic-formats

**Strict parsing and building of cryptographic file formats, for JavaScript.**
X.509, PEM, PKCS#8, PKCS#12, CMS/PKCS#7, OCSP, TSP, CMP, SCEP, JOSE (JWS, JWE,
JWT, JWK), COSE, WebAuthn, OpenSSH, ASN.1/DER, CBOR - read and write.

[![npm](https://img.shields.io/npm/v/cryptographic-formats.svg)](https://www.npmjs.com/package/cryptographic-formats)
[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen.svg)
![node: >=18](https://img.shields.io/badge/node-%3E%3D18-blue.svg)

```
cryptography    given a key and a message, produce a signature
cryptographic-formats   given a file, work out that it holds a key - which key,
                in what encoding, and whether that encoding is valid -
                and write such files back out
```

**This library performs no cryptography.** It never signs, verifies,
hashes, encrypts or derives a key. Where a format involves one of those, it
tells you what operation is needed and hands you the exact bytes it applies
to; you run it with `node:crypto`, WebCrypto, or any library you trust, and
hand the result back. That keeps the security-critical code in one place you
chose, and it means the bytes you sign are never a re-encoding that might
differ from what was signed.

- **Zero dependencies.** 68 modules, ~33,000 lines, about 1,300 tests.
- **Strict by default.** Non-canonical DER, duplicate JSON members, padded
  base64url and the like are refused with a precise error - there is no
  `{ strict: false }` switch anywhere.
- **Checked against independent tools.** Every builder's output is accepted
  by OpenSSL, `keytool`, `pycose` or Python's `cryptography`; the parsers
  run against 8,779 Wycheproof vectors and RFC test vectors.
- **Plain ESM.** `import`, Node 18 or later. No native code, no build step.

---

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Examples](#examples)
- [What it covers](#what-it-covers)
- [Module reference](#module-reference)
- [Naming conventions](#naming-conventions)
- [Builders](#builders)
- [Design](#design)
- [Errors](#errors)
- [Building a certificate verifier](#building-a-certificate-verifier)
- [Interoperability notes](#interoperability-notes)
- [Testing and verification](#testing-and-verification)
- [Contributing](#contributing)
- [Versioning](#versioning)
- [License](#license)

---

## Install

```bash
npm install cryptographic-formats
```

ES modules only, Node.js 18 or later. Import everything from the package
root, or one module by its subpath:

```javascript
import { sniff, x509, pem } from 'cryptographic-formats';
import * as jws from 'cryptographic-formats/jws';
```

The library code uses no Node-specific API - Node `Buffer`s are accepted
wherever bytes are, and `Uint8Array` is what comes back - so bundling it for
a browser should work, though the test suite runs on Node only.

**TypeScript.** Declarations ship with the package, beside each module, so
both the root and every subpath are typed. Results are discriminated unions
where the format has variants - narrow on `sniff(...).format`, a CMS plan's
`kind`, a GeneralName's `type` - and `x509.extension(cert, 'subjectAltName')`
knows the parsed type of each extension it reads. The declarations are
checked three ways: they compile under `strict`, the examples type-check
against them, and `node test/run.mjs types-observed` runs the whole test suite
with every export instrumented and checks each recorded call and return
value against its declaration. That catches a declaration narrower than
the code, not one wider: a parameter declared as text or bytes is
therefore also called with text by `test/declared_inputs.test.js`, which
finds every such parameter in the declarations itself.

---

## Quick start

`sniff` reads a file it has not been told the format of, and says what it
decided:

```javascript
import fs from 'node:fs';
import { sniff } from 'cryptographic-formats';

const found = sniff(fs.readFileSync('mystery.pem'));

found.format   // 'x509', 'pkcs8', 'spki', 'pkcs12', 'cms', 'jwk', ...
found.label    // the PEM label, when there was one
found.value    // the parsed object
```

Check `format` before using `value` - that is what makes guessing safe.
When you know the format, call its module directly - `x509.from_der(der)`,
`pkcs8.from_der(der)` - and get a precise error if the bytes are not that.

---

## Examples

Each example below is a file in [`examples/`](examples/) - complete,
runnable with `node examples/<name>.mjs`, and run by the test suite, which also
checks that every `console.log` prints what its comment says. The
cryptography is `node:crypto` throughout.

### Certificates: build, sign, read, verify

[`examples/certificate.mjs`](examples/certificate.mjs)

```javascript
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
```

### Encrypted private keys (PKCS#8 + PBES2)

[`examples/encrypted-key.mjs`](examples/encrypted-key.mjs)

```javascript
// Open a password-protected private key (PKCS#8 + PBES2). cryptographic-formats
// says what was used; node:crypto derives the key and decrypts.
import crypto from 'node:crypto';
import { pem, pkcs8, algorithm } from 'cryptographic-formats';

const password = 'correct horse battery staple';
const text = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  .privateKey.export({ type: 'pkcs8', format: 'pem',
                       cipher: 'aes-256-cbc', passphrase: password });

// What is needed: the KDF parameters, the cipher, the IV, the ciphertext.
const enc = pkcs8.encrypted_from_der(
  pem.decode_one(text, 'ENCRYPTED PRIVATE KEY').der);
console.log(enc.prf, enc.iterations, enc.cipher);  // hmacWithSHA256 2048 aes256CBC
console.log(enc.weak);                             // false

// The caller's half. Names come back as the file states them;
// algorithm.node_name gives node:crypto's spelling ('sha256', 'aes-256-cbc').
const dk = crypto.pbkdf2Sync(password, enc.salt, enc.iterations,
  enc.key_length, algorithm.node_name(enc.prf));
const d = crypto.createDecipheriv(algorithm.node_name(enc.cipher), dk, enc.iv);
const plain = Buffer.concat([d.update(enc.data), d.final()]);

const key = pkcs8.from_der(plain);
console.log(key.algorithm, key.curve);              // ecPublicKey secp256r1
```

### Keys: PEM, JWK and OpenSSH

[`examples/keys.mjs`](examples/keys.mjs)

```javascript
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
```

### JWT: issue and verify

[`examples/jwt.mjs`](examples/jwt.mjs)

```javascript
// Issue an ES256 JWT and verify it. The token's signature is the raw r||s
// pair (64 bytes), not DER - node:crypto is told so with dsaEncoding.
import crypto from 'node:crypto';
import { jwt } from 'cryptographic-formats';

const key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const now = Math.floor(Date.now() / 1000);

// Issuing: the library gives the bytes to sign, the caller signs.
const prepared = jwt.prepare({ alg: 'ES256', kid: 'k1' },
  { iss: 'https://issuer.example', aud: 'my-api', sub: 'user-42',
    iat: now, exp: now + 300 });
const sig = crypto.sign('sha256', prepared.bytes,
  { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
const token = jwt.assemble(prepared, sig);

// Verifying: structure, then signature, then claims - in that order.
const t = jwt.decode(token);
const ok = crypto.verify('sha256', t.signing_input,
  { key: key.publicKey, dsaEncoding: 'ieee-p1363' }, t.signature);

// claims() hands nothing over unless the signature verified, the algorithm
// is one you accept, and iss / aud / exp all pass.
const claims = jwt.claims(t, ['ES256'], ok,
  { issuer: 'https://issuer.example', audience: 'my-api' });
console.log(claims.sub);                                 // user-42
```

### CMS / PKCS#7 signatures

[`examples/cms-sign.mjs`](examples/cms-sign.mjs)

```javascript
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
```

### PKCS#12 (.p12 / .pfx)

[`examples/pkcs12.mjs`](examples/pkcs12.mjs)

```javascript
// Write a .p12 / .pfx (a key and its certificate) and read it back.
// Every encryption, KDF and MAC is node:crypto, passed in as primitives.
// The MAC is PBMAC1 (RFC 9579) - PBKDF2 then HMAC. For importers older
// than OpenSSL 3.4, leave out `scheme` and use the PKCS#12 KDF instead.
import crypto from 'node:crypto';
import { x509_build, pkcs8, pkcs12, pkcs12_build, algorithm } from 'cryptographic-formats';

const password = 'p12 password';
const key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const tbs = x509_build.prepare({
  serial: crypto.randomBytes(16),
  issuer: [{ commonName: 'me' }], subject: [{ commonName: 'me' }],
  validity: { not_before: new Date(), not_after: new Date(Date.now() + 864e5) },
  public_key: key.publicKey.export({ type: 'spki', format: 'der' }),
  signature_algorithm: 'ecdsaWithSHA256'
});
const cert = x509_build.assemble(tbs,
  crypto.sign('sha256', tbs.bytes, key.privateKey));

// PBES2: derive, encrypt, and describe what was done.
function encrypt(data) {
  const p = { prf: 'hmacWithSHA256', salt: crypto.randomBytes(16),
              iterations: 100000, cipher: 'aes256CBC',
              iv: crypto.randomBytes(16) };
  const k = crypto.pbkdf2Sync(password, p.salt, p.iterations, 32, 'sha256');
  const c = crypto.createCipheriv('aes-256-cbc', k, p.iv);
  return { ...p, data: Buffer.concat([c.update(data), c.final()]) };
}

const id = crypto.createHash('sha1').update(cert).digest();   // ties key to cert
const keys = pkcs12_build.safe_contents([pkcs12_build.shrouded_key_bag(
  pkcs8.encrypted_to_der(encrypt(
    key.privateKey.export({ type: 'pkcs8', format: 'der' }))),
  { friendly_name: 'my key', local_key_id: id })]);
const certs = pkcs12_build.safe_contents([
  pkcs12_build.cert_bag(cert, { local_key_id: id })]);
const p12_prepared = pkcs12_build.prepare([
  pkcs12_build.data_safe(keys), pkcs12_build.encrypted_safe(encrypt(certs))]);

// The MAC covers p12_prepared.bytes - exactly those, nothing around them.
const salt = crypto.randomBytes(16);
const mac_key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
const pfx = pkcs12_build.assemble(p12_prepared, {
  scheme: 'pbmac1', hash: 'sha256', prf: 'hmacWithSHA256',
  salt, iterations: 100000,
  digest: crypto.createHmac('sha256', mac_key).update(p12_prepared.bytes).digest()
});

// Reading: the library walks the file, the primitives do the work.
const p12 = pkcs12.open(pfx, password, {
  pbkdf2: (prf, pw, s, it, len) =>
    crypto.pbkdf2Sync(pw, s, it, len, algorithm.node_name(prf)),
  decrypt: (cipher, k, iv, data) => {
    const d = crypto.createDecipheriv(algorithm.node_name(cipher), k, iv);
    return Buffer.concat([d.update(data), d.final()]);
  },
  hmac: (hash, k, data) => crypto.createHmac(hash, k).update(data).digest()
});

console.log(p12.mac_verified);                         // true
console.log(p12.keys.length, p12.certificates.length); // 1 1
```

### COSE_Sign1

[`examples/cose-sign1.mjs`](examples/cose-sign1.mjs)

```javascript
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
```

### Any ASN.1 structure

[`examples/asn1.mjs`](examples/asn1.mjs)

```javascript
// Any ASN.1 structure, not only the ones this library describes - here a
// made-up record. Strict DER both ways, and a refusal says exactly why.
//
//   Record ::= SEQUENCE {
//     id     INTEGER,
//     name   UTF8String,
//     tags   [0] IMPLICIT SEQUENCE OF UTF8String OPTIONAL }
import { der, der_writer as W, FormatError } from 'cryptographic-formats';

const bytes = W.to_bytes(W.sequence([
  W.integer([42]),
  W.utf8_string('example'),
  W.implicit(0, W.sequence([W.utf8_string('a'), W.utf8_string('b')]))
]));

const record = der.read(bytes, (r) => {
  const seq = r.read_sequence();
  const out = { id: seq.read_unsigned()[0], name: seq.read_utf8_string(),
                tags: [] };
  if (seq.peek_tag() === 0xA0) {
    const tags = seq.read_implicit(0, 0x30);
    while (tags.remaining() > 0) out.tags.push(tags.read_utf8_string());
  }
  seq.expect_end();
  return out;
});
console.log(record);                  // { id: 42, name: 'example', tags: [ 'a', 'b' ] }

// The same INTEGER with its length written in two bytes: valid BER, not DER.
try {
  der.read(new Uint8Array([0x02, 0x81, 0x01, 0x2A]), (r) => r.read_integer());
} catch (e) {
  console.log(e instanceof FormatError, e.code, e.offset);  // true non-minimal-length 1
}
```

### Choosing an issuer

[`examples/chain.mjs`](examples/chain.mjs)

```javascript
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
```

---

## What it covers

| area | formats | read | write |
|---|---|:-:|:-:|
| **encodings** | base16/32/64/64url, base58, base58check, bech32 and bech32m (BIP 173/350), multibase, multihash, CID | ✓ | ✓ |
| **ASN.1** | DER (X.690, strict), BER (separate reader), all 30 universal types incl. REAL, field tables with extension markers and AUTOMATIC TAGS, OIDs | ✓ | ✓ |
| **keys** | SPKI (RFC 5280), PKCS#8 (RFC 5958), PKCS#1 (RFC 8017), SEC1 (RFC 5915), PBES2 (RFC 8018), JWK/JWKS (RFC 7517), COSE_Key (RFC 9053), OpenSSH public and private keys, DH and EC parameters | ✓ | ✓ |
| **SSH** | OpenSSH certificates (PROTOCOL.certkeys) and SSHSIG file signatures (PROTOCOL.sshsig); security keys (FIDO, PROTOCOL.u2f): `sk-ssh-ed25519`, `sk-ecdsa-sha2-nistp256` keys, certificates and signatures, webauthn included; KRLs, sshd's revocation lists (PROTOCOL.krl); security-key attestation files, `ssh-sk-attest-v01` (`ssh-keygen -O write-attestation`), with what the signature covers in both formats a key can use | ✓ | ✓ |
| **OpenPGP** | RFC 9580: ASCII armour, the cleartext signature framework, every packet type, v4 and v6 keys (v3 read), signatures with their subpackets, transferable keys, PKESK/SKESK and v1/v2 SEIPD with what each layer is computed over | ✓ | ✓ |
| **PKCS#12** | RFC 7292 with PBES2, PKCS#12-KDF and PBMAC1 (RFC 9579) MACs; the BER Windows and `keytool` write | ✓ | ✓ |
| **certificates** | X.509 (RFC 5280, incl. RSA-PSS, hostname matching, name constraints; device identities in SAN otherNames - PermanentIdentifier, RFC 4043, and HardwareModuleName, RFC 4108 - and Microsoft's UPN; device attestation extensions - Android's KeyDescription, Apple's WebAuthn/App Attest nonce and Managed Device Attestation values), CSR (RFC 2986), CRL, attribute certificates (RFC 5755), Certificate Transparency SCTs (RFC 6962) | ✓ | ✓ |
| **OCSP / TSP** | OCSP requests and responses (RFC 6960), timestamps (RFC 3161) | ✓ | ✓ |
| **CMS** | SignedData (RFC 5652), EnvelopedData with RSA, ECDH (RFC 5753), shared-key and password (RFC 3211) recipients, AuthEnvelopedData with AES-GCM (RFC 5083/5084), AuthenticatedData (RFC 5652 9), CompressedData (RFC 3274), DigestedData, EncryptedData, S/MIME (RFC 8551) | ✓ | ✓ |
| **CMP / CRMF** | certificate management (RFC 4210): requests and the CA's responses, PBM protection; CRMF requests (RFC 4211) | ✓ | ✓ |
| **SCEP** | simple certificate enrolment (RFC 8894): the pkiMessage's attributes checked against its type, the envelope's content read; CertRep and requests written; GetCACaps text. The envelope is `cms_enveloped`'s, the signature `cms`'s | ✓ | ✓ |
| **JOSE** | JWS (RFC 7515, incl. RFC 7797 unencoded payload) and JWE (RFC 7516) in all three serializations; JWK thumbprints (RFC 7638); JWT claims (RFC 7519); SD-JWT with key binding (RFC 9901) | ✓ | ✓ |
| **CBOR / COSE** | deterministic CBOR (RFC 8949); COSE Sign1, Sign, Mac0, Mac, Encrypt0 and Encrypt with nested recipients (RFC 9052/9053); CWT (RFC 8392) | ✓ | ✓ |
| **post-quantum** | ML-DSA (RFC 9881), SLH-DSA (RFC 9909) and ML-KEM (RFC 9935) keys - public, and private in the seed, expanded and both forms; their signatures in certificates, CRLs, CSRs, OCSP and CMS (RFC 9882); ML-KEM recipients in CMS - KEMRecipientInfo (RFC 9629, RFC 9936) | ✓ | ✓ |
| **WebAuthn / FIDO** | attestation objects, authenticator data, the signing input of each attestation format (fido-u2f's own layout included), assertion signing input; the FIDO Metadata Service BLOB (MDS3): entries by AAGUID, AAID or key identifier, status reports, attestation roots | ✓ | |
| **SAML** | XMLDSig signature containers, SignedInfo canonicalization, structural attack checks - [see below](#saml-is-a-partial-answer) | ✓ | |

**Out of scope:** the cryptography itself; certificate path building and
trust decisions; streaming parsers; DNSSEC; OpenPGP's web of trust and
key servers. The pieces a verifier
needs from the format are in, though - see
[Building a certificate verifier](#building-a-certificate-verifier).

---

## Module reference

Each module is exported from the root (`import { x509 } from 'cryptographic-formats'`)
and most have a subpath (`cryptographic-formats/x509`, with `_` written as `-`). The
main functions:

**Entry point**

| module | for | main functions |
|---|---|---|
| `sniff` | a function, not a module: identify and parse any supported file - PEM, DER, JSON, CBOR, OpenSSH, S/MIME | `sniff(input)` |

**Keys**

| module | for | main functions |
|---|---|---|
| `pem`<br><sub>`cryptographic-formats/pem`</sub> | PEM blocks (RFC 7468), incl. bundles and legacy encrypted PEM | `decode`, `decode_one`, `encode` |
| `spki`<br><sub>`cryptographic-formats/spki`</sub> | public keys - SubjectPublicKeyInfo | `from_der`, `to_der` |
| `pkcs8`<br><sub>`cryptographic-formats/pkcs8`</sub> | private keys - PKCS#8, PKCS#1, SEC1, and password-encrypted (PBES2) | `from_der`, `to_der`, `encrypted_from_der`, `encrypted_to_der`, `pkcs1_from_der`, `sec1_from_der` |
| `pbes2`<br><sub>`cryptographic-formats/pbes2`</sub> | the PBES2 pieces PKCS#8, PKCS#12 and CMS share (RFC 8018) | `scheme_to_der`, `pbkdf2_to_der`, `read_pbkdf2`, `is_weak` |
| `pkcs12`<br><sub>`cryptographic-formats/pkcs12`</sub> | .p12 / .pfx | `from_der`, `open`, `bags_from_der` |
| `jwk`<br><sub>`cryptographic-formats/jwk`</sub> | JWK and JWKS (RFC 7517), thumbprints (RFC 7638) | `from_key`, `to_key`, `set_from_json`, `set_find`, `thumbprint_input` |
| `ssh`<br><sub>`cryptographic-formats/ssh`</sub> | OpenSSH public keys, openssh-key-v1 private keys, fingerprints, SSHSIG signatures, certificates | `key_from_text`, `key_to_text`, `private_from_pem`, `private_to_pem`, `fingerprint_input`, `fingerprint_sha256`, `sshsig_from_text`, `sshsig_prepare`, `certificate_from_text`, `certificate_prepare`, `krl_from_bytes`, `sk_attestation_from_bytes`, `sk_attestation_plan` |
| `openpgp`<br><sub>`cryptographic-formats/openpgp`</sub> | OpenPGP (RFC 9580): armour, cleartext signatures, every packet, transferable keys, signature and decryption inputs | `armor_decode`, `cleartext_decode`, `packets_from_bytes`, `keys_from_packets`, `verification_plan`, `key_id`, `seipd_v1_open`, `session_key_from` |
| `openpgp_build`<br><sub>`cryptographic-formats/openpgp-build`</sub> | OpenPGP written: keys, signatures, messages, encrypted containers | `armor_encode`, `cleartext_encode`, `key_packet`, `signature_prepare`, `signature_assemble`, `literal_packet`, `pkesk`, `skesk`, `seipd_v2_prepare` |
| `params`<br><sub>`cryptographic-formats/params`</sub> | DH and EC domain parameters | `dh_from_pem`, `ec_from_pem`, `dh_to_der`, `ec_to_der` |

**Certificates and PKI**

| module | for | main functions |
|---|---|---|
| `x509`<br><sub>`cryptographic-formats/x509`</sub> | X.509 certificates (RFC 5280) | `from_der`, `name_attribute`, `name_to_string`, `hostname_matches`, `name_constraints_check`, `name_constraints_permit`, `openssl_unsupported_critical`, `validity_contains`, `name_matches`, `extension`, `ocsp_urls`, `crl_urls` |
| `csr`<br><sub>`cryptographic-formats/csr`</sub> | PKCS#10 requests (RFC 2986) | `from_der` |
| `crl`<br><sub>`cryptographic-formats/crl`</sub> | CRLs (RFC 5280) | `from_der`, `find`, `is_current` |
| `ocsp`<br><sub>`cryptographic-formats/ocsp`</sub> | OCSP (RFC 6960) | `request_from_der`, `response_from_der`, `find`, `is_current`, `cert_id_matches` |
| `tsp`<br><sub>`cryptographic-formats/tsp`</sub> | timestamps (RFC 3161) | `request_from_der`, `response_from_der`, `verification_plan`, `check` |
| `attrcert`<br><sub>`cryptographic-formats/attrcert`</sub> | attribute certificates (RFC 5755) | `from_der`, `verification_plan`, `holder_is` |
| `sct`<br><sub>`cryptographic-formats/sct`</sub> | Certificate Transparency SCTs (RFC 6962) | `from_extension`, `in_certificate`, `verification_plan` |
| `crmf`<br><sub>`cryptographic-formats/crmf`</sub> | certificate request messages (RFC 4211) | `from_der`, `verification_plan` |
| `cmp`<br><sub>`cryptographic-formats/cmp`</sub> | certificate management (RFC 4210) | `from_der`, `verification_plan`, `protected_bytes`, `answers` |
| `scep`<br><sub>`cryptographic-formats/scep`</sub> | SCEP (RFC 8894) pkiMessages and what their envelopes hold | `from_der`, `inner`, `capabilities_from_text` |

**Signed and encrypted messages**

| module | for | main functions |
|---|---|---|
| `cms`<br><sub>`cryptographic-formats/cms`</sub> | CMS SignedData (RFC 5652) | `from_der`, `verification_plan`, `digest_matches`, `certificate_for` |
| `cms_enveloped`<br><sub>`cryptographic-formats/cms-enveloped`</sub> | EnvelopedData, AuthEnvelopedData, DigestedData, EncryptedData | `from_der`, `auth_from_der`, `recipient_for`, `pwri_key_from_block`, `digested_from_der`, `encrypted_from_der` |
| `smime`<br><sub>`cryptographic-formats/smime`</sub> | S/MIME (RFC 8551) | `from_bytes`, `verification_plan`, `wrap`, `wrap_opaque`, `canonicalize` |
| `saml`<br><sub>`cryptographic-formats/saml`</sub> | SAML / XMLDSig signature structure | `verification_plan`, `signed_info` |

**JOSE, CBOR and COSE**

| module | for | main functions |
|---|---|---|
| `jws`<br><sub>`cryptographic-formats/jws`</sub> | JWS (RFC 7515, RFC 7797) | `decode`, `signing_input`, `payload`, `select_key`, `prepare`, `assemble`, `general_assemble` |
| `jwe`<br><sub>`cryptographic-formats/jwe`</sub> | JWE (RFC 7516) | `decode`, `decryption_plan`, `prepare`, `assemble` |
| `jwt`<br><sub>`cryptographic-formats/jwt`</sub> | JWT (RFC 7519) | `decode`, `claims`, `prepare`, `assemble` |
| `sd_jwt`<br><sub>`cryptographic-formats/sd-jwt`</sub> | SD-JWT (RFC 9901) - selective disclosure, key binding | `decode`, `claims`, `key_binding`, `disclosure`, `serialize`, `kb_prepare`, `kb_assemble` |
| `cose`<br><sub>`cryptographic-formats/cose`</sub> | COSE (RFC 9052/9053) and COSE_Key | `sign1_decode`, `sign1_prepare`, `sign1_assemble`, `sign_decode`, `mac0_decode`, `mac_decode`, `encrypt0_decode`, `encrypt_decode`, `encrypt_prepare`, `key_from_cbor`, `key_to_cbor` |
| `cwt`<br><sub>`cryptographic-formats/cwt`</sub> | CBOR Web Token (RFC 8392) - claims over a COSE message | `decode`, `claims`, `claims_to_cbor`, `tagged` |
| `webauthn`<br><sub>`cryptographic-formats/webauthn`</sub> | WebAuthn attestation and assertions | `from_cbor`, `auth_data_from_bytes`, `signing_input`, `assertion_signing_input`, `rp_id_matches` |
| `fido_mds`<br><sub>`cryptographic-formats/fido-mds`</sub> | the FIDO Metadata Service BLOB (MDS3) | `decode`, `payload`, `entry_for`, `attestation_roots` |
| `signature`<br><sub>`cryptographic-formats/signature`</sub> | ECDSA DER <-> raw r||s | `der_to_raw`, `raw_to_der`, `describe` |
| `algorithm`<br><sub>`cryptographic-formats/algorithm`</sub> | AlgorithmIdentifier (incl. RSA-PSS, OAEP) and algorithm names | `describe`, `to_der`, `canonical_name`, `node_name` |

**Builders**

| module | for | main functions |
|---|---|---|
| `x509_build`<br><sub>`cryptographic-formats/x509-build`</sub> | certificates | `prepare`, `assemble`, `check`, `key_id_input` |
| `csr_build`<br><sub>`cryptographic-formats/csr-build`</sub> | PKCS#10 requests | `prepare`, `assemble` |
| `crl_build`<br><sub>`cryptographic-formats/crl-build`</sub> | CRLs | `prepare`, `assemble`, `check` |
| `cms_build`<br><sub>`cryptographic-formats/cms-build`</sub> | SignedData and .p7b bundles | `prepare`, `assemble`, `bundle` |
| `cms_enveloped_build`<br><sub>`cryptographic-formats/cms-enveloped-build`</sub> | EnvelopedData and AuthEnvelopedData | `enveloped_data`, `auth_enveloped_data`, `auth_aad`, `kari_shared_info`, `kem_kdf_info`, `pwri_key_block` |
| `ocsp_build`<br><sub>`cryptographic-formats/ocsp-build`</sub> | OCSP requests and responses | `request`, `cert_id_inputs`, `prepare`, `assemble`, `error_response` |
| `tsp_build`<br><sub>`cryptographic-formats/tsp-build`</sub> | timestamp requests and responses | `request`, `tst_info`, `signing_certificate_v2`, `response` |
| `pkcs12_build`<br><sub>`cryptographic-formats/pkcs12-build`</sub> | .p12 / .pfx | `shrouded_key_bag`, `cert_bag`, `safe_contents`, `data_safe`, `encrypted_safe`, `prepare`, `assemble` |
| `attrcert_build`<br><sub>`cryptographic-formats/attrcert-build`</sub> | attribute certificates | `prepare`, `assemble`, `check` |
| `crmf_build`<br><sub>`cryptographic-formats/crmf-build`</sub> | CRMF certificate requests | `prepare`, `assemble` |
| `cmp_build`<br><sub>`cryptographic-formats/cmp-build`</sub> | CMP messages, responses and confirmations | `prepare`, `assemble`, `cert_rep`, `error`, `pkiconf`, `cert_conf` |
| `scep_build`<br><sub>`cryptographic-formats/scep-build`</sub> | SCEP CertRep and requests, GetCACaps | `cert_rep_prepare`, `cert_rep_assemble`, `request_prepare`, `request_assemble`, `cert_rep_content`, `capabilities_text` |

**Encodings (level 0)**

| module | for | main functions |
|---|---|---|
| `der`<br><sub>`cryptographic-formats/der`</sub> | strict DER reader (X.690) | `read`, `reader` |
| `der_writer`<br><sub>`cryptographic-formats/der-writer`</sub> | DER writer, every universal type | `sequence`, `integer`, `oid`, `explicit`, `implicit`, `to_bytes` |
| `ber`<br><sub>`cryptographic-formats/ber`</sub> | BER reader - separate, used only by pkcs12 | `read`, `is_ber` |
| `fields`<br><sub>`cryptographic-formats/fields`</sub> | ASN.1 field tables | `define`, `read_type` |
| `oid`<br><sub>`cryptographic-formats/oid`</sub> | object identifiers | `from_string`, `to_string`, `by_name`, `name_of` |
| `tags` | tag names | `name_of` |
| `real` | ASN.1 REAL | `decode`, `encode` |
| `cbor`<br><sub>`cryptographic-formats/cbor`</sub> | CBOR reader (RFC 8949) | `decode`, `read` |
| `cbor_writer`<br><sub>`cryptographic-formats/cbor-writer`</sub> | deterministic CBOR writer | `encode`, `to_bytes` |
| `json`<br><sub>`cryptographic-formats/json`</sub> | JSON parser that refuses duplicate members | `parse` |
| `xml`<br><sub>`cryptographic-formats/xml`</sub> | strict XML reader and canonicalization | `parse`, `canonicalize` |
| `base`<br><sub>`cryptographic-formats/base`</sub> | base16/32/58/64/64url | `encode`, `decode`, `to_base64url`, `from_base64url`, `base58check_encode` |
| `bech32`<br><sub>`cryptographic-formats/bech32`</sub> | bech32 and bech32m | `encode`, `decode` |
| `multiformats`<br><sub>`cryptographic-formats/multiformats`</sub> | multibase, multihash, CIDs | `decode`, `encode`, `cid_decode` |

Every function that refuses input throws a [`FormatError`](#errors); none
returns `null` for "could not parse".

---

## Naming conventions

The names follow a small set of rules, so the one you need can usually be
guessed - and a test (`test/naming.test.js`) keeps them that way.

| | rule | examples |
|---|---|---|
| **reading** | `from_<encoding>` returns the parsed structure; a module with several structures prefixes the thing | `x509.from_der`, `ocsp.request_from_der`, `pkcs8.encrypted_from_der`, `webauthn.from_cbor` |
| **writing a key or encoding** | `to_<encoding>`, beside the reader | `spki.to_der`, `pkcs8.encrypted_to_der`, `pem.encode` |
| **writing a signed structure** | a `*_build` module named for the reader, with `prepare` → `{ bytes }` and `assemble(prepared, result)` | `x509_build`, `csr_build`, `cms_build`, `cmp_build` |
| **several structures, one module** | `<thing>_prepare` / `<thing>_assemble` | `cose.sign1_prepare`, `cose.encrypt_assemble` |
| **one-step writers** | named for what they write | `ocsp_build.request`, `tsp_build.response`, `cms_enveloped_build.enveloped_data` |
| **tokens and codecs** | `decode` / `encode` | `jws.decode`, `cose.sign1_decode`, `base.encode`, `pem.decode` |
| **verifying** | `verification_plan(x)` → `{ bytes, signature, algorithm, ... }` - what to verify, over what | `cms`, `tsp`, `cmp`, `crmf`, `attrcert`, `sct`, `saml` |
| **fields** | the same name read and written; snake_case | `signature_algorithm`, `public_key`, `tbs_bytes`, `validity.not_before` |
| **algorithms** | returned by OID-table name; accepted in that or node/OpenSSL spelling; `algorithm.node_name()` converts | `'aes256CBC'` ⇄ `'aes-256-cbc'`, `'hmacWithSHA256'` → `'sha256'` |
| **attribute names** | returned by this library's names; accepted in those, the X.520 spelling, or RFC 4514's short form | `stateOrProvince` = `stateOrProvinceName` = `ST`; `organizationalUnit` = `organizationalUnitName` = `OU` |
| **IP addresses** | text or bytes; in nameConstraints a range, as CIDR text or address-and-mask bytes | `{ ip: '2001:db8::1' }`; `{ ip: '10.0.0.0/8' }` |
| **warnings in names** | a field that must not be trusted says so | `signing_time_claimed`, `unsigned_attrs_unsigned`, `unprotected_attrs_unauthenticated` |

Because the readers and builders share field names, a parsed structure can
be fed back: `x509_build.prepare` takes `cert.subject`, `cert.validity`,
`cert.public_key` and `cert.signature_algorithm` exactly as `x509.from_der`
returned them, and the test suite checks the signed bytes come out the same.

---

## Builders

Every builder has the same two calls - `prepare(parts)` returns `{ bytes }`,
the bytes to sign, MAC or use as AAD; you do the cryptography;
`assemble(prepared, result)` writes the structure:

```javascript
const p   = x509_build.prepare({ subject, issuer, serial, validity,
                                 public_key, signature_algorithm });
const der = x509_build.assemble(p, sign(p.bytes));
```

And every one is checked against a tool that shares no code with this
library:

| builder | what it writes | checked by |
|---|---|---|
| `x509_build` | certificates, incl. RSA-PSS | `openssl verify -x509_strict` |
| `csr_build` | PKCS#10 requests | `openssl req -verify` |
| `crl_build` | CRLs | `openssl crl` |
| `cms_build` | SignedData, attached and detached; `.p7b` bundles | `openssl cms -verify` |
| `cms_enveloped_build` | EnvelopedData: RSA (PKCS#1 v1.5, OAEP), ECDH + X9.63 KDF, shared KEK, password (RFC 3211); AuthEnvelopedData with AES-GCM | `openssl cms -decrypt`; asn1crypto for authAttrs |
| `ocsp_build` | OCSP requests; signed responses, error responses | `openssl ocsp`, nonce included |
| `tsp_build` | RFC 3161 requests; responses with signingCertificateV2 | `openssl ts -verify`, against query and data |
| `pkcs12_build` | PFX with PBES2, and a PKCS#12-KDF or PBMAC1 MAC | `openssl pkcs12`, `keytool`; Python `cryptography` and the RFC 9579 files for PBMAC1 |
| `crmf_build`, `cmp_build` | CRMF requests; CMP messages - ip/cp/kup/ccp, error, pkiconf, certConf; the server side of RFC 9483: generalInfo (implicitConfirm, confirmWaitTime, certProfile), rp, pollRep, genp with caCerts and rootCaKeyUpdate | `openssl cmp`, through ir → ip → certConf → pkiconf, implicit confirmation, rr → rp (it checks the revoked serial), polling, genm → genp; OpenSSL's mock server's messages read |
| `scep_build` | SCEP CertRep (SUCCESS, FAILURE with failInfo and failInfoText, PENDING) and requests; CertPoll and GetCert contents; GetCACaps. A GetCACert answer is the CA's DER alone, or `cert_rep_content([ca, ra])` - a degenerate SignedData - with an RA | micromdm `scepclient` enrolling against a server written here, and refused by it; micromdm's own messages read |
| `attrcert_build` | attribute certificates | asn1crypto (OpenSSL cannot parse them), signature checked over the bytes it finds |
| `ssh` | OpenSSH public keys; `openssh-key-v1` private keys, plain and encrypted | byte-identical round trip; Python `cryptography` |
| `jws`, `jwe`, `jwt` | every serialization (`prepare` / `assemble`) | the RFC test vectors |
| `cose` | Sign1, Sign, Mac0, Mac, Encrypt0, Encrypt (`sign1_prepare` / `sign1_assemble`, ...) | `pycose`, both directions |

Where a step needs bytes that are easy to get wrong, the library computes
them: `x509_build.key_id_input` (what a subjectKeyIdentifier hashes),
`ocsp.cert_id_inputs` (what an OCSP CertID hashes),
`cms_enveloped_build.kari_shared_info` (the X9.63 KDF's SharedInfo),
`cms_enveloped_build.kem_kdf_info` (a KEM recipient's HKDF info, RFC 9629),
`cms_enveloped_build.auth_aad` (AuthEnvelopedData's AAD),
`cms_enveloped_build.pwri_key_block` (RFC 3211's key block),
`cose.encrypt_aad` and `cose.mac_input` (the Enc_ and MAC_structures).

`x509_build.check(parts)` reports what is legal and probably wrong - a CA
without `keyCertSign`, a serial too short to resist a chosen-prefix
collision, a keyUsage an ML-DSA or ML-KEM key may not carry. It returns warnings rather than throwing: a builder should not
impose policy nobody asked for, but it should say when something looks off.

---

## Design

### No cryptography, so the signed bytes are the original bytes

Every signed structure returns the bytes its signature covers exactly as
they arrived - `cert.tbs_bytes`, a JWS signing input, CMS `signedAttrs` with
its tag substituted, a COSE Sig_structure built from the protected header
as received. Never a re-encoding: a structure whose encoding deviates from
canonical form would hash differently after a round trip, and its signature
would fail for reasons that look like a bad key.

Signatures cross the boundary in the form the specification names, and the
shape is checked. JOSE and COSE ECDSA signatures are the raw `r||s` pair -
64 bytes for ES256 - where X.509 and CMS use DER (70-72 bytes). `signature`
converts between them, and refuses to "convert" Ed25519 or RSA, which have
one form.

```javascript
signature.der_to_raw({ der: bytes, curve: 'secp256r1' })   // -> 64 bytes
signature.raw_to_der({ raw: bytes, curve: 'secp521r1' })   // -> DER
```

### Three levels

```javascript
sniff(bytes)                  // level 2 - "just read this", and says what it guessed
x509.from_der(bytes)          // level 1 - a specific format
der.read(bytes, fn)           // level 0 - any ASN.1, structures this library
                              //           does not describe
```

A PEM label narrows the search rather than widening it: a block labelled
`CERTIFICATE` is tried as a certificate and nothing else. Level 0 is
exported deliberately - there are more ASN.1 structures than this library
will ever describe, and a caller who cannot reach the strict reader
installs a lenient one instead.

### Strict by default

Lenient parsing is where vulnerabilities live, so every relaxation has a
written reason beside it, and none can be switched on by a flag.

```javascript
der.read(bytes, fn)     // refuses a non-minimal length, a non-minimal
                        // INTEGER, an indefinite length, a constructed
                        // string, a BOOLEAN that is not 0x00 or 0xFF,
                        // a SET or SET OF out of order, an explicitly
                        // encoded DEFAULT, trailing bytes

json.parse(text)        // refuses duplicate members: JSON.parse keeps the
                        // last silently, so {"kty":"EC","kty":"RSA"} reads
                        // as RSA to one consumer and EC to another

base.decode('base64url', s)
                        // refuses padding and non-zero trailing bits -
                        // both give one byte string two spellings
```

Where tolerance is genuinely needed it gets a separate module whose name
says so: `ber` reads the BER that Windows and Java `keytool` write into
PKCS#12 files, only `pkcs12` uses it (a test enforces that), and the result
reports `encoding: 'ber'` so the caller knows.

Costs the file chooses are capped: PBKDF2 and PKCS#12 iteration counts
above 1,000,000 are refused unless the caller raises `max_iterations`, and
nesting depths are bounded.

### ASN.1 beyond cryptography

All 30 X.690 universal types, including `REAL` (all three encodings),
`RELATIVE-OID`, `EXTERNAL`, `EMBEDDED PDV` and the old string types; field
tables with extension markers (`...`), `AUTOMATIC TAGS` and `SIZE`
constraints. The DER core imports nothing crypto-aware - the tests parse an
LDAP `BindRequest` and an SNMP `GetRequest` with it.

### SAML is a partial answer

`saml.verification_plan(xml)` reads the document with a strict XML reader
(no DTDs, no entity expansion, namespace-aware), checks the XMLDSig
structure, and canonicalizes `ds:SignedInfo`, so the plan's `bytes` are
what the SignatureValue covers - real signatures from `signxml` verify over
it. It does **not** compute the digest of the referenced element: that runs
the document's own transforms, and a second XML reading beside your XML
library's is the parser differential that signature-wrapping attacks use.

```javascript
const plan = saml.verification_plan(xml);

plan.problems          // reasons to REFUSE, from the structure alone
plan.element_id        // which element the signature protects
plan.bytes             // canonical SignedInfo - verify the signature over this
plan.certificates      // parsed X.509, as from a PEM
```

An empty `problems` is not a pass. The checks refuse the published attacks
(wrapping, duplicate IDs, DOCTYPE, external references, SHA-1, transforms
that execute code); accepting a document still needs the signature verified
and the reference digest computed by your XML library.

---

## Errors

Every refusal throws a `FormatError` with a stable `code`, the `family`
(module area) and, where it applies, the byte `offset`:

```javascript
import { x509, FormatError } from 'cryptographic-formats';

try {
  x509.from_der(bytes);
} catch (e) {
  if (!(e instanceof FormatError)) throw e;
  e.family   // 'der'
  e.offset   // 47
  e.code     // 'non-minimal-length'
  e.message  // 'cryptographic-formats: der: offset 47: length 5 is written in
             //  two octets where one would do'
}
```

Match on `code`, never on `message` - codes are part of the API, messages
are prose and get reworded. A `TypeError` means the call itself was wrong
(a string where bytes were expected), not the input.

---

## Building a certificate verifier

Path building and trust are yours. What the format can tell you, and where a
verifier written by hand usually gets it wrong - each one checked against
`openssl verify` on the same certificates:

| question | call | matches OpenSSL |
|---|---|---|
| critical extensions you do not enforce | `x509.unenforced_critical(cert, ['basicConstraints', 'keyUsage', ...])` → `[{ id, name }]` (or pass `x509.enforced_set([...])`, resolved once) | RFC 5280 4.2: refuse what is left. *Reading* an extension is not enforcing it, so the list is yours |
| critical extensions OpenSSL refuses | `x509.openssl_unsupported_critical(cert)` → `[{ id, name }]` | error 34 only - including AKI, SKI, AIA, SIA, freshestCRL and issuerAltName, which this library *reads*. Not "nothing left": OpenSSL enforces nsCertType, RFC 3779 and proxyCertInfo by rules this library does not read |
| what was read despite a violation | `cert.warnings` → `[{ code, detail, extension }]` | violations OpenSSL accepts and that cannot be read two ways - an encoded `cA FALSE`, an empty SAN or EKU, a non-prefix IP mask... - are read and listed; what OpenSSL refuses (an all-zero keyUsage, PSS without parameters) is refused |
| a weak signature | `cert.signature_params.weak` (from `algorithm.describe`) | error 68 below the anchor: MD2/MD4/MD5/SHA-1 under RSA (both OIDs), PSS, DSA, ECDSA - and PSS with no `hashAlgorithm`, which is SHA-1 by default |
| name constraints, whole certificate | `x509.name_constraints_check(cert, constraints, { common_name })` → `{ ok, checks, refused, unknown }`, each refused name with `reason` | error 48 (`'excluded'`) or 47 (`'not-permitted'`); a URI with no host under a URI constraint is `unknown` (error 53); a subtree with a minimum or maximum throws `subtree-minmax` (error 49); names counted as OpenSSL counts them; refused above 2^20 comparisons (`NAME_CHECK_MAX`), before any is made |
| is it for this host | `x509.hostname_matches(cert, host)` | RFC 9525: SAN only (CN only with `{ common_name: true }`), `*` only as a whole left-most label, IP literals against iPAddress SANs only; a SAN with a trailing dot matches no host |
| choosing among issuers | `name_matches`, `validity_contains`, the above | see [`examples/chain.mjs`](examples/chain.mjs); ASCII case only, as OpenSSL |
| indexing anchors by subject | `x509.name_key(name)` | equal exactly when `name_matches` says so |
| loading a CA bundle | `pem.decode_skipping(text)` → `{ blocks, skipped }` | a corrupt block is skipped and named, as node skips it; `pem.decode` refuses the whole file |

`name_constraints_permit(constraints, name)` answers for one name. Looping
it over a certificate is what the ceiling exists for: the certificates
choose both counts, and 1,024 × 1,024 directory names took 850ms that way
against about 25ms in `name_constraints_check`.

`x509.from_der` is strict: a negative serial, an explicit DEFAULT such as
`critical FALSE`, or a non-minimal INTEGER is refused, though OpenSSL
accepts them. All 120 system roots parse; a larger corpus has not been
measured yet.

---

## Interoperability notes

Places where this library deliberately follows the standard rather than a
popular implementation:

- **OpenSSL 3.0 and AuthEnvelopedData.** OpenSSL 3.0 reads `authAttrs` as
  `[2]` where RFC 5083 says `[1]`, and requires the GCM ICV length even at
  its DEFAULT of 12. `auth_enveloped_data` writes the RFC; with no `authAttrs` and
  the default 16-byte tag - what OpenSSL writes - the messages interoperate.
- **PBMAC1 needs OpenSSL 3.4 or later** to verify. `pkcs12_build` uses the
  traditional PKCS#12 MAC unless you pass `scheme: 'pbmac1'`.
- **The PBMAC1 password is UTF-8.** RFC 9579 section 6 says BMPString; its
  own test vectors - and every implementation - use the UTF-8 bytes.
- **Post-quantum digests in CMS are written without parameters.** RFC
  9882 3.3 and RFC 9814 4 say the digestAlgorithm beside an ML-DSA or
  SLH-DSA signer MUST omit them; every other signer keeps the NULL that
  deployed verifiers expect. SHA-3 and SHAKE digests never take NULL.
- **ML-KEM private keys: only the seed form is recommended.** The expanded
  and `both` forms are read and written (RFC 9881 6, RFC 9935 6), but this
  library cannot check that an expanded key belongs to its seed - that
  takes the key generation. Such keys come back with `unchecked` saying so;
  the one inconsistency a byte comparison catches (RFC 9935 C.4.1's fourth
  example) is refused.
- **Weak content ciphers are read, and written only on request.** Single
  DES (micromdm's scepclient) is read, marked `weak`, and never written.
  3DES is written only with `{ allow_weak: true }` - for a SCEP client older
  than AES; everyone else gets AES.
- **OpenSSL 3.0 prints PermanentIdentifier and HardwareModuleName as
  `<unsupported>`.** They are checked against the bytes its ASN.1 generator
  writes from a config (`otherName:1.3.6.1.5.5.7.8.4;SEQUENCE:hw`).
- **CMP password MAC** (PBM, RFC 4211) is not PBKDF2: the one-way function
  runs over `secret || salt`, `iterationCount` times in all.
  `cmp.verification_plan` describes it for each message.

---

## Testing and verification

A round trip proves the encoder and decoder agree - not that either is
right. So every encoder is checked against something outside the library:

```
~1,430 unit tests
8,779 Wycheproof vectors        zero disagreements
150 byte comparisons            vs asn1crypto, zero disagreements
1,075 fuzz comparisons          vs asn1crypto, never looser than a BER parser
1.2 million mutated inputs      every decoder; zero exceptions other than
                                FormatError
5,600 canonicalizations         vs libxml2 (lxml), zero disagreements
every post-quantum RFC example  read, and written back byte for byte;
                                ML-DSA signatures verified, and ML-KEM
                                encapsulated and decapsulated, in Python's
                                cryptography (OpenSSL 4)
RFC 9580 appendix A (OpenPGP)   every key, signature and message read,
                                verified or decrypted by node:crypto (EAX,
                                A.9, by cryptographic-primitives), and rebuilt byte for
                                byte; gpg imports, verifies
                                and decrypts what is written here
RFC 8392, 9901 examples         CWT and SD-JWT, checked and rebuilt
OpenSSH's own test data         SSHSIG signatures and certificates, verified
                                and rebuilt byte for byte
120 system root certificates    all parse; all self-signatures verify
                                over tbs_bytes
```

Fixtures are generated by OpenSSL, Python's `cryptography`, `fido2`,
`asn1crypto` and `signxml`, plus the RFC test vectors. The builder tests call
`openssl`, `keytool`, `gpg` and Python (`cryptography`, `pycose`, `asn1crypto`);
tests that need a Python module skip, saying so, when it is absent. EAX,
which node:crypto lacks, comes from cryptographic-primitives, this library's sibling for
the primitives - found by `$CRYPTOFLEX` or in a `cryptographic-primitives` directory next
to this one, and skipped likewise without it. It is never imported by `src/`.

The tests are not in `package.json` - it carries only what is published -
but in `test/run.mjs`:

```bash
node test/run.mjs                 # all unit tests, the examples, and the structural rules
node test/run.mjs fixtures        # regenerate fixtures from openssl + python
node test/run.mjs types-observed  # the declarations against every call the suite makes
node test/run.mjs differential    # regenerate the asn1crypto corpora
node test/run.mjs wycheproof      # needs a Wycheproof checkout
node test/run.mjs duplication     # jscpd
```

---

## Contributing

The architecture is enforced by tests, not by convention -
`test/structure.test.js` reads the source and checks, among other things:

- no reader imports a writer and no writer imports a reader
- module bodies are ES5 (`var`, no arrow functions) inside ESM modules
- only `pkcs12` uses the BER reader
- every path in `package.json` `exports` exists, code and declarations
- every `*.test.js` is in the list `test/run.mjs` runs

One rule matters more than the rest: **a helper may be shared by modules
facing the same direction, never between a reader and its writer.** A bug
in a shared helper cancels out on a round trip and every test passes. Before
sharing, ask: *if this were wrong, would a round trip still pass?* If yes,
it stays duplicated. See [`src/commons/README.md`](src/commons/README.md).

New behaviour needs a test against an outside tool, not only a round trip,
and refusals are asserted by `code`.

[`DECISIONS.md`](DECISIONS.md) records every architectural choice, the
alternatives rejected, and the corrections made when something measured
contradicted something assumed - including every bug an outside tool found.

---

## Versioning

Pre-1.0: the API may change between minor versions (0.x), and changes are
listed in the release notes. Error `code`s are treated as API.

## License

[Apache-2.0](LICENSE)
