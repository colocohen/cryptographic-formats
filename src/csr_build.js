// Building PKCS#10 certification requests - RFC 2986. csr.js reads them.
//
// The same two calls as every builder here, and the same shapes as
// x509_build - a CSR asks for a certificate, so it is described the way the
// certificate will be:
//
//   var p   = csr_build.prepare({
//     subject:    [{ commonName: 'example.com' }],
//     public_key: spki_der,                   // or what spki.from_der returned
//     extensions: { subjectAltName: [{ dns: 'example.com' }] },
//     signature_algorithm: 'ecdsaWithSHA256'
//   });
//   var der = csr_build.assemble(p, sign(p.bytes));   // signed by the KEY
//
// ⚠ THE SIGNATURE IS BY THE KEY BEING CERTIFIED, not by a CA. It is the
// requester's proof of possession, and a CA that does not verify it (with
// csr.from_der(der).tbs_bytes) certifies keys for people who do not hold
// them.
//
// Extensions travel in an extensionRequest attribute (RFC 2985 5.4.2):
// they are what the requester ASKS for, and csr.from_der reports them as
// `requested`. A CA decides what it grants.

import * as W from './der_writer.js';
import * as OID from './oid.js';

import { make_fail_here } from './commons/fail.js';

import { algorithm_to_der, assemble_signed, public_key_to_der,
  x509_name_to_der as name_to_der,
  certificate_extensions_to_der as extensions_to_der } from './pkix.js';

var fail = make_fail_here('csr');

//   CertificationRequestInfo ::= SEQUENCE {
//      version       INTEGER { v1(0) },
//      subject       Name,
//      subjectPKInfo SubjectPublicKeyInfo,
//      attributes    [0] IMPLICIT Attributes }
function prepare(parts) {
  if (parts === null || typeof parts !== 'object') {
    fail('bad-input', 'prepare takes an object describing the request');
  }
  if (parts.subject === undefined) {
    fail('bad-input', 'prepare needs { subject }, as for x509_build');
  }
  if (parts.public_key === undefined) {
    fail('bad-input', 'prepare needs { public_key }');
  }
  if (typeof parts.signature_algorithm !== 'string') {
    fail('bad-input', 'prepare needs { signature_algorithm }');
  }

  // Validated now, so a bad name fails here and not at assemble().
  algorithm_to_der(parts.signature_algorithm);

  var attributes = [];
  var exts = extensions_to_der(parts.extensions, parts);

  if (exts !== null) {
    attributes.push(W.sequence([
      W.oid(OID.by_name('extensionRequest')),
      W.set_of([exts])
    ]));
  }

  var info = W.sequence([
    W.integer([0x00]),
    name_to_der(parts.subject),
    public_key_to_der(parts.public_key),
    // [0] IMPLICIT, and NOT optional: a request asking for nothing still
    // carries an empty SET.
    W.implicit(0, W.set_of(attributes))
  ]);

  return {
    bytes:               W.to_bytes(info),
    signature_algorithm: parts.signature_algorithm
  };
}

//   CertificationRequest ::= SEQUENCE {
//      certificationRequestInfo  CertificationRequestInfo,
//      signatureAlgorithm        AlgorithmIdentifier,
//      signature                 BIT STRING }
//
// The signature as the algorithm names it - DER for ECDSA, unlike JOSE.
function assemble(prepared, signature) {
  return assemble_signed(prepared, signature, fail);
}

export {
  prepare,
  assemble
};
