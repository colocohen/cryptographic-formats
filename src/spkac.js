// SPKAC: Netscape's SignedPublicKeyAndChallenge - what the <keygen> element
// submitted, what `openssl spkac` writes and `openssl ca -spkac` issues from,
// and what node's crypto.Certificate reads (DECISIONS 45).
//
//   SignedPublicKeyAndChallenge ::= SEQUENCE {
//        publicKeyAndChallenge PublicKeyAndChallenge,
//        signatureAlgorithm    AlgorithmIdentifier,
//        signature             BIT STRING }
//
//   PublicKeyAndChallenge ::= SEQUENCE {
//        spki      SubjectPublicKeyInfo,
//        challenge IA5String }
//
// A smaller CSR: a public key, a challenge string the server handed out, and
// a signature by the key over both - which proves possession, as a CSR's
// does. As for every signed structure here, the signed part comes back as
// the bytes that arrived, and verification_plan says what to check.
//
// ⚠ MD5 IS THE DEFAULT. `openssl spkac` signs with md5WithRSAEncryption
// unless given -digest, and browsers did the same. It is read - the request
// exists - and reported as weak through signature_params, as describe_signature
// reports it for a certificate.
//
// The text form is base64 of the DER on one line, as node's
// Certificate.verifySpkac takes it, optionally behind `SPKAC=` - the line
// `openssl spkac` prints and `openssl ca -spkac` reads. Line breaks inside the
// base64 are refused, as node refuses them.

import * as DER from './der_reader.js';
import * as F from './fields.js';
import * as OID from './oid.js';
import * as ALG from './algorithm.js';
import * as SPKI from './spki.js';
import * as B from './base.js';

// Imported for its side effect: AlgorithmIdentifier.
import './pkix.js';

import { to_bytes } from './commons/bytes.js';
import { make_fail_here } from './commons/fail.js';

var fail = make_fail_here('spkac');

function from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var outer = r.read_sequence();

    // Captured BEFORE parsing, so the bytes are the ones that were signed.
    var signed = F.capture(outer);
    var inner = DER.read(signed, function (t) {
      var seq = t.read_sequence();
      var spki = F.capture(seq);
      var challenge = seq.read_ia5_string();
      seq.expect_end();
      return { spki: spki, challenge: challenge };
    });

    var sig_alg = F.read_type(outer, 'AlgorithmIdentifier');
    var sig = outer.read_bit_string();
    outer.expect_end();

    if (sig.unused !== 0) {
      fail('bad-signature',
        'the signature BIT STRING has ' + sig.unused + ' unused bits');
    }

    return {
      public_key:    SPKI.from_der(inner.spki),
      // What the server sent; comparing it with the one it issued is the
      // caller's step - see verification_plan.
      challenge:     inner.challenge,
      signature:     sig.bytes,
      signature_algorithm: OID.name_of(sig_alg.algorithm) ||
                     OID.describe(sig_alg.algorithm),
      signature_params: ALG.describe_signature(sig_alg, sig.bytes, fail),
      tbs_bytes:     signed,
      der:           bytes
    };
  });
}

// The base64 line, with or without `SPKAC=`, as text or as its bytes.
function from_text(input) {
  var text = typeof input === 'string' ? input
    : String.fromCharCode.apply(null, to_bytes(input));

  text = text.replace(/^\s+|\s+$/g, '');
  if (text.indexOf('SPKAC=') === 0) {
    text = text.substring(6);
  }
  if (text === '') {
    fail('bad-input', 'an SPKAC is a base64 line, and this is empty');
  }

  // base.js's strict codec: a line break inside, or bits after the last
  // whole byte, is refused there.
  return from_der(B.decode('base64', text));
}

// What has to be verified, and over which bytes - and the step that is not
// a signature check.
function verification_plan(spkac) {
  return {
    algorithm: spkac.signature_algorithm,
    bytes:     spkac.tbs_bytes,
    signature: spkac.signature,
    key:       spkac.public_key,
    also:      'compare the challenge with the one you issued for this ' +
               'request. The signature proves the key signed THIS challenge; ' +
               'without the comparison, an SPKAC captured from another ' +
               'session verifies just as well.'
  };
}

export {
  from_der,
  from_text,
  verification_plan
};
