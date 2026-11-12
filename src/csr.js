// PKCS#10 certification requests, RFC 2986.
//
// Without this, X.509 is read-only: certificates can be examined and nothing
// can be issued.
//
//   CertificationRequest ::= SEQUENCE {
//        certificationRequestInfo CertificationRequestInfo,
//        signatureAlgorithm       AlgorithmIdentifier,
//        signature                BIT STRING }
//
//   CertificationRequestInfo ::= SEQUENCE {
//        version       INTEGER { v1(0) },
//        subject       Name,
//        subjectPKInfo SubjectPublicKeyInfo,
//        attributes    [0] IMPLICIT Attributes }
//
// The signature is what makes a CSR meaningful: it proves the requester
// controls the private key matching the public key inside. So the signed
// portion comes back as its ORIGINAL bytes, for the same reason a
// certificate's does - a re-encode would change the hash for any request that
// deviates from canonical DER, and the proof would fail to verify.
//
// The attributes are where extensions are requested. A CA is free to ignore
// them, which is worth knowing: a CSR asking for CA:TRUE is a request, not a
// grant, and reading one should not suggest otherwise.

import * as DER from './der_reader.js';
import * as W from './der_writer.js';
import * as F from './fields.js';
import * as OID from './oid.js';
import * as ALG from './algorithm.js';
import * as SPKI from './spki.js';

// Imported for its type definitions: RDNSequence, Extension and Extensions
// are registered when x509.js loads, and a CSR reuses all three.
import * as X509 from './x509.js';


import { to_bytes, to_array, int_value } from './commons/bytes.js';
import { make_fail_here } from './commons/fail.js';

var fail = make_fail_here('csr');


// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

F.define('Attribute', [
  { name: 'type',   type: 'oid' },
  // SET OF AttributeValue, captured whole because what is inside depends on
  // the type OID - the ANY DEFINED BY pattern, resolved a layer up.
  { name: 'values', type: 'raw' }
]);

F.define('Attributes', { kind: 'set_of', of: 'Attribute' });

F.define('CertificationRequestInfo', [
  { name: 'version',    type: 'unsigned' },
  { name: 'subject',    type: 'RDNSequence' },
  { name: 'spki',       type: 'raw' },
  // [0] IMPLICIT Attributes. NOT optional in the syntax - an empty SET is
  // written when there is nothing to request, and a request omitting the
  // field entirely is malformed rather than attribute-free.
  { name: 'attributes', tag: 0xA0, mode: 'implicit', type: 'Attributes' }
]);

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

function from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var req = r.read_sequence();

    // Captured BEFORE parsing, so the bytes are the ones that were signed.
    var info_bytes = F.capture(req);
    var info = DER.read(info_bytes, function (t) {
      return F.read_type(t, 'CertificationRequestInfo');
    });

    var sig_alg = F.read_type(req, 'AlgorithmIdentifier');
    var sig = req.read_bit_string();
    req.expect_end();

    if (sig.unused !== 0) {
      fail('bad-signature',
        'the signature BIT STRING has ' + sig.unused + ' unused bits');
    }

    var version = int_value(info.version);

    // RFC 2986 fixes the version at 0 and there has never been another. A
    // request claiming a version this parser has not been written against is
    // one whose fields may not mean what they appear to.
    if (version !== 0) {
      fail('bad-version',
        'a certification request is version 0, got ' + version);
    }

    return {
      subject:       info.subject,
      public_key:    SPKI.from_der(info.spki),
      attributes:    read_attributes(info.attributes),
      requested:     requested_extensions(info.attributes),
      challenge_password: challenge_password(info.attributes),
      signature:     sig.bytes,
      signature_algorithm: OID.name_of(sig_alg.algorithm) ||
                     OID.describe(sig_alg.algorithm),
      // The scheme and hash, and every PSS parameter - see algorithm.js.
      signature_params: ALG.describe_signature(sig_alg, sig.bytes, fail),
      // The bytes the signature covers: the CertificationRequestInfo as it
      // arrived. Named as in every signed structure here.
      tbs_bytes:     info_bytes,
      der:           bytes
    };
  });
}

function read_attributes(list) {
  var out = [];
  var seen = {};
  var i;

  for (i = 0; i < list.length; i++) {
    var id = OID.describe(list[i].type);

    // RFC 2986: each attribute type appears at most once. Two copies is a
    // request with two answers, and a CA reading the first while a policy
    // check reads the second is the same failure as a duplicate extension.
    if (Object.prototype.hasOwnProperty.call(seen, id)) {
      fail('duplicate-attribute',
        'attribute ' + id + ' appears more than once');
    }
    seen[id] = true;

    out.push({
      id:    id,
      oid:   list[i].type,
      name:  OID.name_of(list[i].type),
      value: list[i].values
    });
  }

  return out;
}

// ⚠ challengePassword (RFC 2985 5.4.1) - the shared secret a SCEP PKCSReq
// carries (RFC 8894 3.3.1). A DirectoryString, single-valued. Returned as
// text so the caller can compare it; comparing it, and refusing a request
// without one, is the caller's - and it travels encrypted only because SCEP
// encrypts the whole request.
function challenge_password(list) {
  var want = OID.by_name('challengePassword');
  var i;
  for (i = 0; i < list.length; i++) {
    if (OID.equal(list[i].type, want)) {
      return DER.read(list[i].values, function (r) {
        var set = r.read_set_of();
        var s = set.read_any_string();
        if (set.remaining() > 0) {
          fail('multi-valued-challenge', 'challengePassword has one value (RFC 2985 5.4.1)');
        }
        return s.value;
      });
    }
  }
  return null;
}

// The extensionRequest attribute, RFC 2985 section 5.4.2, carries the
// extensions the requester is ASKING FOR. A CA may grant, alter or ignore any
// of them, so these are returned under a name that says so rather than beside
// the parsed extensions of a certificate.
function requested_extensions(list) {
  var want;
  try {
    want = OID.by_name('extensionRequest');
  } catch (e) {
    return [];
  }

  var i;
  for (i = 0; i < list.length; i++) {
    if (!OID.equal(list[i].type, want)) {
      continue;
    }

    // The attribute value is a SET OF, holding one Extensions SEQUENCE.
    return DER.read(list[i].values, function (r) {
      var set = r.read_set_of();
      var exts = F.read_type(set, 'Extensions');
      set.expect_end();

      var out = [];
      var j;

      // Duplicates are refused by the Extensions type itself - pkix.js.
      for (j = 0; j < exts.length; j++) {
        // Named as x509.from_der names extensions, and as x509_build and
        // csr_build take them: 'subjectAltName', not 'ext_subjectAltName' -
        // and decoded as x509 decodes them, so `parsed` is the same shape.
        out.push(X509.read_extension(exts[j]));
      }

      return out;
    });
  }

  return [];
}

// The request is written by csr_build.js.

export {
  from_der
};
