// Building certificates.
//
// ⚠ TWO CALLS WITH A SIGNATURE BETWEEN THEM, AND THE NAMES SAY SO.
//
//   var tbs = x509_build.prepare(parts);        // the bytes to sign
//   var sig = flex.sign(alg, key, tbs.bytes);   // not this library
//   var der = x509_build.assemble(tbs, sig);    // the certificate
//
// Every other writer here is `to_der(parts)` in one call. This is not, and
// calling it that would hide the step in the middle - a caller would look
// for the signature parameter and find none.
//
// ⚠ AND `tbs` CARRIES THE BYTES, NOT JUST THE FIELDS.
//
// assemble() takes what build() produced rather than rebuilding it. If it
// re-encoded, any difference of one byte - a re-serialized name, a time
// written differently - would produce a certificate whose signature covers
// something else. It would look correct and fail verification for reasons
// that look like a bad key.
//
// That is the same rule from_der follows in the other direction, where
// tbs_bytes is a slice and never a re-encode.
//
// ⚠ AND A BUILDER THAT MAKES CERTIFICATES EASY MAKES WRONG ONES EASY.
//
// So check() exists separately, and build() refuses the combinations that
// cannot be meant: a CA with no basicConstraints, keyCertSign without ca,
// notAfter before notBefore. What it does NOT do is impose policy - a caller
// who wants a certificate this library thinks is unwise can have one, having
// read the problems.

import * as W from './der_writer.js';
import * as OID from './oid.js';
import * as X509 from './x509.js';
import { time_to_der, algorithm_to_der, assemble_signed,
  validity_to_der as pkix_validity_to_der, validity_days,
  x509_name_to_der as name_to_der, public_key_to_der,
  certificate_extensions_to_der as extensions_to_der,
  KEY_USAGE_ORDER, EKU_NAMES } from './pkix.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, hex, int_bytes, bytes_equal } from './commons/bytes.js';
import * as SPKI from './spki.js';
import { PQ_KEYS } from './ec_domain.js';

var fail = make_fail_here('x509');

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

function prepare(parts) {
  if (parts === null || typeof parts !== 'object') {
    fail('bad-input', 'prepare takes an object describing the certificate');
  }

  require_field(parts, 'serial');
  require_field(parts, 'issuer');
  require_field(parts, 'subject');
  require_field(parts, 'validity');
  require_field(parts, 'public_key');
  require_field(parts, 'signature_algorithm');

  var fields = [];

  // ⚠ VERSION 3, ALWAYS, WHEN THERE ARE EXTENSIONS - and there always are,
  // because a v1 certificate cannot carry basicConstraints and a modern
  // verifier will not build a path through one.
  //
  // The field is [0] EXPLICIT and holds v3 as INTEGER 2.
  fields.push(W.explicit(0, W.unsigned(new Uint8Array([2]))));

  var serial = to_bytes(parts.serial);

  if (serial.length === 0) {
    fail('bad-serial', 'a serial number needs at least one byte');
  }

  // ⚠ THE SERIAL IS A POSITIVE INTEGER, and RFC 5280 4.1.2.2 requires it -
  // so the top bit being set means a leading zero, which unsigned() adds.
  // A negative serial is refused by browsers.
  fields.push(W.unsigned(serial));

  var alg = algorithm_to_der(parts.signature_algorithm);

  // ⚠ THE ALGORITHM APPEARS TWICE, inside the TBS and beside the signature,
  // and RFC 5280 4.1.1.2 requires them to match. Only the inner one is
  // signed, so a mismatch means the outer is unprotected - assemble() writes
  // the same one rather than taking it again.
  fields.push(alg);

  fields.push(name_to_der(parts.issuer));
  fields.push(validity_to_der(parts.validity));
  fields.push(name_to_der(parts.subject));
  fields.push(public_key_to_der(parts.public_key));

  var extensions = extensions_to_der(parts.extensions, parts);

  if (extensions !== null) {
    fields.push(W.explicit(3, extensions));
  }

  var tbs = W.to_bytes(W.sequence(fields));

  return {
    // ⚠ THE BYTES TO SIGN. assemble() takes these back rather than
    // rebuilding, because a re-encode differing by one byte would produce a
    // certificate whose signature covers something else.
    bytes:     tbs,
    signature_algorithm: parts.signature_algorithm,
    parts:     parts
  };
}

// The shape is the same for a certificate, a CRL and an attribute
// certificate - see pkix.assemble_signed.
function assemble(tbs, signature) {
  return assemble_signed(tbs, signature, fail);
}

// ---------------------------------------------------------------------------


function validity_to_der(validity) {
  return pkix_validity_to_der(validity, time_to_der, fail);
}


function self_issued(parts) {
  if (!parts.issuer || !parts.subject) {
    return false;
  }
  try {
    return bytes_equal(W.to_bytes(name_to_der(parts.issuer)),
                       W.to_bytes(name_to_der(parts.subject)));
  } catch (e) {
    return false;
  }
}

// ⚠ THE BYTES A KEY IDENTIFIER IS A HASH OF.
//
// RFC 5280 4.2.1.2 method (1): the SHA-1 of the subjectPublicKey BIT STRING's
// value - NOT the whole SubjectPublicKeyInfo, and not the BIT STRING with
// its unused-bits octet. Hashing either of those gives an identifier that
// is consistent with itself and matches nobody else's, so a chain built
// from it fails to link in every other implementation. RFC 7093 adds the
// SHA-256 variants over the same bytes.
function key_id_input(public_key) {
  // spki.js already reads exactly this - it calls it `point`, because for an
  // EC key that is what it is, and for RSA it is the RSAPublicKey DER. One
  // reader of a SubjectPublicKeyInfo, not two.
  return SPKI.from_der(public_key_to_der(public_key)).point;
}








function require_field(parts, name) {
  if (parts[name] === undefined || parts[name] === null) {
    fail('missing-' + name.replace('_', '-'),
      'prepare needs { ' + name + ' }');
  }
}

// ---------------------------------------------------------------------------
// Checking
// ---------------------------------------------------------------------------

// ⚠ SEPARATE FROM build(), AND THAT IS THE POINT.
//
// build() refuses what cannot be encoded or cannot be meant. check() reports
// what is legal, encodable, and probably a mistake - and returns rather than
// throws, so a caller who knows what they are doing can proceed.
//
// A builder that makes certificates easy makes wrong ones easy, and the
// alternative to this is a builder that imposes policy on people who did not
// ask.
// The public key's algorithm name, for check() - from what spki.from_der
// returned, or from the DER. Null when it cannot be read: check() reports,
// and prepare() is where a bad key is refused.
function key_algorithm(key) {
  if (key && typeof key.algorithm === 'string') { return key.algorithm; }
  if (key instanceof Uint8Array) {
    try { return SPKI.from_der(key).algorithm; } catch (e) { return null; }
  }
  return null;
}

function check(parts) {
  var problems = [];
  var ext = parts.extensions || {};

  if (ext.basicConstraints === undefined) {
    problems.push({
      code: 'no-basic-constraints',
      detail: 'RFC 5280 4.2.1.9: a certificate without basicConstraints is ' +
              'not a CA, and some verifiers will not build a path through ' +
              'one at all. Say { ca: false } if that is what you mean.'
    });
  }

  var is_ca = ext.basicConstraints && ext.basicConstraints.ca === true;
  var usage = ext.keyUsage || [];

  if (is_ca && usage.indexOf('keyCertSign') === -1) {
    problems.push({
      code: 'ca-without-key-cert-sign',
      detail: 'this is a CA and its keyUsage does not include keyCertSign, ' +
              'so it may not sign the certificates it exists to sign'
    });
  }

  if (!is_ca && usage.indexOf('keyCertSign') !== -1) {
    problems.push({
      code: 'key-cert-sign-without-ca',
      detail: 'keyUsage includes keyCertSign and basicConstraints does not ' +
              'say ca. RFC 5280 4.2.1.3 makes this combination invalid, and ' +
              'it is what a path-length attack looks like.'
    });
  }

  if (ext.keyUsage === undefined) {
    problems.push({
      code: 'no-key-usage',
      detail: 'without keyUsage, the key may be used for anything'
    });
  }

  // ⚠ A POST-QUANTUM KEY DOES ONE JOB, AND ITS keyUsage SAYS WHICH.
  //
  // RFC 9881 5 and RFC 9909 6: an ML-DSA or SLH-DSA key signs - any of
  // digitalSignature, nonRepudiation, keyCertSign, cRLSign, and none of
  // the encipherment or agreement bits. RFC 9935 5: an ML-KEM key MUST
  // carry keyEncipherment alone. A certificate saying otherwise is legal
  // DER that the RFCs forbid, so it is reported here, not refused.
  var key_alg = key_algorithm(parts.public_key);
  var family = key_alg && PQ_KEYS[key_alg] ? PQ_KEYS[key_alg].family : null;
  if (family !== null && ext.keyUsage !== undefined) {
    var allowed = family === 'ml-kem' ? ['keyEncipherment']
      : ['digitalSignature', 'nonRepudiation', 'keyCertSign', 'cRLSign'];
    var stray = usage.filter(function (u) { return allowed.indexOf(u) === -1; });
    if (stray.length > 0 || (family === 'ml-kem' && usage.length !== 1)) {
      problems.push({
        code: 'key-usage-for-key',
        detail: family === 'ml-kem'
          ? 'RFC 9935 5: an ML-KEM certificate\'s keyUsage is keyEncipherment ' +
            'and nothing else' + (stray.length ? ' - not ' + stray.join(', ') : '')
          : 'RFC 9881 5 / RFC 9909 6: a ' + key_alg + ' key only signs, so ' +
            'its keyUsage may not include ' + stray.join(', ')
      });
    }
  }

  var serial = parts.serial ? to_bytes(parts.serial) : new Uint8Array(0);

  if (serial.length < 8) {
    problems.push({
      code: 'short-serial',
      detail: 'the CA/Browser Forum requires at least 64 bits of entropy in ' +
              'a serial number, because a predictable serial makes a ' +
              'chosen-prefix collision easier to mount'
    });
  }

  if (serial.length > 0 && serial[0] === 0 && serial.length > 1) {
    problems.push({
      code: 'padded-serial',
      detail: 'the serial starts with a zero byte. That is legal and it ' +
              'wastes entropy - the value is what matters, not the width.'
    });
  }

  var days = validity_days(parts.validity);

  if (days !== null) {
    if (days > 398 && !is_ca) {
      problems.push({
        code: 'long-validity',
        detail: Math.round(days) + ' days. Browsers reject public TLS ' +
                'certificates valid for more than 398.'
      });
    }
  }

  // ⚠ THE KEY IDENTIFIERS, WHICH THIS LIBRARY CANNOT COMPUTE AND SO MUST
  //    REMIND ABOUT.
  //
  // RFC 5280 4.2.1.2: a CA MUST carry subjectKeyIdentifier. 4.2.1.1: every
  // certificate MUST carry authorityKeyIdentifier except a self-signed root.
  // OpenSSL 3 enforces both under -x509_strict, and a chain built by this
  // module without them was refused there while check() said nothing. Both
  // are SHA-1 (or SHA-256, RFC 7093) of key_id_input(key) - the hash is the
  // caller's, the bytes to hash are below.
  if (is_ca && ext.subjectKeyId === undefined) {
    problems.push({
      code: 'no-subject-key-id',
      detail: 'RFC 5280 4.2.1.2: a CA MUST carry subjectKeyIdentifier. Hash ' +
              'key_id_input(public_key) and pass it as subjectKeyId.'
    });
  }

  if (ext.authorityKeyId === undefined && !self_issued(parts)) {
    problems.push({
      code: 'no-authority-key-id',
      detail: 'RFC 5280 4.2.1.1: every certificate but a self-signed root ' +
              'MUST carry authorityKeyIdentifier - the issuer\'s ' +
              'subjectKeyIdentifier, as authorityKeyId: { key_id }.'
    });
  }

  if (!is_ca && ext.subjectAltName === undefined) {
    problems.push({
      code: 'no-subject-alt-name',
      detail: 'RFC 6125 and every browser: the name a TLS certificate is ' +
              'for comes from subjectAltName, and commonName is not read'
    });
  }

  return problems;
}

export {
  prepare,
  assemble,
  check,
  key_id_input,
  KEY_USAGE_ORDER,
  EKU_NAMES
};
