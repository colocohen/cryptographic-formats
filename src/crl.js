// Certificate revocation lists, RFC 5280 section 5.
//
// Without this and OCSP, X.509 verification is incomplete in the way that
// matters: a signature can be perfectly valid on a certificate that was
// revoked years ago, and nothing in the chain says so. A verifier that stops
// at the signature is answering "was this issued?" while the caller asked "is
// this good?".
//
//   CertificateList ::= SEQUENCE {
//        tbsCertList          TBSCertList,
//        signatureAlgorithm   AlgorithmIdentifier,
//        signatureValue       BIT STRING }
//
//   TBSCertList ::= SEQUENCE {
//        version              Version OPTIONAL,
//        signature            AlgorithmIdentifier,
//        issuer               Name,
//        thisUpdate           Time,
//        nextUpdate           Time OPTIONAL,
//        revokedCertificates  SEQUENCE OF SEQUENCE {
//             userCertificate      CertificateSerialNumber,
//             revocationDate       Time,
//             crlEntryExtensions   Extensions OPTIONAL } OPTIONAL,
//        crlExtensions    [0] EXPLICIT Extensions OPTIONAL }
//
// ⚠ THE LIST IS ONLY MEANINGFUL WITH ITS DATES. A CRL that is out of date
// says nothing about what has been revoked since, and treating a stale list
// as authoritative is worse than having none - it produces a confident "not
// revoked" for a certificate revoked last week. So is_current is provided
// alongside the lookup, and the lookup does not imply it.

import * as DER from './der_reader.js';
import * as F from './fields.js';
import * as OID from './oid.js';
import * as ALG from './algorithm.js';

// Imported for its type definitions: RDNSequence, Extension and Extensions.
import * as X509 from './x509.js';


import { to_bytes, hex, int_value, bytes_equal } from './commons/bytes.js';
import { make_fail_here } from './commons/fail.js';

var fail = make_fail_here('crl');


// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

F.define('RevokedCertificate', [
  { name: 'serial',     type: 'integer' },
  { name: 'date',       type: 'time' },
  { name: 'extensions', type: 'Extensions', optional: true }
]);

F.define('RevokedCertificates',
  { kind: 'sequence_of', of: 'RevokedCertificate' });

F.define('TBSCertList', [
  // ⚠ OPTIONAL WITH NO DEFAULT - unlike a certificate's version, which has
  // DEFAULT v1.
  //
  // RFC 5280 section 5.1 says a CRL is v1 when the field is absent, but it
  // says it in PROSE rather than with a DEFAULT clause. The distinction
  // matters: X.690 11.5 forbids encoding a value equal to its DEFAULT, and a
  // field with no DEFAULT has nothing to forbid - so a CRL may legally carry
  // `version 0` where a certificate may not.
  //
  // This table declared `def: 0` for a while, copied from the certificate,
  // which would have refused a legal CRL. Caught by comparing against the
  // ASN.1 module in RFC 5280.
  { name: 'version',    type: 'unsigned', optional: true },
  { name: 'signature',  type: 'AlgorithmIdentifier' },
  { name: 'issuer',     type: 'RDNSequence' },
  { name: 'thisUpdate', type: 'time' },
  { name: 'nextUpdate', type: 'time', optional: true },
  { name: 'revoked',    type: 'RevokedCertificates', optional: true },
  { name: 'extensions', tag: 0xA0, mode: 'explicit', type: 'Extensions',
    optional: true }
]);

// RFC 5280 5.3.1, by name - x509.js's table, which a CMP revocation request
// reads its reason with too.
var REASONS = X509.CRL_REASONS;

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

function from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var list = r.read_sequence();

    // Captured BEFORE parsing, so the bytes are the ones that were signed.
    var tbs_bytes = F.capture(list);
    var tbs = DER.read(tbs_bytes, function (t) {
      return F.read_type(t, 'TBSCertList');
    });

    var sig_alg = F.read_type(list, 'AlgorithmIdentifier');
    var sig = list.read_bit_string();
    list.expect_end();

    if (sig.unused !== 0) {
      fail('bad-signature',
        'the signature BIT STRING has ' + sig.unused + ' unused bits');
    }

    // The same two-copies rule as a certificate, RFC 5280 5.1.1.2: the
    // algorithm inside the TBS must match the outer one, or the CRL's
    // algorithm depends on which copy a verifier reads.
    if (!OID.equal(tbs.signature.algorithm, sig_alg.algorithm)) {
      fail('signature-algorithm-mismatch',
        'the TBS names ' + OID.describe(tbs.signature.algorithm) +
        ' but the CRL names ' + OID.describe(sig_alg.algorithm));
    }
    if (!same_params(tbs.signature.parameters, sig_alg.parameters)) {
      fail('signature-algorithm-mismatch',
        'the TBS and the CRL name the same algorithm with different ' +
        'parameters - see x509.js');
    }

    // Absent means v1, by RFC 5280 5.1's prose rather than by a DEFAULT.
    var version = tbs.version === undefined
      ? 1 : int_value(tbs.version) + 1;

    if (version !== 1 && version !== 2) {
      fail('bad-version', 'CRL version ' + version);
    }
    if (tbs.extensions !== undefined && version !== 2) {
      fail('version-extension-mismatch',
        'CRL extensions require version 2, this list says v' + version);
    }

    // RFC 5280 5.1.2.5: nextUpdate is optional in the syntax and the profile
    // says it SHOULD be present. A list without one cannot be checked for
    // staleness at all, which is worth surfacing rather than treating as
    // "never expires".
    var next = tbs.nextUpdate === undefined ? null : tbs.nextUpdate;

    if (next !== null &&
        next.date.getTime() < tbs.thisUpdate.date.getTime()) {
      fail('bad-validity',
        'nextUpdate is before thisUpdate');
    }

    return {
      version:       version,
      issuer:        tbs.issuer,
      this_update:   tbs.thisUpdate,
      next_update:   next,
      revoked:       read_entries(tbs.revoked),
      extensions:    read_extensions(tbs.extensions),
      signature:     sig.bytes,
      signature_algorithm: OID.name_of(sig_alg.algorithm) ||
                     OID.describe(sig_alg.algorithm),
      // The scheme and hash, and every PSS parameter - see algorithm.js.
      signature_params: ALG.describe_signature(sig_alg, sig.bytes, fail),
      tbs_bytes:     tbs_bytes,
      der:           bytes
    };
  });
}

function read_entries(list) {
  if (list === undefined) {
    // An empty CRL is a valid statement: "nothing is revoked as of
    // thisUpdate". It is NOT the same as a missing list, and the syntax
    // distinguishes them, so an absent field becomes an empty array and the
    // caller cannot tell the difference - which is correct, because the
    // meaning is the same.
    return [];
  }

  var out = [];
  var seen = {};
  var i;

  for (i = 0; i < list.length; i++) {
    var entry = list[i];
    var serial = hex(entry.serial);

    // A serial appearing twice is a list with two revocation dates for one
    // certificate. Whichever a verifier reads first wins, which is the same
    // class of ambiguity as a duplicate extension.
    if (Object.prototype.hasOwnProperty.call(seen, serial)) {
      fail('duplicate-entry',
        'serial ' + serial + ' is revoked twice in this list');
    }
    seen[serial] = true;

    out.push({
      serial: entry.serial,
      serial_hex: serial,
      date: entry.date,
      reason: entry_reason(entry.extensions)
    });
  }

  return out;
}

function entry_reason(extensions) {
  if (extensions === undefined) {
    return null;
  }
  var want = OID.by_name('ext_crlReason');
  var i;
  for (i = 0; i < extensions.length; i++) {
    if (OID.equal(extensions[i].extnID, want)) {
      return X509.read_extension(extensions[i]).parsed;
    }
  }
  return null;
}

function read_extensions(list) {
  if (list === undefined) {
    return [];
  }

  var out = [];
  var i;

  // x509's shape - `id` the dotted OID, `name` without the table's ext_
  // prefix. This returned 'ext_crlNumber' for both.
  for (i = 0; i < list.length; i++) {
    out.push(X509.extension_entry(list[i]));
  }

  return out;
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

// Returns the entry for a serial, or null.
//
// Answering null means "not in THIS list", not "not revoked". Whether the
// list is current is a separate question with a separate function, because
// conflating them produces a confident "not revoked" from a list that stopped
// being updated a year ago.
function find(crl, serial) {
  var want = serial instanceof Uint8Array ? hex(serial)
    : String(serial).toLowerCase().replace(/^0x/, '');

  var i;
  for (i = 0; i < crl.revoked.length; i++) {
    if (crl.revoked[i].serial_hex === want) {
      return crl.revoked[i];
    }
  }
  return null;
}

// Whether the list covers the given moment.
//
// A CRL with no nextUpdate cannot be checked, and this returns false for one
// rather than true: a list that never claims to expire is not a list that is
// always fresh, and the profile says nextUpdate SHOULD be there.
function is_current(crl, when) {
  var t = when === undefined ? new Date() : when;

  if (!(t instanceof Date) || isNaN(t.getTime())) {
    fail('bad-time', 'expected a Date');
  }
  if (crl.next_update === null) {
    return false;
  }

  return t.getTime() >= crl.this_update.date.getTime() &&
         t.getTime() <= crl.next_update.date.getTime();
}

// ---------------------------------------------------------------------------




function same_params(a, b) {
  if (a === undefined || b === undefined) { return a === b; }
  return bytes_equal(a, b);
}

export {
  from_der,
  find,
  is_current,
  REASONS
};
