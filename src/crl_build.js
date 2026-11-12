// Building certificate revocation lists - RFC 5280 section 5.
//
// ⚠ A CRL IS A CERTIFICATE'S OPPOSITE AND SHARES ALMOST ALL OF ITS SHAPE.
//
//   TBSCertList ::= SEQUENCE {
//        version              Version OPTIONAL,
//        signature            AlgorithmIdentifier,
//        issuer               Name,
//        thisUpdate           Time,
//        nextUpdate           Time OPTIONAL,
//        revokedCertificates  SEQUENCE OF SEQUENCE {
//             userCertificate     CertificateSerialNumber,
//             revocationDate      Time,
//             crlEntryExtensions  Extensions OPTIONAL } OPTIONAL,
//        crlExtensions   [0]  EXPLICIT Extensions OPTIONAL }
//
// Same two calls as everywhere else, because this library does not sign.
//
// ⚠ AND THE THING THAT MAKES CRLs DIFFERENT: AN EMPTY ONE IS MEANINGFUL.
//
// A CRL with no revoked certificates says "nothing is revoked as of
// thisUpdate", and that is a real statement a CA has to publish. The
// revokedCertificates field is OPTIONAL and MUST BE ABSENT rather than an
// empty SEQUENCE - RFC 5280 5.1.2.6 - because an empty SEQUENCE OF is a
// different encoding of the same claim and DER admits only one.
//
// ⚠ AND nextUpdate IS OPTIONAL AND SHOULD NOT BE.
//
// RFC 5280 5.1.2.5 says conforming CRL issuers MUST include it, and the
// field is optional because X.509 predates the advice. A CRL without one
// never expires, so a relying party has nothing telling it to fetch a newer
// one - which is how a revocation stops taking effect.

import * as W from './der_writer.js';
import * as OID from './oid.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, hex, int_bytes } from './commons/bytes.js';

import './pkix.js';
import { time_to_der, algorithm_to_der, name_to_der as pkix_name_to_der,
  attribute_to_der, assemble_signed, extension_to_der, raw_extensions_to_der,
  number_bytes, REASONS }
  from './pkix.js';

var fail = make_fail_here('crl');

// ---------------------------------------------------------------------------
// Reason codes
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

function prepare(parts) {
  if (parts === null || typeof parts !== 'object') {
    fail('bad-input', 'prepare takes an object describing the CRL');
  }

  if (parts.issuer === undefined || parts.issuer === null) {
    fail('missing-issuer',
      'prepare needs { issuer } - hand over the CA certificate\'s subject');
  }

  if (typeof parts.signature_algorithm !== 'string') {
    fail('missing-algorithm',
      'prepare needs { signature_algorithm: "ecdsaWithSHA256" }');
  }

  if (!(parts.this_update instanceof Date)) {
    fail('missing-this-update',
      'prepare needs { this_update: Date } - when this CRL was issued');
  }

  var fields = [];

  // ⚠ VERSION 2 WHENEVER THERE ARE EXTENSIONS, and there always are: a CRL
  // without crlNumber cannot be ordered against another, so a relying party
  // cannot tell an old one from a new one.
  //
  // Encoded as INTEGER 1, and UNTAGGED - unlike a certificate's version,
  // which is [0] EXPLICIT.
  var has_extensions = parts.crl_number !== undefined ||
    (parts.extensions !== undefined && parts.extensions !== null);

  if (has_extensions) {
    fields.push(W.unsigned(new Uint8Array([1])));
  }

  fields.push(algorithm_to_der(parts.signature_algorithm));
  // ⚠ AN ENCODER IS PASSED, UNLIKE IN cms_build.
  //
  // A CMS SignerInfo names a certificate that already exists, so its issuer
  // must match byte for byte and a hand-written name is a mistake. A CRL's
  // issuer is what the CA DECIDES it is called - the same position
  // x509_build takes - so both a parsed name and a written one are meant.
  fields.push(pkix_name_to_der(parts.issuer, attribute_to_der));
  fields.push(time_to_der(parts.this_update));

  if (parts.next_update !== undefined && parts.next_update !== null) {
    if (!(parts.next_update instanceof Date)) {
      fail('bad-next-update', 'next_update is a Date');
    }

    if (parts.next_update.getTime() <= parts.this_update.getTime()) {
      fail('backwards-update',
        'nextUpdate is not after thisUpdate');
    }

    fields.push(time_to_der(parts.next_update));
  }

  var revoked = parts.revoked || [];

  if (!Array.isArray(revoked)) {
    fail('bad-revoked', 'revoked is an array of { serial, date, reason }');
  }

  // ⚠ AN EMPTY LIST IS ABSENT, NOT AN EMPTY SEQUENCE.
  //
  // RFC 5280 5.1.2.6. "Nothing is revoked" is a real statement and it has
  // exactly one encoding - writing an empty SEQUENCE would be a second one,
  // and this library's own reader refuses non-canonical DER.
  if (revoked.length > 0) {
    fields.push(W.sequence(revoked.map(revoked_entry)));
  }

  var extensions = crl_extensions(parts);

  if (extensions !== null) {
    // [0] EXPLICIT, unlike the certificate entry extensions below, which are
    // untagged.
    fields.push(W.explicit(0, extensions));
  }

  var tbs = W.to_bytes(W.sequence(fields));

  return {
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
// Entries
// ---------------------------------------------------------------------------

//   SEQUENCE { userCertificate, revocationDate, crlEntryExtensions OPTIONAL }
function revoked_entry(entry) {
  if (entry === null || typeof entry !== 'object') {
    fail('bad-entry',
      'a revocation is { serial, date, reason }');
  }

  if (entry.serial === undefined) {
    fail('missing-serial', 'a revocation needs the certificate serial');
  }

  if (!(entry.date instanceof Date)) {
    fail('missing-date',
      'a revocation needs { date } - when the certificate was revoked');
  }

  var serial = to_bytes(entry.serial);

  if (serial.length === 0) {
    fail('bad-serial', 'a serial number needs at least one byte');
  }

  var fields = [
    // The serial is a positive INTEGER, the same as in the certificate.
    W.unsigned(serial),
    time_to_der(entry.date)
  ];

  var extensions = entry_extensions(entry);

  if (extensions !== null) {
    // ⚠ UNTAGGED, unlike the CRL-level extensions which are [0] EXPLICIT.
    // The difference is easy to miss and produces a CRL whose entries carry
    // extensions nothing reads.
    fields.push(extensions);
  }

  return W.sequence(fields);
}

function entry_extensions(entry) {
  var out = [];

  if (entry.reason !== undefined && entry.reason !== null) {
    var code = REASONS[entry.reason];

    if (code === undefined) {
      fail('unknown-reason',
        '"' + entry.reason + '" is not a revocation reason. The ten are: ' +
        Object.keys(REASONS).join(', '));
    }

    // ⚠ THE REASON IS AN ENUMERATED, not an INTEGER - RFC 5280 5.3.1. They
    // encode differently (0x0A against 0x02) and a reader expecting one
    // refuses the other.
    out.push(extension('ext_crlReason', false,
      W.to_bytes(W.enumerated(new Uint8Array([code])))));
  }

  if (entry.invalidity_date !== undefined &&
      entry.invalidity_date !== null) {
    if (!(entry.invalidity_date instanceof Date)) {
      fail('bad-invalidity-date', 'invalidity_date is a Date');
    }

    // ⚠ ALWAYS GeneralizedTime - RFC 5280 5.3.2, no 2050 pivot. And it is
    // NOT the revocation date: it is when the key is BELIEVED to have been
    // compromised, which is usually earlier and is what decides whether a
    // signature made last week still counts.
    out.push(extension('ext_invalidityDate', false,
      W.to_bytes(W.generalized_time(entry.invalidity_date))));
  }

  if (entry.certificate_issuer !== undefined &&
      entry.certificate_issuer !== null) {
    fail('indirect-crl',
      'certificateIssuer marks an INDIRECT CRL, where entries name ' +
      'certificates from other issuers. This module does not write one - ' +
      'the extension is critical and getting it wrong makes a CRL that ' +
      'revokes things it does not mean to.');
  }

  return out.length === 0 ? null : W.sequence(out);
}

// ---------------------------------------------------------------------------
// CRL extensions
// ---------------------------------------------------------------------------

function crl_extensions(parts) {
  var out = [];

  if (parts.crl_number !== undefined && parts.crl_number !== null) {
    // ⚠ MONOTONIC, AND THE POINT OF IT.
    //
    // RFC 5280 5.2.3: without a crlNumber a relying party cannot tell one
    // CRL from another, so an attacker can replay an old one and a
    // revocation quietly stops taking effect.
    out.push(extension('ext_crlNumber', false,
      W.to_bytes(W.unsigned(number_bytes(parts.crl_number, 'bad-crl-number',
        'crl_number', fail)))));
  }

  if (parts.authority_key_id !== undefined &&
      parts.authority_key_id !== null) {
    out.push(extension('ext_authorityKeyId', false,
      W.to_bytes(W.sequence([
        W.implicit(0, W.octet_string(to_bytes(parts.authority_key_id)))
      ]))));
  }

  // Raw bytes for anything this module does not write, the same
  // arrangement x509_build makes.
  out = out.concat(raw_extensions_to_der(parts.extensions, fail, 'CRL'));

  return out.length === 0 ? null : W.sequence(out);
}



function extension(name, critical, value) {
  return extension_to_der(name, critical, value, fail);
}


// ---------------------------------------------------------------------------
// Checking
// ---------------------------------------------------------------------------

// What is legal and probably wrong - the same arrangement as x509_build.
function check(parts) {
  var problems = [];

  if (parts.next_update === undefined || parts.next_update === null) {
    problems.push({
      code: 'no-next-update',
      detail: 'RFC 5280 5.1.2.5: conforming CRL issuers MUST include ' +
              'nextUpdate. Without one this CRL never expires, so nothing ' +
              'tells a relying party to fetch a newer one - and a ' +
              'revocation published later never takes effect for them.'
    });
  }

  if (parts.crl_number === undefined || parts.crl_number === null) {
    problems.push({
      code: 'no-crl-number',
      detail: 'RFC 5280 5.2.3: without a crlNumber, one CRL cannot be ' +
              'ordered against another - so an attacker can replay an old ' +
              'one and the revocations added since quietly stop applying.'
    });
  }

  if (parts.authority_key_id === undefined ||
      parts.authority_key_id === null) {
    problems.push({
      code: 'no-authority-key-id',
      detail: 'RFC 5280 5.2.1: a relying party finds the signing key ' +
              'through this, and a CA that has rolled its key has two ' +
              'certificates with the same subject'
    });
  }

  if (parts.next_update && parts.this_update) {
    var days = (parts.next_update - parts.this_update) / 86400000;

    if (days > 365) {
      problems.push({
        code: 'long-validity',
        detail: Math.round(days) + ' days between updates. A revocation ' +
                'published the day after this one takes that long to reach ' +
                'anybody who cached it.'
      });
    }
  }

  var revoked = parts.revoked || [];
  var seen = {};
  var i;

  for (i = 0; i < revoked.length; i++) {
    if (revoked[i].serial === undefined) { continue; }

    var key = hex(to_bytes(revoked[i].serial));

    if (seen[key] === true) {
      problems.push({
        code: 'duplicate-serial',
        detail: 'serial ' + key + ' is revoked twice, with possibly ' +
                'different reasons - and which one a reader takes is ' +
                'undefined'
      });
    }

    seen[key] = true;

    if (revoked[i].date && parts.this_update &&
        revoked[i].date > parts.this_update) {
      problems.push({
        code: 'future-revocation',
        detail: 'serial ' + key + ' is dated after thisUpdate, so this CRL ' +
                'announces a revocation that has not happened yet'
      });
    }
  }

  return problems;
}

export {
  prepare,
  assemble,
  check,
  REASONS
};
