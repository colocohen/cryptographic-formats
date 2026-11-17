// X.509 certificates, RFC 5280.
//
// SCOPE, and it is deliberate:
//
//   IN     the full parse, with every extension surfaced individually
//   IN     name_matches, validity_contains, constraint_permits - pure
//          functions over parsed values, no state
//   OUT    chain construction, trust anchors, policy trees
//
// Path building has state and rounds, which is this project's own test for
// what belongs to a protocol library rather than a format one. But parsing
// alone leaves the output nearly useless, and RFC 5280 defines name matching
// and validity precisely enough that they are format semantics rather than
// policy. So the primitives are here and the walk is the caller's.
//
// TWO THINGS THAT MATTER MORE THAN THE REST:
//
// 1. tbs_bytes is the ORIGINAL bytes of the signed portion, never a
//    re-encode. A certificate whose DER deviates from canonical form would
//    hash differently after a round trip and its signature would fail to
//    verify - the bytes that were signed are the bytes that arrived.
//
// 2. An unrecognised CRITICAL extension makes the certificate unusable, per
//    RFC 5280 section 4.2. A parser that skips extensions it does not know is
//    ignoring the issuer saying "you must understand this to use this
//    certificate". Recognised extensions are parsed; unrecognised
//    non-critical ones are recorded; unrecognised critical ones are reported
//    so the caller can refuse.

import * as DER from './der_reader.js';
import * as T from './tags.js';
import * as SCT from './sct.js';
import * as DEVICE from './device_attestation.js';
import * as F from './fields.js';

// Imported for its side effect: pkix.js defines AlgorithmIdentifier,
// RDNSequence, Extension and the other structures PKIX shares.
import './pkix.js';
import * as OID from './oid.js';
import * as ALG from './algorithm.js';
import * as SPKI from './spki.js';

import { to_bytes, bytes_equal, int_value, hex } from './commons/bytes.js';
import { make_fail_here } from './commons/fail.js';
import { parse_ip, parse_cidr } from './commons/ip.js';
import { short_name, short_name_oid } from './commons/rfc4514.js';
import { latin1 } from './commons/decode_text.js';
import { SHORT_NAMES as OPENSSL_NAMES } from './openssl_names.js';

var fail = make_fail_here('x509');


// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------


// AttributeTypeAndValue, RelativeDistinguishedName, RDNSequence, Validity,
// Extension and Extensions now live in pkix.js, imported above. They are
// shared by X.509, CSR, CRL, OCSP and CMS, and each of those used to carry
// its own copy behind an `if (!F.defined(...))` guard - a note saying
// "somebody else may have already done this, and I do not know who".

F.define('TBSCertificate', [
  // ⚠ DEFAULT v1, which is INTEGER 0 - RFC 5280 4.1.2.1.
  //
  // Declaring it lets the field engine refuse an explicitly encoded v1, per
  // X.690 11.5. That check used to be written by hand below, and the same
  // check was written by hand again in crl.js - which is exactly what
  // DECISIONS 2.5 says the engine exists to prevent.
  //
  // Found by comparing this table against the ASN.1 module in RFC 5280: the
  // RFC records a DEFAULT and this table did not, so nothing connected the
  // two hand-written checks to the rule they were both implementing.
  { name: 'version',      tag: 0xA0, mode: 'explicit', type: 'unsigned',
    optional: true, def: 0 },
  { name: 'serialNumber', type: 'integer' },
  { name: 'signature',    type: 'AlgorithmIdentifier' },
  { name: 'issuer',       type: 'RDNSequence' },
  { name: 'validity',     type: 'Validity' },
  { name: 'subject',      type: 'RDNSequence' },
  { name: 'spki',         type: 'raw' },
  { name: 'issuerUID',    tag: 0x81, mode: 'implicit', type: 'bit_string',
    optional: true },
  { name: 'subjectUID',   tag: 0x82, mode: 'implicit', type: 'bit_string',
    optional: true },
  { name: 'extensions',   tag: 0xA3, mode: 'explicit', type: 'CertificateExtensions',
    optional: true }
]);

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

function from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var cert = r.read_sequence();

    // Captured BEFORE parsing, so the bytes are the ones that arrived.
    var tbs_bytes = F.capture(cert);
    var tbs = DER.read(tbs_bytes, function (t) {
      return F.read_type(t, 'TBSCertificate');
    });

    var sig_alg = F.read_type(cert, 'AlgorithmIdentifier');
    var sig     = cert.read_bit_string();
    cert.expect_end();

    if (sig.unused !== 0) {
      fail('bad-signature',
        'the signature BIT STRING has ' + sig.unused + ' unused bits');
    }

    return build(bytes, tbs_bytes, tbs, sig_alg, sig.bytes);
  });
}

function build(der, tbs_bytes, tbs, sig_alg, signature) {
  // RFC 5280 4.1.1.2: the algorithm in the signature field of the TBS must
  // MATCH the one in the outer signatureAlgorithm. They are two copies of one
  // fact, and a certificate where they disagree is one whose signature
  // algorithm depends on which copy a verifier reads - the shape of a
  // substitution attack.
  if (!OID.equal(tbs.signature.algorithm, sig_alg.algorithm)) {
    fail('signature-algorithm-mismatch',
      'the TBS names ' + OID.describe(tbs.signature.algorithm) +
      ' but the certificate names ' + OID.describe(sig_alg.algorithm));
  }

  // ⚠ AND THE PARAMETERS. RFC 5280 4.1.1.2 says the two AlgorithmIdentifiers
  // are the SAME, and for PSS the parameters are half the algorithm: an
  // outer copy saying salt 0 beside a signed inner copy saying salt 32 is
  // the same substitution with one more step. Compared as bytes - NULL and
  // absent are different spellings, and the two copies must not differ even
  // in spelling.
  var p_in = tbs.signature.parameters;
  var p_out = sig_alg.parameters;
  if ((p_in === undefined) !== (p_out === undefined) ||
      (p_in !== undefined && !bytes_equal(p_in, p_out))) {
    fail('signature-algorithm-mismatch',
      'the TBS and the certificate name the same algorithm with different ' +
      'parameters');
  }

  // An omitted DEFAULT comes back as the declared value, so this is 0 for a
  // v1 certificate whether the field was present or not.
  var version = int_value(tbs.version) + 1;

  if (version < 1 || version > 3) {
    fail('bad-version', 'certificate version ' + version);
  }

  // RFC 5280 4.1.2.1: version MUST be v3 when extensions are present, and the
  // DEFAULT means v1 must omit the field rather than encode 0.
  if (tbs.extensions !== undefined && version !== 3) {
    fail('version-extension-mismatch',
      'extensions require version 3, but this certificate says v' + version);
  }

  var out = {
    version:       version,
    serial:        tbs.serialNumber,
    issuer:        tbs.issuer,
    subject:       tbs.subject,
    // Named as the builders take it. The ASN.1 field names are notBefore
    // and notAfter; the library's names are snake_case throughout.
    validity:      { not_before: tbs.validity.notBefore,
                     not_after:  tbs.validity.notAfter },
    public_key:    SPKI.from_der(tbs.spki),
    signature:     signature,
    signature_algorithm: OID.name_of(sig_alg.algorithm) ||
                   OID.describe(sig_alg.algorithm),
    // The scheme, hash and - for PSS - every parameter a verifier needs.
    signature_params: ALG.describe_signature(sig_alg, signature, fail),
    tbs_bytes:     tbs_bytes,
    der:           der,
    extensions:    [],
    unhandled_critical: [],
    // Profile violations that were READ rather than refused, each with a
    // written reason at the place it is detected. Empty for a conforming
    // certificate.
    warnings:      []
  };

  // ⚠ A NEGATIVE SERIAL IS READ, WITH A WARNING. RFC 5280 4.1.2.2 makes
  // serials positive and then: "Certificate users SHOULD be prepared to
  // gracefully handle such certificates." It was refused, and OpenSSL and
  // Node read it - so a peer's certificate that every TLS stack accepts
  // could not be shown. Two's complement has one reading: `serial` is the
  // bytes as encoded, and the warning says the sign bit is set. Comparing
  // serials compares those bytes, as the issuer's records hold them.
  if ((tbs.serialNumber[0] & 0x80) !== 0) {
    out.warnings.push({ code: 'negative-serial',
      detail: 'the serial number is negative; RFC 5280 4.1.2.2 requires a positive one' });
  }

  ['not_before', 'not_after'].forEach(function (k) {
    if (out.validity[k].profile_violation !== undefined) {
      out.warnings.push({
        code:   out.validity[k].profile_violation,
        detail: k + ' is a GeneralizedTime for ' + out.validity[k].year +
                '; RFC 5280 4.1.2.5 requires UTCTime before 2050'
      });
    }
  });

  if (tbs.extensions !== undefined) {
    if (tbs.extensions.length === 0) {
      out.warnings.push({ code: 'empty-extensions',
        detail: 'the extensions list is present and empty; RFC 5280 4.1 requires at least ' +
          'one - OpenSSL 3.0 writes this when every extension line is =none' });
    }
    read_extensions(out, tbs.extensions);
  }

  return out;
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// The extensions that say WHERE TO GO NEXT
// ---------------------------------------------------------------------------

// ⚠ THESE TWO ARE HOW A VERIFIER FINDS THE OCSP RESPONDER AND THE CRL.
//
// This library had ocsp.js and crl.js before it had either of these - which
// meant it could read a revocation answer and not find out where to ask.
//
//   AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
//
//   AccessDescription ::= SEQUENCE {
//        accessMethod    OBJECT IDENTIFIER,
//        accessLocation  GeneralName }
//
// RFC 5280 4.2.2.1 says this extension MUST be non-critical, and that is
// checked: a CA marking it critical is saying a relying party must understand
// a hint about where to fetch things, which is not something a hint can
// demand.
function info_access(value) {
  return sequence_of(value, access_description,
    'empty-info-access', 'an info access extension with no descriptions');
}

function access_description(r) {
  var d = r.read_sequence();
  var method = d.read_oid();
  var location = general_name(d);
  d.expect_end();

  return {
    method: OID.name_of(method) || OID.to_string(method),
    method_oid: method,
    location: location
  };
}

// The URIs for one access method, which is what a caller actually wants:
// `ocsp_urls(cert)` rather than a walk over descriptions.
function access_urls(cert, extension_name, method) {
  var ext = extension(cert, extension_name);

  if (ext === null || ext.parsed === null) {
    return [];
  }

  var out = [];
  var i;

  for (i = 0; i < ext.parsed.length; i++) {
    if (ext.parsed[i].method === method &&
        ext.parsed[i].location.type === 'uri') {
      out.push(ext.parsed[i].location.value);
    }
  }

  return out;
}

// Where to ask whether this certificate is revoked.
function ocsp_urls(cert) {
  return access_urls(cert, 'ext_authorityInfoAccess', 'ad_ocsp');
}

// Where to fetch the issuer's certificate, for a chain with a gap in it.
function issuer_urls(cert) {
  return access_urls(cert, 'ext_authorityInfoAccess', 'ad_caIssuers');
}

// ⚠ A PRECERTIFICATE MUST NOT BE SERVED, and this is how to tell.
function is_precertificate(cert) {
  return extension(cert, 'ext_precert_poison') !== null;
}

// Where to fetch the CRL.
//
// ⚠ RETURNS THE COMPLETE POINTS ONLY BY DEFAULT.
//
// A distribution point carrying `reasons` covers SOME revocation reasons and
// not others, so a verifier that fetched one and found nothing would conclude
// the certificate is good while another CRL says otherwise. Pass
// { partial: true } to get those as well, having decided what to do about it.
function crl_urls(cert, options) {
  var opts = options || {};
  var ext = extension(cert, 'ext_crlDistribution');

  if (ext === null || ext.parsed === null) {
    return [];
  }

  var out = [];
  var i, j;

  for (i = 0; i < ext.parsed.length; i++) {
    var point = ext.parsed[i];

    if (point.partial && opts.partial !== true) {
      continue;
    }

    for (j = 0; j < point.names.length; j++) {
      if (point.names[j].type === 'uri') {
        out.push(point.names[j].value);
      }
    }
  }

  return out;
}

//   CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
//
//   DistributionPoint ::= SEQUENCE {
//        distributionPoint  [0] DistributionPointName OPTIONAL,
//        reasons            [1] ReasonFlags OPTIONAL,
//        cRLIssuer          [2] GeneralNames OPTIONAL }
//
// ⚠ A distribution point with `reasons` covers only SOME revocation reasons,
// and a verifier that fetched it and found nothing would conclude the
// certificate is good when another CRL says otherwise. So the reasons are
// reported rather than dropped, and a caller checking one point must know
// whether it is partial.
// RFC 5280 5.3.1. The reason is advisory - a verifier must treat a
// revocation as final regardless - but keyCompromise and certificateHold
// mean very different things operationally, and the second can be lifted.
// Here, not in crl.js, so a CMP revocation request reads its reason the
// same way; crl.js exports it as REASONS.
var CRL_REASONS = [
  'unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged',
  'superseded', 'cessationOfOperation', 'certificateHold', null,
  'removeFromCRL', 'privilegeWithdrawn', 'aACompromise'
];

// The reason by name, or 'reason-N' for a number RFC 5280 does not name.
// An ENUMERATED, which shares INTEGER's encoding but not its tag.
function crl_reason(value) {
  return DER.read(value, function (r) {
    var v = r.read_enumerated();
    var n = v.length === 1 ? v[0] : -1;
    return CRL_REASONS[n] === undefined || CRL_REASONS[n] === null
      ? 'reason-' + n : CRL_REASONS[n];
  });
}

// RFC 5280 5.3.2: when the key is known or suspected to have been
// compromised - a GeneralizedTime, which may be earlier than the revocation.
function invalidity_date(value) {
  return DER.read(value, function (r) {
    return r.read_generalized_time();
  });
}

function crl_distribution_points(value) {
  return sequence_of(value, distribution_point,
    'empty-distribution-points',
    'a CRL distribution points extension with no points');
}

function distribution_point(r) {
  var dp = r.read_sequence();
  var out = { names: [], reasons: null, issuer: null, partial: false };

  if (dp.peek_tag() === 0xA0) {
    var wrapper = dp.read_explicit(0);

    //   DistributionPointName ::= CHOICE {
    //        fullName                 [0] GeneralNames,
    //        nameRelativeToCRLIssuer  [1] RelativeDistinguishedName }
    if (wrapper.peek_tag() === 0xA0) {
      var full = wrapper.read_implicit(0, 0x30);
      while (full.remaining() > 0) {
        out.names.push(general_name(full));
      }
    } else if (wrapper.peek_tag() === 0xA1) {
      var rel = wrapper.read_implicit(1, 0x31);
      out.relative = null;
      // The relative form names a point under the CRL issuer's own name, so
      // it cannot be resolved without that name - kept whole.
      out.relative_raw = rel.buf.subarray(rel.pos, rel.end);
      rel.pos = rel.end;
    }

    wrapper.expect_end();
  }

  if (dp.peek_tag() === 0x81) {
    var bits = dp.read_implicit(1, 0x03);
    out.reasons = reason_flags(bits.bytes);
    // ⚠ A point that covers only some reasons is NOT the whole answer.
    out.partial = true;
  }

  if (dp.peek_tag() === 0xA2) {
    var issuer = dp.read_implicit(2, 0x30);
    out.issuer = [];
    while (issuer.remaining() > 0) {
      out.issuer.push(general_name(issuer));
    }
  }

  dp.expect_end();
  return out;
}

// RFC 5280 4.2.1.13. The bit numbering is the CRLReason numbering minus the
// two that have no flag, which is why this is a table rather than an index.
var REASON_FLAGS = [
  'unused', 'keyCompromise', 'cACompromise', 'affiliationChanged',
  'superseded', 'cessationOfOperation', 'certificateHold',
  'privilegeWithdrawn', 'aACompromise'
];

function reason_flags(bytes) {
  var out = [];
  var i;

  // The first octet of a BIT STRING's value here is already stripped by
  // read_implicit, so bytes[0] is the unused-bit count.
  var unused = bytes.length > 0 ? bytes[0] : 0;
  var content = bytes.subarray(1);
  var total = content.length * 8 - unused;

  for (i = 0; i < total; i++) {
    if (((content[Math.floor(i / 8)] >> (7 - (i % 8))) & 1) === 1) {
      out.push(REASON_FLAGS[i] === undefined ? 'bit-' + i : REASON_FLAGS[i]);
    }
  }

  return out;
}

// ---------------------------------------------------------------------------
// The policy extensions
// ---------------------------------------------------------------------------

//   AuthorityKeyIdentifier ::= SEQUENCE {
//        keyIdentifier              [0] IMPLICIT KeyIdentifier OPTIONAL,
//        authorityCertIssuer        [1] IMPLICIT GeneralNames OPTIONAL,
//        authorityCertSerialNumber  [2] IMPLICIT INTEGER OPTIONAL }
//
// How a verifier picks the right issuer certificate when several share a
// subject name - which happens every time a CA rolls its key.
function authority_key_id(value) {
  return DER.read(value, function (r) {
    var seq = r.read_sequence();
    var out = { key_id: null, issuer: null, serial: null };

    if (seq.peek_tag() === 0x80) {
      out.key_id = seq.read_implicit(0, 0x04).bytes;
    }
    if (seq.peek_tag() === 0xA1) {
      var names = seq.read_implicit(1, 0x30);
      out.issuer = [];
      while (names.remaining() > 0) {
        out.issuer.push(general_name(names));
      }
    }
    if (seq.peek_tag() === 0x82) {
      out.serial = seq.read_implicit(2, 0x02).bytes;
    }

    seq.expect_end();

    // RFC 5280 4.2.1.1: issuer and serial travel together or not at all -
    // one without the other identifies nothing.
    if ((out.issuer === null) !== (out.serial === null)) {
      fail('incomplete-authority-key-id',
        'authorityCertIssuer and authorityCertSerialNumber must both be ' +
        'present or both absent');
    }

    return out;
  });
}

//   certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
//
//   PolicyInformation ::= SEQUENCE {
//        policyIdentifier  OBJECT IDENTIFIER,
//        policyQualifiers  SEQUENCE SIZE (1..MAX) OF
//                            PolicyQualifierInfo OPTIONAL }
function certificate_policies(value) {
  return DER.read(value, function (r) {
    var seq = r.read_sequence();
    var out = [];
    var seen = {};

    while (seq.remaining() > 0) {
      var info = seq.read_sequence();
      var oid = info.read_oid();
      var id = OID.to_string(oid);

      // RFC 5280 4.2.1.4: a policy identifier appears at most once. Two
      // entries for one policy is a certificate making two statements about
      // the same thing.
      if (Object.prototype.hasOwnProperty.call(seen, id)) {
        fail('duplicate-policy',
          'policy ' + id + ' appears more than once');
      }
      seen[id] = true;

      var entry = {
        id: id,
        name: OID.name_of(oid),
        // ⚠ anyPolicy is the wildcard, and inhibitAnyPolicy exists to switch
        // it off - so a caller applying policy rules has to know which one
        // this is.
        any: id === '2.5.29.32.0',
        qualifiers: []
      };

      if (info.remaining() > 0) {
        var quals = info.read_sequence();
        while (quals.remaining() > 0) {
          entry.qualifiers.push(policy_qualifier(quals));
        }
      }

      info.expect_end();
      out.push(entry);
    }

    if (out.length === 0) {
      fail('empty-policies', 'a certificatePolicies extension with no policies');
    }
    return out;
  });
}

function policy_qualifier(r) {
  var q = r.read_sequence();
  var oid = q.read_oid();
  var name = OID.name_of(oid);

  var out = { id: OID.to_string(oid), name: name, value: null };

  if (name === 'policy_qualifier_cps') {
    // A CPS pointer is an IA5String URI.
    var s = q.read_ia5_string();
    out.value = s;
  } else {
    // A user notice is a structure with optional parts; kept whole rather
    // than guessed at, because displaying it is a caller's decision.
    out.value = F.capture(q);
  }

  q.expect_end();
  return out;
}

//   PolicyConstraints ::= SEQUENCE {
//        requireExplicitPolicy  [0] IMPLICIT SkipCerts OPTIONAL,
//        inhibitPolicyMapping   [1] IMPLICIT SkipCerts OPTIONAL }
// ⚠ BOTH FIELDS ARE [n] IMPLICIT INTEGER, AND THEY WERE READ AS RAW BYTES.
//
// read_implicit(...).bytes skipped every INTEGER rule: empty content read as
// 0, a padded 00 05 as 5, and 0x80 as 128 - so a negative count, which is
// malformed, became "128 certificates before the policy is required". The
// fields table reads them as `unsigned`, through the same reader as every
// other INTEGER.
F.define('PolicyConstraints', [
  { name: 'require_explicit', tag: 0x80, mode: 'implicit', type: 'unsigned',
    optional: true },
  { name: 'inhibit_mapping',  tag: 0x81, mode: 'implicit', type: 'unsigned',
    optional: true }
]);

function policy_constraints(value) {
  return DER.read(value, function (r) {
    var pc = F.read_type(r, 'PolicyConstraints');
    var out = {
      require_explicit: pc.require_explicit === undefined
        ? null : int_value(pc.require_explicit, 'requireExplicitPolicy'),
      inhibit_mapping:  pc.inhibit_mapping === undefined
        ? null : int_value(pc.inhibit_mapping, 'inhibitPolicyMapping')
    };
    // RFC 5280 4.2.1.11: at least one field must be present. An empty one
    // constrains nothing while claiming to be a constraint.
    if (out.require_explicit === null && out.inhibit_mapping === null) {
      fail('empty-policy-constraints',
        'a policyConstraints extension with neither field set');
    }

    return out;
  });
}

//   PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
//        issuerDomainPolicy   CertPolicyId,
//        subjectDomainPolicy  CertPolicyId }
function policy_mappings(value) {
  return DER.read(value, function (r) {
    var seq = r.read_sequence();
    var out = [];

    while (seq.remaining() > 0) {
      var m = seq.read_sequence();
      var issuer = m.read_oid();
      var subject = m.read_oid();
      m.expect_end();

      // RFC 5280 4.2.1.5: neither may be anyPolicy. Mapping the wildcard
      // would make every policy equivalent to every other.
      if (OID.to_string(issuer) === '2.5.29.32.0' ||
          OID.to_string(subject) === '2.5.29.32.0') {
        fail('any-policy-mapped',
          'anyPolicy must not appear in a policy mapping');
      }

      out.push({
        issuer: OID.to_string(issuer),
        subject: OID.to_string(subject)
      });
    }

    if (out.length === 0) {
      fail('empty-policy-mappings', 'a policyMappings extension with no maps');
    }
    return out;
  });
}

// A bare INTEGER: how many certificates may follow before anyPolicy stops
// being accepted.
function skip_certs(value) {
  return DER.read(value, function (r) {
    return int_value(r.read_unsigned(), 'skipCerts');
  });
}

function sct_list(value) {
  return SCT.from_extension(value);
}

// ⚠ A PRECERTIFICATE IS NOT A CERTIFICATE, AND THIS EXTENSION SAYS SO.
//
// RFC 6962 3.1: a precertificate carries a CRITICAL extension with a NULL
// value, whose only purpose is that every conforming implementation refuses
// the certificate. It exists so a precertificate - which is submitted to
// logs before issuance and is signed by the real CA - cannot be presented as
// the real thing.
//
// So this is READ and then flagged: the certificate parses, and
// `is_precertificate` says it must not be used.
function precert_poison(value) {
  DER.read(value, function (r) {
    r.read_null();
  });

  return {
    poison: true,
    note: 'this is a PRECERTIFICATE, not a certificate. RFC 6962 3.1 makes ' +
          'the poison extension critical so that every conforming ' +
          'implementation refuses it - it exists to be submitted to CT logs ' +
          'and never to be served.'
  };
}

// Handlers are called with (value, entry); the device readers take the value.
function apple_text(v) { return DEVICE.apple_text(v); }

// Handlers for the extensions this module understands. Anything not here is
// recorded rather than parsed - and if it is critical, recorded in
// unhandled_critical, which is what makes the certificate unusable.
var HANDLERS = {
  ext_basicConstraints:  basic_constraints,
  ext_keyUsage:          key_usage,
  ext_extKeyUsage:       extended_key_usage,
  ext_subjectAltName:    subject_alt_name,
  ext_issuerAltName:     subject_alt_name,
  ext_subjectKeyId:      key_identifier,
  ext_nameConstraints:   name_constraints,

  // ⚠ Added after a sweep counted the table against RFC 5280 and found SEVEN
  // of sixteen. The gap that mattered: this library had ocsp.js and crl.js
  // before it had either of the extensions that say WHERE TO ASK.
  ext_authorityKeyId:    authority_key_id,
  ext_authorityInfoAccess: info_access,
  ext_subjectInfoAccess: info_access,
  ext_crlDistribution:   crl_distribution_points,
  // Entry extensions - a CRL entry's, and a CMP revocation request's
  // crlEntryDetails, which are the same two.
  ext_crlReason:         crl_reason,
  ext_invalidityDate:    invalidity_date,
  ext_freshestCRL:       crl_distribution_points,
  ext_certificatePolicy: certificate_policies,
  ext_policyConstraints: policy_constraints,
  ext_policyMappings:    policy_mappings,
  ext_inhibitAnyPolicy:  skip_certs,

  // ⚠ THE ONE EXTENSION WHOSE BODY IS NOT ASN.1.
  //
  // RFC 6962 was written by the TLS working group and reuses TLS's
  // presentation language - length-prefixed, big-endian, no tags - wrapped
  // in an OCTET STRING so X.509 can carry it. sct.js has its own reader for
  // exactly that reason.
  ext_sct_list:          sct_list,
  ext_precert_poison:    precert_poison,

  // A device's attestation (device_attestation.js, DECISIONS 34).
  ext_appleNonce:        function (v) { return DEVICE.apple_nonce(v); },
  ext_appleSerialNumber: apple_text,
  ext_appleUdid:         apple_text,
  ext_appleOsVersion:    apple_text,
  ext_appleSepOsVersion: apple_text,
  ext_appleLlbVersion:   apple_text,
  ext_appleFreshnessCode: function (v) { return DEVICE.apple_bytes(v); },
  ext_androidKeyDescription: function (value) { return DEVICE.key_description(value, warn); }
};

// ⚠ WHAT OPENSSL WILL REFUSE AS AN UNHANDLED CRITICAL EXTENSION.
//
// unhandled_critical lists the critical extensions THIS module cannot read.
// That is not the list a verifier needs: this module reads AKI, SKI, AIA,
// SIA, freshestCRL and issuerAltName, so they are never "unhandled" here -
// and OpenSSL and BoringSSL refuse every one of them when it is critical
// (X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION, error 34). A verifier built on
// this library that went by unhandled_critical accepted certificates
// node:tls refuses.
//
// The set is OpenSSL's X509_supported_extension, and each entry was probed
// with `openssl verify` (3.0.13): a leaf carrying it critical, error 34 or
// not. RFC 3779's two and proxyCertInfo pass the critical check and fail on
// their own rules (errors 46 and 40) - they are supported, as here.
var OPENSSL_SUPPORTED = [
  '2.5.29.15',                  // keyUsage
  '2.5.29.17',                  // subjectAltName
  '2.5.29.19',                  // basicConstraints
  '2.5.29.30',                  // nameConstraints
  '2.5.29.31',                  // cRLDistributionPoints
  '2.5.29.32',                  // certificatePolicies
  '2.5.29.33',                  // policyMappings
  '2.5.29.36',                  // policyConstraints
  '2.5.29.37',                  // extKeyUsage
  '2.5.29.54',                  // inhibitAnyPolicy
  '2.16.840.1.113730.1.1',      // Netscape certificate type
  '1.3.6.1.5.5.7.1.7',          // RFC 3779 IP address blocks
  '1.3.6.1.5.5.7.1.8',          // RFC 3779 AS identifiers
  '1.3.6.1.5.5.7.1.14',         // proxyCertInfo
  '1.3.6.1.5.5.7.48.1.5'        // OCSP noCheck
];

// The critical extensions of `cert` outside that set, as { id, name } -
// empty when OpenSSL would not refuse the certificate for this reason.
//
// ⚠ IT ANSWERS "WOULD OPENSSL SAY ERROR 34", AND NOTHING MORE. Four of the
// set - Netscape certificate type, RFC 3779's two, proxyCertInfo - and OCSP
// noCheck are ones OpenSSL accepts critical because it ENFORCES them, by
// rules of its own (nsCertType limits purposes; RFC 3779 resources must
// nest, error 46; proxy certificates need a flag, error 40). This library
// reads none of the first four. A verifier that takes an empty list here as
// "nothing critical left unchecked" accepts what OpenSSL refuses (reported
// from lemon). For that question use unenforced_critical, with the list of
// extensions the verifier itself enforces.
function openssl_unsupported_critical(cert) {
  return cert.extensions.filter(function (e) {
    return e.critical && OPENSSL_SUPPORTED.indexOf(e.id) === -1;
  }).map(function (e) {
    return { id: e.id, name: e.name };
  });
}

// The critical extensions of `cert` that `enforced` - the extensions the
// CALLER enforces, by name ('basicConstraints') or dotted OID - does not
// cover, as { id, name }. RFC 5280 4.2: a certificate with one must be
// refused. Reading an extension is not enforcing it, so this library has no
// default for the list; a name it does not know is refused, since a typo
// would otherwise leave that extension unenforced and unreported.
//
// `enforced` is the list, or what enforced_set made of it once: resolving
// the names is the costly part, and a verifier asks for every certificate
// of every chain with the same list (reported from lemon).
function unenforced_critical(cert, enforced) {
  var set = enforced !== null && typeof enforced === 'object' && !Array.isArray(enforced) &&
    enforced.enforced_ids !== undefined ? enforced : enforced_set(enforced);
  return cert.extensions.filter(function (e) {
    return e.critical && set.enforced_ids[e.id] !== true;
  }).map(function (e) {
    return { id: e.id, name: e.name };
  });
}

// The list, resolved to dotted OIDs once - for unenforced_critical.
function enforced_set(enforced) {
  if (!Array.isArray(enforced)) {
    fail('bad-enforced', 'pass the extensions you enforce, by name or dotted OID');
  }
  var ids = {};
  enforced.forEach(function (n) {
    var dotted;
    try {
      dotted = OID.to_string(extension_oid(n));
    } catch (e) {
      fail('unknown-extension', '"' + n + '" is not an extension name this library knows; ' +
        'pass its dotted OID');
    }
    ids[dotted] = true;
  });
  return { enforced_ids: ids };
}

function read_extensions(out, list) {
  var i;

  for (i = 0; i < list.length; i++) {
    var ext = list[i];
    var name = OID.name_of(ext.extnID);
    var id = OID.describe(ext.extnID);

    // (RFC 5280 4.2's "at most once" is enforced by the Extensions type in
    // pkix.js, for every format that uses it.)

    // ⚠ `name` IS THE NAME x509_build TAKES - 'subjectAltName', not the
    // OID table's 'ext_subjectAltName' - so what is read can be written
    // back under the same key. `id` is the dotted OID, for the ones with
    // no name.
    var entry = read_extension(ext);

    if ((name === null || HANDLERS[name] === undefined) && ext.critical) {
      // RFC 5280 4.2: a certificate-using system MUST reject the certificate
      // if it encounters a critical extension it does not recognise. The
      // issuer is saying "you must understand this to use this certificate",
      // and silently continuing is ignoring them.
      out.unhandled_critical.push(id);
    }

    (entry.warnings || []).forEach(function (w) {
      out.warnings.push({ code: w.code, detail: w.detail, extension: entry.name || entry.id });
    });
    out.extensions.push(entry);
  }
}

// Convenience: the parsed value of an extension by name, or null.
// The OID table's extension names carry an 'ext_' prefix, to keep them
// apart from the attribute and algorithm names in the same table. The
// prefix is not part of the extension's name.
function extension_name(table_name) {
  if (table_name === null) {
    return null;
  }
  return table_name.indexOf('ext_') === 0 ? table_name.slice(4) : table_name;
}

// ⚠ ONE SHAPE FOR AN EXTENSION, IN EVERY READER.
//
// csr, crl, attrcert and crmf each built their own entry, and three of the
// four disagreed with this one: crl returned id 'ext_crlNumber' where this
// returns the dotted OID, attrcert and crmf kept the ext_ prefix in `name`
// and had no `oid`. A caller who learned the shape here found nothing there.
// Writing one TypeScript type for all of them is what showed it.
//
// `ext` is an Extension as the field tables read it.
function extension_entry(ext) {
  return {
    id:       OID.to_string(ext.extnID),
    name:     extension_name(OID.name_of(ext.extnID)),
    oid:      ext.extnID,
    critical: ext.critical === true,
    value:    ext.extnValue
  };
}

// An extension entry with its value decoded, for the extensions this module
// reads; `parsed` is null for the rest. A certificate's extensions are read
// with it, and so are the ones a CSR or a CRMF template asks for - the same
// SAN is the same bytes in all three, and one reader decodes it.
//
// Violations a handler reads rather than refuses (see warn) land in
// `warnings` on the entry - present only when there are any - and a
// certificate collects them into its own.
function read_extension(ext) {
  var entry = extension_entry(ext);
  var name = OID.name_of(ext.extnID);
  var handler = name === null ? undefined : HANDLERS[name];
  var saved = WARNINGS;
  WARNINGS = [];
  try {
    entry.parsed = handler === undefined ? null : handler(ext.extnValue, entry);
    if (WARNINGS.length > 0) {
      entry.warnings = WARNINGS;
    }
  } finally {
    WARNINGS = saved;
  }
  return entry;
}

// ⚠ READ, AND SAY SO - FOR WHAT OPENSSL ACCEPTS AND WHOSE MEANING IS PLAIN.
//
// The handlers refused every profile violation, and a verifier built on
// them refused certificates node:tls accepts (reported from lemon). Each
// was put to `openssl verify` (3.0.13); the ones it accepts, and that
// cannot be read two ways, are now warnings with the same code:
//
//   non-canonical-default   cA FALSE encoded, or a subtree minimum of 0
//   path-len-without-ca     pathLenConstraint with cA absent
//   empty-ext-key-usage     no purposes - which then permits none
//   empty-alt-name          no names
//   bad-ia5-string          a byte above 0x7F in an IA5String name, read
//                           as Latin-1 and so matching no ASCII name
//   bad-ip-mask             a constraint mask that is not a prefix -
//                           matched bit by bit, as OpenSSL does
//   subtree-minmax          a subtree with a minimum or maximum; checking
//                           against it fails (name_constraints_check),
//                           as OpenSSL fails it with error 49
//
// Still refused, because OpenSSL refuses them too: an all-zero keyUsage
// (it marks the certificate invalid) and RSASSA-PSS without parameters
// (it cannot verify the signature). And anything that does not parse.
//
// Only while an extension is read: elsewhere - a GeneralName in a CRL or
// an OCSP response - warn() refuses as before.
var WARNINGS = null;

function warn(code, detail) {
  if (WARNINGS === null) {
    fail(code, detail);
  }
  WARNINGS.push({ code: code, detail: detail });
}

// 'subjectAltName' as x509_build and the parsed entries name it, the
// table's 'ext_subjectAltName', or a dotted OID. extension() took only the
// second once, so extension(cert, 'basicConstraints') found nothing.
function extension_oid(name) {
  return /^\d+(\.\d+)+$/.test(name) ? OID.from_string(name)
    : OID.by_name(name.indexOf('ext_') === 0 ? name : 'ext_' + name);
}

function extension(cert, name) {
  var want;
  try {
    want = extension_oid(name);
  } catch (e) {
    return null;
  }

  var i;
  for (i = 0; i < cert.extensions.length; i++) {
    if (OID.equal(cert.extensions[i].oid, want)) {
      return cert.extensions[i];
    }
  }
  return null;
}

//   BasicConstraints ::= SEQUENCE {
//        cA                      BOOLEAN DEFAULT FALSE,
//        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
function basic_constraints(value) {
  return DER.read(value, function (r) {
    var seq = r.read_sequence();
    var ca = false;
    var path_len = null;

    if (seq.peek_tag() === 0x01) {
      ca = seq.read_boolean();
      // DEFAULT FALSE: DER omits a value equal to the default, so an
      // explicitly encoded FALSE is a second encoding of the same extension.
      if (ca === false) {
        warn('non-canonical-default',
          'cA is FALSE, which is the DEFAULT and must be omitted');
      }
    }

    if (seq.peek_tag() === 0x02) {
      path_len = int_value(seq.read_unsigned());
      // RFC 5280 4.2.1.9: pathLenConstraint is meaningful only when cA is
      // TRUE. Present without it, the certificate is stating a limit on a
      // chain it cannot be part of.
      if (!ca) {
        warn('path-len-without-ca',
          'pathLenConstraint is present but cA is not TRUE');
      }
    }

    seq.expect_end();
    return { ca: ca, path_len: path_len };
  });
}

var KEY_USAGE_BITS = [
  'digitalSignature', 'nonRepudiation', 'keyEncipherment',
  'dataEncipherment', 'keyAgreement', 'keyCertSign',
  'cRLSign', 'encipherOnly', 'decipherOnly'
];

function key_usage(value) {
  return DER.read(value, function (r) {
    var bs = r.read_bit_string();
    var out = {};
    var i;

    for (i = 0; i < KEY_USAGE_BITS.length; i++) {
      var byte = Math.floor(i / 8);
      var bit  = 7 - (i % 8);
      out[KEY_USAGE_BITS[i]] =
        byte < bs.bytes.length && ((bs.bytes[byte] >> bit) & 1) === 1;
    }

    // RFC 5280 4.2.1.3 requires at least one bit set. An all-zero KeyUsage
    // permits nothing, which is a certificate that cannot be used for
    // anything and was almost certainly not what the issuer meant.
    var any = false;
    for (i = 0; i < KEY_USAGE_BITS.length; i++) {
      if (out[KEY_USAGE_BITS[i]]) { any = true; }
    }
    if (!any) {
      fail('empty-key-usage', 'KeyUsage has no bits set');
    }

    return out;
  });
}

// ⚠ EACH PURPOSE AS { id, name }: the dotted OID always, and the name the
// builder takes - 'serverAuth' - or null. It was the OID table's name,
// prefix and all ('eku_serverAuth', where extensions come back without
// 'ext_'), or the dotted string when the table had none - anyExtendedKeyUsage
// among them - so one field held two kinds of thing (reported from lemon).
function extended_key_usage(value) {
  return DER.read(value, function (r) {
    var seq = r.read_sequence();
    var out = [];

    while (seq.remaining() > 0) {
      var oid = seq.read_oid();
      var name = OID.name_of(oid);
      out.push({ id: OID.to_string(oid),
                 name: name !== null && name.indexOf('eku_') === 0 ? name.slice(4) : null });
    }

    if (out.length === 0) {
      warn('empty-ext-key-usage', 'ExtKeyUsage has no purposes, so it permits none');
    }
    return out;
  });
}

// GeneralName is a nine-way CHOICE. Only the forms that carry a name a
// caller compares are decoded; the rest are kept as raw bytes rather than
// guessed at.
// Several extensions are a SEQUENCE SIZE (1..MAX) OF something, and RFC 5280
// means the (1..MAX): an empty one is a certificate asserting a list and
// providing none. Extracted after the similarity budget caught three copies
// of the same walk.
// `report` is fail or warn: warn for the one OpenSSL accepts empty.
function sequence_of(value, read_member, empty_code, empty_detail, report) {
  return DER.read(value, function (r) {
    var seq = r.read_sequence();
    var out = [];

    while (seq.remaining() > 0) {
      out.push(read_member(seq));
    }

    if (out.length === 0) {
      (report || fail)(empty_code, empty_detail);
    }
    return out;
  });
}

function subject_alt_name(value) {
  return sequence_of(value, general_name,
    'empty-alt-name', 'the alternative name list is empty', warn);
}

// `in_constraint` is true when the name is a nameConstraints subtree base,
// where RFC 5280 4.2.1.10 makes an iPAddress an address AND a mask - 8 bytes
// for v4, 32 for v6 - rather than an address alone.
// ⚠ otherName VALUES DECODED BY type-id.
//
// userPrincipalName (1.3.6.1.4.1.311.20.2.3) is a UTF8String.
//
// PermanentIdentifier (RFC 4043 2) - an identifier that survives a change
// of name, as a device keeps its serial number:
//   SEQUENCE { identifierValue UTF8String OPTIONAL,
//              assigner        OBJECT IDENTIFIER OPTIONAL }
// Both optional, and each combination means something (RFC 4043 2's four
// matching rules): no assigner - the issuer assigned it; no value - the
// subject's serialNumber attribute is the value. Which applies is the
// caller's; this reads what is there, and null for what is not.
//
// HardwareModuleName (RFC 4108 5) - 802.1AR's name for a module:
//   SEQUENCE { hwType OBJECT IDENTIFIER, hwSerialNum OCTET STRING }
// The serial is bytes "with no particular structure" (RFC 4108 5), so bytes.
var OTHER_NAMES = {
  '1.3.6.1.4.1.311.20.2.3': { field: 'upn', warn: false, read: function (u) {
    return u.read_utf8_string();
  } },
  '1.3.6.1.5.5.7.8.3': { field: 'permanent_identifier', warn: true, read: function (u) {
    var seq = u.read_sequence();
    var value = seq.peek_tag() === T.UTF8_STRING ? seq.read_utf8_string() : null;
    var assigner = seq.peek_tag() === T.OID ? seq.read_oid() : null;
    seq.expect_end();
    return {
      value: value,
      assigner: assigner === null ? null : OID.to_string(assigner),
      assigner_name: assigner === null ? null : OID.name_of(assigner)
    };
  } },
  '1.3.6.1.5.5.7.8.4': { field: 'hardware_module_name', warn: true, read: function (u) {
    var seq = u.read_sequence();
    var type = seq.read_oid();
    var serial = seq.read_octet_string();
    seq.expect_end();
    return {
      type: OID.to_string(type),
      type_name: OID.name_of(type),
      serial: serial,
      serial_hex: hex(serial)
    };
  } }
};

function general_name(r, in_constraint) {
  var tag = r.peek_tag();

  // [1] rfc822Name and [2] dNSName are IA5String, implicitly tagged.
  if (tag === 0x81) {
    return { type: 'email', value: ia5(r, 1) };
  }
  if (tag === 0x82) {
    return { type: 'dns', value: ia5(r, 2) };
  }
  if (tag === 0x86) {
    return { type: 'uri', value: ia5(r, 6) };
  }
  if (tag === 0x87) {
    // [7] iPAddress is an OCTET STRING: four bytes for v4, sixteen for v6.
    var got = r.read_implicit(7, 0x04);

    // ⚠ IN A NAME CONSTRAINT IT IS ADDRESS PLUS MASK. The first version
    // allowed 4 or 16 everywhere, so every CA carrying an IP name
    // constraint - `permitted;IP:10.0.0.0/255.0.0.0`, routine in private
    // PKI - was refused outright with "bad-ip-address".
    if (in_constraint === true) {
      if (got.bytes.length !== 8 && got.bytes.length !== 32) {
        fail('bad-ip-address',
          'an iPAddress name constraint is address and mask, 8 or 32 ' +
          'bytes, got ' + got.bytes.length);
      }
      check_contiguous_mask(got.bytes.subarray(got.bytes.length / 2));
    } else if (got.bytes.length !== 4 && got.bytes.length !== 16) {
      // ⚠ READ, MARKED, AND MATCHED BY NOTHING. Refused, it took the whole
      // extension with it - every DNS name beside it - where OpenSSL prints
      // "IP Address:<invalid>" and goes on. Now: a warning inside an
      // extension (refused anywhere else, as warn() does), and
      // `invalid: true`, which hostname_matches and the name-constraint
      // check treat as an address nothing equals and no subtree can
      // vouch for (DECISIONS 40).
      warn('bad-ip-address', 'an iPAddress is 4 or 16 bytes, got ' + got.bytes.length);
      return { type: 'ip', value: got.bytes, invalid: true };
    }
    return { type: 'ip', value: got.bytes };
  }
  if (tag === 0xA4) {
    // [4] directoryName is EXPLICIT, because Name is itself a CHOICE.
    var inner = r.read_explicit(4);
    var name = F.read_type(inner, 'RDNSequence');
    inner.expect_end();
    return { type: 'directory', value: name };
  }

  if (tag === 0x88) {
    // ⚠ [8] registeredID is a bare OID, implicitly tagged - so the tag says
    // OID and the content is one. Keeping it raw meant a caller had to know
    // that and decode it themselves, which is the kind of thing a format
    // library exists to have already done.
    var id = r.read_implicit(8, T.OID);
    return {
      type: 'registered-id',
      value: OID.to_string(id.bytes),
      name: OID.name_of(id.bytes),
      oid: id.bytes
    };
  }

  if (tag === 0xA0) {
    // ⚠ [0] otherName IS HOW A WINDOWS UPN TRAVELS.
    //
    //   OtherName ::= SEQUENCE {
    //        type-id  OBJECT IDENTIFIER,
    //        value    [0] EXPLICIT ANY DEFINED BY type-id }
    //
    // A certificate issued for smartcard logon carries the principal name
    // here and nowhere else, so a library that kept this raw could read
    // every SAN in such a certificate except the one that identifies the
    // user.
    //
    // The VALUE is captured rather than decoded, because what it holds
    // depends on the type-id - the ANY DEFINED BY pattern - and only the
    // caller knows which type-ids they accept. The one exception is the UPN,
    // which is common enough and simple enough to decode here.
    var outer = r.read_explicit(0);
    var type_id = outer.read_oid();
    var wrapper = outer.read_explicit(0);
    var raw = wrapper.capture();
    wrapper.expect_end();
    outer.expect_end();

    var out = {
      type: 'other',
      id: OID.to_string(type_id),
      name: OID.name_of(type_id),
      value: raw
    };

    // The type-ids decoded here: Microsoft's UPN, and the two device
    // identities (DECISIONS 31) - OTHER_NAMES, below.
    var known = OTHER_NAMES[out.id];
    if (known !== undefined) {
      try {
        out[known.field] = DER.read(raw, known.read);
      } catch (e) {
        // A malformed UPN is left as bytes rather than refused: the rest of
        // the certificate is still readable, and `value` still holds what
        // arrived. The two later ones also say so - a warning inside an
        // extension, refused elsewhere, as every lenient read here is.
        out[known.field] = null;
        if (known.warn) {
          warn('malformed-other-name', known.field + ': ' + e.message);
        }
      }
    }

    return out;
  }

  // [3] x400Address and [5] ediPartyName are kept whole. Both are
  // structures from the X.400 messaging world that no certificate in
  // circulation uses, and decoding one on the strength of its tag would be
  // guessing.
  return { type: 'other-tag', tag: tag, value: F.capture(r) };
}

function ia5(r, n) {
  var got = r.read_implicit(n, 0x16);
  var s = '';
  var i;

  var high = false;

  for (i = 0; i < got.bytes.length; i++) {
    high = high || got.bytes[i] > 0x7F;
    s += String.fromCharCode(got.bytes[i]);
  }
  if (high) {
    warn('bad-ia5-string', 'a GeneralName IA5String contains a byte above 0x7F; ' +
      'read as Latin-1, it matches no ASCII name');
  }
  return s;
}

function key_identifier(value) {
  return DER.read(value, function (r) {
    return r.read_octet_string();
  });
}

//   NameConstraints ::= SEQUENCE {
//        permittedSubtrees  [0] GeneralSubtrees OPTIONAL,
//        excludedSubtrees   [1] GeneralSubtrees OPTIONAL }
function name_constraints(value) {
  return DER.read(value, function (r) {
    var seq = r.read_sequence();
    var out = { permitted: [], excluded: [] };

    if (seq.peek_tag() === 0xA0) {
      out.permitted = subtrees(seq.read_implicit(0, 0x30));
    }
    if (seq.peek_tag() === 0xA1) {
      out.excluded = subtrees(seq.read_implicit(1, 0x30));
    }

    // RFC 5280 4.2.1.10: at least one of the two must be present. An empty
    // NameConstraints constrains nothing while claiming to constrain.
    if (out.permitted.length === 0 && out.excluded.length === 0) {
      fail('empty-name-constraints',
        'NameConstraints has neither permitted nor excluded subtrees');
    }

    seq.expect_end();
    return out;
  });
}

function subtrees(r) {
  var out = [];

  while (r.remaining() > 0) {
    var sub = r.read_sequence();
    var g = general_name(sub, true);

    // ⚠ minimum [0] and maximum [1]: RFC 5280 4.2.1.10 says minimum MUST be
    // zero - which DER, omitting a DEFAULT, writes as absent - and maximum
    // MUST be absent. They were SKIPPED once, so a subtree whose bounds
    // changed its meaning was read as if they were not there; then any was
    // refused, which failed the whole certificate where OpenSSL fails only
    // the check against it. Now they are read and kept on the subtree, and
    // name_constraints_check refuses to check against one (OpenSSL's error
    // 49). A minimum of 0 written out is only a second encoding.
    if (sub.peek_tag() === 0x80) {
      var min = int_value(sub.read_implicit(0, 0x02).bytes);
      if (min === 0) {
        warn('non-canonical-default', 'a subtree minimum of 0 is the DEFAULT and must be omitted');
      } else {
        g.minimum = min;
      }
    }
    if (sub.peek_tag() === 0x81) {
      g.maximum = int_value(sub.read_implicit(1, 0x02).bytes);
    }
    sub.expect_end();
    if (g.minimum !== undefined || g.maximum !== undefined) {
      warn('subtree-minmax', 'a subtree carries a minimum or maximum, which RFC 5280 ' +
        'forbids; name_constraints_check refuses to check against it');
    }
    out.push(g);
  }

  return out;
}

function check_contiguous_mask(mask) {
  var seen_zero = false;
  var i, b;

  for (i = 0; i < mask.length; i++) {
    for (b = 7; b >= 0; b--) {
      var bit = (mask[i] >> b) & 1;
      if (bit === 0) { seen_zero = true; }
      else if (seen_zero) {
        warn('bad-ip-mask',
          'an iPAddress name constraint mask is not a prefix (CIDR) mask; ' +
          'it is matched bit by bit, as OpenSSL matches it');
        return;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

// RFC 5280 4.1.2.5: the period is INCLUSIVE at both ends. An implementation
// that treats notAfter as exclusive rejects a certificate on its last valid
// second, which looks like a clock problem.
function validity_contains(cert, when) {
  var t = when === undefined ? new Date() : when;

  if (!(t instanceof Date) || isNaN(t.getTime())) {
    fail('bad-time', 'expected a Date');
  }

  return t.getTime() >= cert.validity.not_before.date.getTime() &&
         t.getTime() <= cert.validity.not_after.date.getTime();
}

// Two names match when they have the same RDNs in the same order, each with
// the same attributes, compared per RFC 5280 section 7.1.
//
// The comparison is NOT byte equality. RFC 5280 requires case-insensitive
// matching with internal whitespace collapsed for the string attribute types,
// so "CN=Example" and "cn=example  Ltd" versus "CN=Example Ltd" are
// questions with defined answers. Comparing bytes would make a chain fail to
// build because an issuer capitalised their own name differently in two
// certificates.
function name_matches(a, b) {
  if (a.length !== b.length) {
    return false;
  }

  var i;
  for (i = 0; i < a.length; i++) {
    if (!rdn_matches(a[i], b[i])) {
      return false;
    }
  }
  return true;
}

function rdn_matches(a, b) {
  if (a.length !== b.length) {
    return false;
  }

  // An RDN is a SET, so its members are unordered as a matter of meaning even
  // though DER fixes their encoding order. Each attribute in one must find a
  // partner in the other.
  var used = {};
  var i, j;

  for (i = 0; i < a.length; i++) {
    var found = false;

    for (j = 0; j < b.length; j++) {
      if (used[j]) { continue; }
      if (attribute_matches(a[i], b[j])) {
        used[j] = true;
        found = true;
        break;
      }
    }

    if (!found) { return false; }
  }

  return true;
}

function attribute_matches(a, b) {
  if (!OID.equal(a.type, b.type)) {
    return false;
  }

  var va = attribute_string(a.value);
  var vb = attribute_string(b.value);

  // A type this module cannot read as a string falls back to byte equality,
  // which is stricter and therefore safe: it can only fail to match things
  // that are equal, never match things that are not.
  if (va === null || vb === null) {
    return bytes_equal(a.value, b.value);
  }

  return normalise(va) === normalise(vb);
}

// The string attribute types RFC 5280 defines, plus the two it deprecates
// and real certificates still carry.
//
// Falling back to byte equality for a type this cannot read is SAFE - it can
// only fail to match things that are equal, never match things that are not
// - but it is not free: an issuer whose name is a TeletexString would fail
// to match itself across two certificates that spell it differently, and a
// chain would fail to build for a reason nothing reports.
function attribute_string(raw) {
  try {
    return DER.read(raw, function (r) {
      return r.read_any_string().value;
    });
  } catch (e) {
    return null;
  }
}

// ⚠ ONE ATTRIBUTE VALUE AS TEXT - a name's value, as the parsed name holds
// it: its whole DER, tag and length included.
//
//   x509.attribute_text(cert.subject[0][0].value)
//     // { type: 'printable', value: 'IL', valid: true }
//
// Every string type a name can hold: UTF8String, PrintableString,
// IA5String, VisibleString, NumericString, BMPString, UniversalString, and
// the T61String RFC 5280 deprecates. null for a value that is not a string
// - a SEQUENCE where a string belongs.
//
// By default each type's own rule holds: a PrintableString with "*" in it
// is not one, and is null. { lenient: true } reads as OpenSSL does: an
// 8-bit string type holding characters its type forbids - the PrintableString
// CN "*.example.com" real CAs have issued - is its bytes, one character
// each, and `valid: false` says so. A UTF8String that is not UTF-8, or a
// BMPString or UniversalString of the wrong length, is null either way:
// there is no text to give, and OpenSSL refuses such a certificate too.
//
// ⚠ T61String IS T.61 BY DEFAULT AND LATIN-1 WHEN LENIENT. The default is
// the standard's character set (commons/t61.js: 0xE9 is "Ø", and an accent
// comes before its letter). OpenSSL reads every T61String as Latin-1 (0xE9
// is "é"), and so does Node; lenient reads as OpenSSL does, so there it is
// Latin-1. The two agree on ASCII, which is nearly every T61String issued.
// The 8-bit types: their character-set rule (der_reader's predicates), or
// none - GraphicString, GeneralString and VideotexString are read as
// Latin-1 whatever they hold.
var EIGHT_BIT = {};
EIGHT_BIT[T.PRINTABLE_STRING] = { type: 'printable', ok: DER.is_printable };
EIGHT_BIT[T.IA5_STRING] = { type: 'ia5', ok: DER.is_ia5 };
EIGHT_BIT[T.VISIBLE_STRING] = { type: 'visible', ok: DER.is_visible };
EIGHT_BIT[T.NUMERIC_STRING] = { type: 'numeric', ok: DER.is_numeric };
EIGHT_BIT[T.GRAPHIC_STRING] = { type: 'graphic', ok: null };
EIGHT_BIT[T.GENERAL_STRING] = { type: 'general', ok: null };
EIGHT_BIT[T.VIDEOTEX_STRING] = { type: 'videotex', ok: null };

// ⚠ NO EXCEPTION ON THE WAY TO A LENIENT READING. It read strictly, caught
// the refusal and read again - and an exception, with its stack, cost 4-5us
// where the read costs under one: lenient was twice strict, and lemon-tls's
// getPeerCertificate twice what it had been (DECISIONS 41). Now the 8-bit
// types ask der_reader's predicate first; only a UTF8String, BMPString or
// UniversalString that is not what it says still throws inside - there is
// no text for those either way, and real certificates do not carry them.
function attribute_text(value, options) {
  var raw = to_bytes(value);
  var lenient = options !== undefined && options !== null && options.lenient === true;
  var tag = raw.length > 0 ? raw[0] : -1;
  var eight = EIGHT_BIT[tag];

  if (eight !== undefined || tag === T.T61_STRING) {
    var bytes = content_of(raw, tag);
    if (bytes === null) { return null; }
    if (tag === T.T61_STRING) {
      if (lenient) { return { type: 't61', value: latin1(bytes), valid: true }; }
    } else {
      var ok = eight.ok === null || eight.ok(bytes);
      if (!ok && !lenient) { return null; }
      return { type: eight.type, value: latin1(bytes), valid: ok };
    }
  }

  try {
    var s = DER.read(raw, function (r) { return r.read_any_string(); });
    return { type: s.type, value: s.value, valid: true };
  } catch (e) {
    return null;
  }
}

// The content of a value that is one primitive TLV with this tag - the
// reader's checks (DER length, nothing after) - or null.
function content_of(raw, tag) {
  try {
    return DER.read(raw, function (r) { return r._read_value(tag).bytes; });
  } catch (e) {
    return null;
  }
}

// Leading and trailing whitespace removed, internal whitespace collapsed to
// one space, case folded - RFC 5280 7.1's rule as OpenSSL applies it
// (asn1_string_canon): ASCII letters and ASCII whitespace ONLY.
//
// ⚠ IT WAS JavaScript's toLowerCase AND \s, which fold all of Unicode -
// so names OpenSSL keeps apart matched here: "É" and "é", and worse, the
// Kelvin sign U+212A and "k", and Unicode spaces such as U+00A0 and a
// plain space. In an excluded subtree that refuses more than OpenSSL; in a
// permitted one it ADMITS more, which is the direction that matters. RFC
// 5280 points at RFC 4518's full preparation (normalisation, mapping,
// folding), which neither this nor OpenSSL implements; half of it is worse
// than OpenSSL's well-defined subset, so this matches OpenSSL.
var ASCII_SPACES = /[ \t\n\v\f\r]+/g;

function ascii_lower(s) {
  return s.replace(/[A-Z]+/g, function (m) { return m.toLowerCase(); });
}

function normalise(s) {
  return ascii_lower(s.replace(/^[ \t\n\v\f\r]+|[ \t\n\v\f\r]+$/g, '')
    .replace(ASCII_SPACES, ' '));
}

// ⚠ ONE NAME AGAINST ONE CONSTRAINT, BY TYPE. RFC 5280 4.2.1.10.
//
//   dns     "example.com" permits example.com and any name made by adding
//           labels on the left; ".example.com" permits only the latter.
//           The boundary falls on a label: "notexample.com" never matches.
//   email   "a@example.com" is that mailbox; "example.com" is every mailbox
//           AT that host; ".example.com" is every mailbox at a host below it.
//   uri     the same three forms as email, applied to the URI's host.
//   ip      a range (address and mask bytes, or CIDR text) against an
//           address (bytes or text) of the same family.
//   directory  the constraint's RDNs are a prefix of the name's.
//
// The first version had one function for every type, written for DNS: it
// stripped a leading dot - so ".example.com" permitted example.com itself,
// where OpenSSL and Go do not - and it compared an email address as a
// hostname, so "a@example.com" never matched "example.com" at all.
//
// `type` defaults to 'dns', which is what the two-argument form meant.
function constraint_permits(constraint, name, type) {
  var t = type === undefined ? 'dns' : type;

  if (t === 'dns') {
    return host_within(String(constraint), String(name), true);
  }
  if (t === 'email') {
    return email_within(String(constraint), String(name));
  }
  if (t === 'uri') {
    var host = uri_host(String(name));
    return host !== null && host_within(String(constraint), host, false);
  }
  if (t === 'ip') {
    // Text as the builder takes it - "10.0.0.0/8" and "10.1.2.3" - or bytes.
    var range = typeof constraint === 'string' ? parse_cidr(constraint) : to_bytes(constraint);
    var addr = typeof name === 'string' ? parse_ip(name) : to_bytes(name);
    if (range === null || addr === null) {
      fail('bad-ip', 'not an IP range and an address: ' + constraint + ', ' + name);
    }
    return ip_within(range, addr);
  }
  if (t === 'directory') {
    return dn_within(constraint, name);
  }

  fail('unsupported-constraint-type',
    'no name-constraint rule for "' + t + '"');
}

// `dns_style`: for dNSName, a constraint without a leading dot ALSO matches
// subdomains. For email and URI hosts it does not - "example.com" there
// means that host exactly, and ".example.com" means hosts below it.
function host_within(constraint, name, dns_style) {
  var c = ascii_lower(constraint);
  var n = ascii_lower(name);

  if (c === '') {
    // An empty constraint matches everything, which RFC 5280 allows.
    return true;
  }

  if (c.charAt(0) === '.') {
    return n.length > c.length && n.substr(n.length - c.length) === c;
  }

  if (n === c) {
    return true;
  }

  return dns_style &&
         n.length > c.length &&
         n.charAt(n.length - c.length - 1) === '.' &&
         n.substr(n.length - c.length) === c;
}

function email_within(constraint, address) {
  var at = address.lastIndexOf('@');

  if (at <= 0) {
    return false;
  }

  var host = address.substring(at + 1);

  if (constraint.indexOf('@') !== -1) {
    // A whole mailbox. RFC 5280 7.5: the local part is case-sensitive and
    // the host is not.
    var cat = constraint.lastIndexOf('@');
    return constraint.substring(0, cat) === address.substring(0, at) &&
           ascii_lower(constraint.substring(cat + 1)) === ascii_lower(host);
  }

  return host_within(constraint, host, false);
}

// The host of a URI with an authority, lower-cased and without userinfo,
// port or IPv6 brackets. A URI with no authority - urn:, mailto: - has no
// host, and RFC 5280 says such a name cannot satisfy a URI constraint.
function uri_host(uri) {
  var m = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]*)/.exec(uri);

  if (m === null) {
    return null;
  }

  var authority = m[1].replace(/^[^@]*@/, '');

  if (authority.charAt(0) === '[') {
    return null;
  }

  var host = authority.replace(/:\d*$/, '');
  return host === '' ? null : host;
}

function ip_within(constraint, address) {
  if (constraint.length !== address.length * 2) {
    // v4 against v6, or the reverse: a different family never matches.
    return false;
  }

  var n = address.length;
  var i;

  for (i = 0; i < n; i++) {
    if ((address[i] & constraint[n + i]) !== (constraint[i] & constraint[n + i])) {
      return false;
    }
  }
  return true;
}

function dn_within(constraint, name) {
  if (constraint.length > name.length) {
    return false;
  }

  var i;
  for (i = 0; i < constraint.length; i++) {
    if (!rdn_matches(constraint[i], name[i])) {
      return false;
    }
  }
  return true;
}

// ⚠ THE WHOLE RULE, FOR ONE NAME: excluded first, then permitted.
//
// `constraints` is what the nameConstraints extension parses to -
// { permitted, excluded }, each a list of GeneralNames. `name` is a
// GeneralName, { type, value }, from a subjectAltName or the subject.
//
//   - a name inside ANY excluded subtree of its type is refused
//   - if there are permitted subtrees of its type, it must be inside one
//   - if there are none of its type, the type is unconstrained
//
// Types this module has no rule for (otherName, registeredID) are reported
// as unknown rather than guessed: `null`, which a caller must not treat as
// true. RFC 5280 says a CA that constrains a type a verifier cannot check
// should have its certificates refused.
//
// For a whole certificate use name_constraints_check below: it picks the
// names as OpenSSL does and refuses the inputs that would make this loop a
// denial of service.
function name_constraints_permit(constraints, name) {
  var r = permit_reason(constraints, name);
  return r === true || r === null ? r : false;
}

// The same rule, saying which half refused: true, null (unknown),
// 'excluded' or 'not-permitted' - OpenSSL's errors 48 and 47.
function permit_reason(constraints, name) {
  var types = { dns: 1, email: 1, uri: 1, ip: 1, directory: 1 };

  refuse_minmax(constraints);

  if (!types[name.type]) {
    var constrained = constraints.permitted.concat(constraints.excluded)
      .some(function (g) { return g.type === name.type; });
    return constrained ? null : true;
  }

  var i;

  // ⚠ A URI WITH NO HOST - urn:, mailto:, or a host this cannot read, such
  // as an IPv6 literal - cannot be checked against a URI subtree. It was
  // simply "not inside" one: ok under excluded subtrees, which is a pass for
  // a name nothing compared. OpenSSL fails it with
  // X509_V_ERR_UNSUPPORTED_NAME_SYNTAX (53); here it is unknown.
  if (name.type === 'uri' && uri_host(String(name.value)) === null &&
      constraints.permitted.concat(constraints.excluded)
        .some(function (g) { return g.type === 'uri'; })) {
    return null;
  }

  // An iPAddress that is not 4 or 16 bytes is no address: under an IP
  // subtree it is unknown, never "outside the excluded ones".
  if (name.type === 'ip' && name.invalid === true &&
      constraints.permitted.concat(constraints.excluded)
        .some(function (g) { return g.type === 'ip'; })) {
    return null;
  }

  var other = name.type === 'dns' ? undotted(String(name.value)) : null;

  for (i = 0; i < constraints.excluded.length; i++) {
    var ex = constraints.excluded[i];
    if (ex.type === name.type &&
        (constraint_permits(ex.value, name.value, name.type) ||
         (other !== null && constraint_permits(ex.value, other, 'dns')))) {
      return 'excluded';
    }
  }

  var any = false;

  for (i = 0; i < constraints.permitted.length; i++) {
    var p = constraints.permitted[i];
    if (p.type !== name.type) { continue; }
    any = true;
    if (constraint_permits(p.value, name.value, name.type)) {
      return true;
    }
  }

  return any ? 'not-permitted' : true;
}

// ⚠ THE WHOLE CERTIFICATE AGAINST ONE CA'S CONSTRAINTS - WITH A CEILING.
//
// name_constraints_permit answers for one name; a verifier loops. The cost
// of that loop is names x subtrees, and the certificates choose BOTH: a CA
// with 1,024 subtrees over a leaf with 1,024 names is a million comparisons
// (here: 78ms for DNS names, 850ms for directory names - CPU that blocks the
// event loop, paid before any signature says the certificate is genuine).
//
// So this does what OpenSSL's NAME_CONSTRAINTS_check does:
//
//   counts names as OpenSSL does   every ATTRIBUTE of the subject, plus every
//                                  SAN. Counting the subject as one name lets
//                                  a DN of a thousand attributes through
//                                  under the ceiling (x509-limbo nc-dos-3).
//   refuses before working         when names x subtrees exceeds 2^20
//                                  (OpenSSL's NAME_CHECK_MAX), with
//                                  'name-constraints-too-costly' - OpenSSL
//                                  fails it as X509_V_ERR_UNSPECIFIED.
//   prepares once                  the subtrees are split by type, hosts
//                                  lower-cased and directory names turned
//                                  into one key per RDN ONCE per call, so a
//                                  comparison is a string compare: 1,024 x
//                                  1,024 directory names went from 850ms to
//                                  about 25ms, DNS names from 70ms to 20ms.
//
// The names checked, as OpenSSL checks them:
//   - the subject, as a directoryName, when it is not empty
//   - each emailAddress attribute of the subject, as an rfc822Name
//   - each subjectAltName
//   - with `options.common_name: true`, the subject's commonName as a
//     dNSName when the certificate has no DNS SAN - what OpenSSL does for a
//     leaf (NAME_CONSTRAINTS_check_CN). A CN that is not a hostname is not
//     checked, as there.
//
// A chain multiplies this: each CA's constraints apply to every certificate
// below it. The ceiling is per certificate-and-CA pair, as in OpenSSL; a
// verifier wanting one for the whole path passes `max_checks` and keeps its
// own count from `checks`.
//
// Returns { ok, checks, refused, unknown }:
//   ok       true; false when any name is refused; null when none is refused
//            but a constrained type has no rule here (see
//            name_constraints_permit) - which a caller must not treat as true
//   checks   names x subtrees, the figure the ceiling applies to
//   refused  the names outside the constraints, { type, value, reason }:
//            reason 'excluded' (OpenSSL's error 48) or 'not-permitted' (47)
//   unknown  the names whose type this module cannot check
var NAME_CHECK_MAX = 1048576;

function name_constraints_check(cert, constraints, options) {
  var opts = options || {};
  var max = opts.max_checks === undefined ? NAME_CHECK_MAX : opts.max_checks;

  var san_ext = extension(cert, 'subjectAltName');
  var sans = san_ext === null ? [] : san_ext.parsed;
  var attributes = 0;
  var i;

  for (i = 0; i < cert.subject.length; i++) {
    attributes += cert.subject[i].length;
  }

  refuse_minmax(constraints);

  var subtree_count = constraints.permitted.length +
                      constraints.excluded.length;
  var checks = (attributes + sans.length) * subtree_count;

  if (checks > max) {
    fail('name-constraints-too-costly',
      (attributes + sans.length) + ' names against ' + subtree_count +
      ' subtrees is ' + checks + ' comparisons, over the ceiling of ' + max +
      ' (OpenSSL NAME_CHECK_MAX); refused before any is made');
  }

  var names = [];

  if (cert.subject.length > 0) {
    names.push({ type: 'directory', value: cert.subject });
  }
  name_attribute(cert.subject, 'emailAddress').forEach(function (e) {
    names.push({ type: 'email', value: e });
  });
  names = names.concat(sans);

  if (opts.common_name === true &&
      !sans.some(function (g) { return g.type === 'dns'; })) {
    var cn = common_name(cert.subject);
    if (cn !== null && looks_like_hostname(cn)) {
      names.push({ type: 'dns', value: cn });
    }
  }

  var grouped = group_constraints(constraints);
  var out = { ok: true, checks: checks, refused: [], unknown: [] };

  for (i = 0; i < names.length; i++) {
    var group = grouped[names[i].type] || { permitted: [], excluded: [] };
    var verdict = names[i].type === 'directory'
      ? prepared_permit(group, rdn_keys(names[i].value), keys_within)
      : names[i].type === 'dns'
      ? prepared_permit(group, ascii_lower(String(names[i].value)),
          dns_within_lower, undotted)
      : permit_reason(group, names[i]);
    if (verdict === 'excluded' || verdict === 'not-permitted') {
      // Which half refused it - OpenSSL's 48 or 47 - so a caller need not
      // run the check again to find out (reported from lemon).
      out.refused.push({ type: names[i].type, value: names[i].value, reason: verdict });
    } else if (verdict === null) {
      out.unknown.push(names[i]);
    }
  }

  out.ok = out.refused.length > 0 ? false
    : out.unknown.length > 0 ? null : true;
  return out;
}

// A subtree with a minimum or maximum has a meaning RFC 5280 forbids and
// nothing implements. OpenSSL fails the whole check (X509_V_ERR_SUBTREE_MINMAX,
// error 49), whatever the names - and so does this, before any comparison.
function refuse_minmax(constraints) {
  var all = constraints.permitted.concat(constraints.excluded);
  var i;
  for (i = 0; i < all.length; i++) {
    if (all[i].minimum !== undefined || all[i].maximum !== undefined) {
      fail('subtree-minmax', 'a subtree carries a minimum or maximum; RFC 5280 ' +
        'forbids both, and OpenSSL refuses the check (error 49)');
    }
  }
}

// The subtrees split by type, DNS hosts lower-cased and directory names as
// RDN keys - done once, rather than once per name per subtree.
function group_constraints(constraints) {
  var by = {};

  function add(list, key) {
    list.forEach(function (g) {
      if (by[g.type] === undefined) {
        by[g.type] = { permitted: [], excluded: [] };
      }
      var v = g.value;
      if (g.type === 'dns') {
        // Case only: a trailing dot is NOT stripped from the constraint.
        // For the name, see undotted.
        v = ascii_lower(String(v));
      } else if (g.type === 'directory') {
        v = rdn_keys(v);
      }
      by[g.type][key].push({ type: g.type, value: v });
    });
  }

  add(constraints.permitted, 'permitted');
  add(constraints.excluded, 'excluded');
  return by;
}

// ⚠ A DIRECTORY NAME AS ONE STRING PER RDN, MADE ONCE.
//
// dn_within decodes and normalises both attribute values on every
// comparison - and a million of them took 850ms. Here each RDN becomes a
// key once: per attribute, the type's OID and the RFC 5280 7.1 normalised
// string (or the raw bytes, for a value that is not a string - the same
// fallback attribute_matches makes), sorted, since an RDN is a SET. Two
// RDNs match under rdn_matches exactly when their keys are equal.
function rdn_keys(name) {
  return name.map(function (rdn) {
    return rdn.map(function (a) {
      var v = attribute_string(a.value);
      return hex(a.type) + (v === null ? '#' + hex(a.value)
        : '=' + JSON.stringify(normalise(v)));
    }).sort().join('+');
  });
}

// ⚠ ONE STRING PER NAME, EQUAL EXACTLY WHEN name_matches SAYS SO.
//
// A verifier indexing its trust anchors by subject needs a key, and one it
// made itself - the DER, or name_to_string - disagrees with name_matches:
// "O=Acme" and "o=ACME " are one name there and two keys (reported from
// lemon, which keeps such an index). This is rdn_keys joined. Each value is
// JSON-quoted, so the joining characters cannot be forged from inside one.
function name_key(name) {
  return rdn_keys(name).join(',');
}

function keys_within(constraint, name) {
  if (constraint.length > name.length) { return false; }
  var i;
  for (i = 0; i < constraint.length; i++) {
    if (constraint[i] !== name[i]) { return false; }
  }
  return true;
}

// host_within(c, n, true) for a constraint and a name both lower-cased
// already - the case folding done once rather than per comparison.
function dns_within_lower(c, n) {
  if (c === '') { return true; }
  if (c.charAt(0) === '.') {
    return n.length > c.length && n.substr(n.length - c.length) === c;
  }
  return n === c || (n.length > c.length &&
    n.charAt(n.length - c.length - 1) === '.' &&
    n.substr(n.length - c.length) === c);
}

// name_constraints_permit's rule - excluded first, then permitted - over
// values prepared once. `alternate`, when given, is a second spelling of
// the name that an EXCLUDED subtree also catches (see undotted).
function prepared_permit(group, name, within, alternate) {
  var other = alternate === undefined ? null : alternate(name);
  var i;
  for (i = 0; i < group.excluded.length; i++) {
    if (within(group.excluded[i].value, name) ||
        (other !== null && within(group.excluded[i].value, other))) {
      return 'excluded';
    }
  }
  for (i = 0; i < group.permitted.length; i++) {
    if (within(group.permitted[i].value, name)) { return true; }
  }
  return group.permitted.length === 0 ? true : 'not-permitted';
}

// ⚠ A dNSName WITH A TRAILING DOT, WITHOUT IT - FOR EXCLUDED SUBTREES ONLY.
//
// "b.example.com." is not inside ".example.com" by string - OpenSSL does
// not strip the dot, and neither did this. But a hostname matcher that
// DOES strip it - node:tls's checkServerIdentity does, and this library's
// hostname_matches did - then accepts the name as b.example.com. The
// excluded subtree was walked around by one byte (reported from lemon).
//
// So an excluded subtree catches the name in both spellings, and nothing
// a matcher might reduce it to escapes the exclusion. A permitted subtree
// stays exact, as OpenSSL's: there the stricter reading is the exact one.
// And hostname_matches no longer strips the dot from a certificate's names
// at all (as OpenSSL's X509_check_host), so the dotted SAN matches no host.
function undotted(name) {
  return name.length > 1 && name.charAt(name.length - 1) === '.'
    ? name.substring(0, name.length - 1) : null;
}

// OpenSSL's test before treating a CN as a hostname: letters, digits,
// hyphens and dots, at least one dot, no empty label.
function looks_like_hostname(s) {
  return /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/.test(s);
}

// ---------------------------------------------------------------------------
// Hostname verification
// ---------------------------------------------------------------------------

// ⚠ WHETHER A CERTIFICATE IS FOR THIS HOST. RFC 9525 (which replaced RFC
//    6125 in 2023), with the CA/Browser Forum's narrowing - what every
//    browser enforces.
//
// It is not path validation and it says nothing about trust. It is the
// check most often written wrong by hand, in the same handful of ways:
//
//   reading commonName      browsers stopped in 2017 (Chrome 58). A
//                           certificate whose only name is in the CN is
//                           not for anything, and RFC 9525 dropped the
//                           CN-ID outright. `options.common_name:
//                           true` restores RFC 6125's old one, for legacy
//                           peers only, and only when the certificate has
//                           no DNS or IP names at all (6125 6.4.4).
//   loose wildcards         `*` is a whole left-most label and matches ONE
//                           label: *.example.com is a.example.com, never
//                           a.b.example.com and never example.com. Partial
//                           wildcards (f*.example.com) are refused, as are
//                           wildcards with fewer than two labels after them.
//   IPs as names            an IP literal is compared with iPAddress SANs as
//                           bytes, and never with a dNSName - a certificate
//                           for "10.0.0.1" as a DNS name is not for 10.0.0.1.
//   Unicode                 the host must be in A-label (punycode) form.
//                           Comparing U-labels needs IDNA mapping, and a
//                           near-miss there is a homograph.
function hostname_matches(cert, host, options) {
  var opts = options || {};

  if (typeof host !== 'string' || host === '') {
    fail('bad-hostname', 'a hostname is required');
  }

  var ip = parse_ip(host);
  var san = extension(cert, 'ext_subjectAltName');
  var names = san === null ? [] : san.parsed;
  var i;

  if (ip !== null) {
    for (i = 0; i < names.length; i++) {
      if (names[i].type === 'ip' && names[i].invalid !== true && bytes_equal(names[i].value, ip)) {
        return true;
      }
    }
    return false;
  }

  if (/[^\x21-\x7E]/.test(host)) {
    fail('bad-hostname',
      'the hostname is not ASCII; convert it to A-labels (punycode) first');
  }

  // One trailing dot on the HOST is the root: "example.com." is
  // example.com. On a certificate's name it is not stripped - see undotted.
  var h = ascii_lower(host).replace(/\.$/, '');
  var any_id = false;

  for (i = 0; i < names.length; i++) {
    if (names[i].type === 'dns') {
      any_id = true;
      if (dns_id_matches(names[i].value, h)) {
        return true;
      }
    } else if (names[i].type === 'ip') {
      any_id = true;
    }
  }

  if (!any_id && opts.common_name === true) {
    var cn = common_name(cert.subject);
    return cn !== null && dns_id_matches(cn, h);
  }

  return false;
}

function dns_id_matches(pattern, host) {
  var p = ascii_lower(String(pattern));

  // A name with a trailing dot matches no host: stripping it is what let
  // b.example.com. past an excluded .example.com (see undotted).
  if (p === '' || host === '' || p.charAt(p.length - 1) === '.') {
    return false;
  }

  if (p.indexOf('*') === -1) {
    return p === host;
  }

  var labels = p.split('.');

  // Only a whole left-most `*`, and at least two labels after it.
  if (labels[0] !== '*' || labels.length < 3 ||
      p.indexOf('*', 1) !== -1) {
    return false;
  }

  var rest = p.substring(1);                       // ".example.com"
  var dot = host.indexOf('.');

  return dot > 0 && host.substring(dot) === rest;
}


function has_unhandled_critical(cert) {
  return cert.unhandled_critical.length > 0;
}

// The common name of a subject, for display. NOT for verification: RFC 6125
// deprecated the CN as a host identity years ago, and subjectAltName is where
// a name to check lives.
function common_name(name) {
  var cn = OID.by_name('commonName');
  var i, j;

  for (i = 0; i < name.length; i++) {
    for (j = 0; j < name[i].length; j++) {
      if (OID.equal(name[i][j].type, cn)) {
        return attribute_string(name[i][j].value);
      }
    }
  }
  return null;
}

// A subject name as a readable string, for error messages and logs.
// RFC 4514 - the string form of a distinguished name that LDAP, Java and
// Python's cryptography (rfc4514_string) print, and checked against the
// last: 'CN=Example CA,O=Acme,C=US'.
//
// ⚠ THE ORDER IS REVERSED. RFC 4514 2.1 writes the LAST RDN first, so a
// name encoded C, O, CN prints CN first. This printed it in encoded order
// with the table's long names - 'countryName=US, ...' - which matched
// nothing a user compares against.
//
// Short names only for the nine RFC 4514 3 defines (CN, L, ST, O, OU, C,
// STREET, DC, UID); any other attribute is its dotted OID, which is what
// the RFC prescribes and what keeps the output unambiguous. Values that are
// not strings are '#' and the hex of their DER (2.4).
// options.readable: for showing to a person, not for comparing. Attributes
// RFC 4514 has no short name for are written by name - serialNumber=,
// emailAddress= - instead of by OID, and RDNs are separated by ', '. The
// result is NOT RFC 4514: it will not equal what another system prints for
// the same name, so it belongs in a log or a UI and never in a comparison.
//
// options.style: 'openssl' is the text OpenSSL prints with the flags Node
// uses for X509Certificate's subject and issuer (X509_NAME_print_ex,
// XN_FLAG_SEP_MULTILINE | XN_FLAG_FN_SN | ASN1_STRFLGS_ESC_2253 |
// ESC_CTRL | UTF8_CONVERT): the RDNs in ENCODED order, one per line ('\n'),
// a multi-valued RDN's values joined with ' + ', OpenSSL's short names
// (openssl_names.js; any other attribute by dotted OID), values read
// leniently (attribute_text), RFC 2253 escapes - , + " \ < > ; anywhere,
// '#' or a space first, a space last - and control characters as \XX.
// A value that is no string is its whole DER, byte for byte, as OpenSSL
// prints it. 'openssl-rfc2253' is the line Node prints for a DirName in
// subjectAltName: the RDNs in REVERSE order joined with ',' - and, as
// OpenSSL reverses entries rather than RDNs, a multi-valued RDN's values
// reversed too, joined with '+' - the same short names and escapes but no
// \XX for control characters, and an attribute OpenSSL has no name for as
// its OID and '#' with the hex of its DER.
//
// Both are checked against node:crypto, field by field (test/x509.test.js).
// They are for showing what Node and OpenSSL show; never for comparing
// names - name_matches is.
function name_to_string(name, options) {
  if (options && options.style === 'openssl') {
    return openssl_name(name, false);
  }
  if (options && options.style === 'openssl-rfc2253') {
    return openssl_name(name, true);
  }
  if (options && options.style !== undefined) {
    fail('bad-style', 'name_to_string styles are "openssl" and "openssl-rfc2253", ' +
      'or none for RFC 4514');
  }
  var readable = options && options.readable === true;
  var rdns = [];
  var i, j;

  for (i = name.length - 1; i >= 0; i--) {
    var attrs = [];
    for (j = 0; j < name[i].length; j++) {
      var attr = name[i][j];
      var dotted = OID.to_string(attr.type);
      var label = short_name(dotted) ||
        (readable ? OID.name_of(attr.type) || dotted : dotted);
      var value = attribute_string(attr.value);
      attrs.push(label + '=' + (value === null
        ? '#' + hex(to_bytes(attr.value)) : rfc4514_escape(value)));
    }
    // A multi-valued RDN is joined with '+'.
    rdns.push(attrs.join('+'));
  }

  return rdns.join(readable ? ', ' : ',');
}

function openssl_name(name, rfc2253) {
  var rdns = [];
  var i;
  for (i = 0; i < name.length; i++) {
    var attrs = name[i].map(function (attr) {
      var dotted = OID.to_string(attr.type);
      var label = OPENSSL_NAMES[dotted];
      if (label === undefined && rfc2253) {
        return dotted + '=#' + hex(to_bytes(attr.value)).toUpperCase();
      }
      var text = attribute_text(attr.value, { lenient: true });
      var v = text !== null ? text.value : latin1(to_bytes(attr.value));
      return (label === undefined ? dotted : label) + '=' + openssl_escape(v, !rfc2253);
    });
    rdns.push(rfc2253 ? attrs.reverse().join('+') : attrs.join(' + '));
  }
  return rfc2253 ? rdns.reverse().join(',') : rdns.join('\n');
}

// OpenSSL's do_esc_char with ASN1_STRFLGS_ESC_2253, and ESC_CTRL when
// `ctrl`: characters above 0x7F as they are (UTF8_CONVERT, no ESC_MSB).
// Nearly every value needs none of it: one test, and back unchanged.
var NEEDS_ESCAPE = /[,+"\\<>;\x00-\x1f\x7f]|^[# ]| $/;

function openssl_escape(v, ctrl) {
  if (!NEEDS_ESCAPE.test(v)) {
    return v;
  }
  var out = '';
  var i;
  for (i = 0; i < v.length; i++) {
    var ch = v.charAt(i);
    var code = v.charCodeAt(i);
    if (',+"\\<>;'.indexOf(ch) !== -1 || (i === 0 && (ch === '#' || ch === ' ')) ||
        (i === v.length - 1 && ch === ' ')) {
      out += '\\' + ch;
    } else if (ctrl && (code < 0x20 || code === 0x7F)) {
      out += '\\' + (code < 16 ? '0' : '') + code.toString(16).toUpperCase();
    } else {
      out += ch;
    }
  }
  return out;
}

// The values of one attribute in a name, in the order the name holds them
// - a list, because an attribute can appear more than once (DC=example,
// DC=corp; several OUs). Empty when absent.
//
//   x509.name_attribute(cert.subject, 'serialNumber')     // ['12345']
//   x509.name_attribute(cert.subject, 'CN')               // ['alice']
//
// `type` is the library's name ('organizationName'), an RFC 4514 short
// name ('O'), or a dotted OID. A value that is not a string comes back as
// the bytes of its DER.
//
// Prefer this to taking a string apart: a value may contain ',' '+' or
// '=', and the parsed name has no such ambiguity.
function name_attribute(name, type) {
  var want = attribute_type(type);
  var out = [];
  var i, j;

  for (i = 0; i < name.length; i++) {
    for (j = 0; j < name[i].length; j++) {
      if (OID.to_string(name[i][j].type) === want) {
        var v = attribute_string(name[i][j].value);
        out.push(v === null ? to_bytes(name[i][j].value) : v);
      }
    }
  }
  return out;
}

function attribute_type(type) {
  if (typeof type !== 'string' || type.length === 0) {
    fail('bad-attribute-type', 'the attribute is a name, a short name like ' +
      '"CN", or a dotted OID');
  }
  if (/^\d+(\.\d+)+$/.test(type)) {
    return type;
  }
  var short = short_name_oid(type);
  if (short !== null) {
    return short;
  }
  try {
    return OID.to_string(OID.by_name(type));
  } catch (e) {
    fail('unknown-attribute', '"' + type + '" is not an attribute this ' +
      'library names - pass the dotted OID');
  }
}

// RFC 4514 2.4.
function rfc4514_escape(v) {
  if (v.length === 0) {
    return '';
  }
  var out = v.replace(/\\/g, '\\\\')
             .replace(/["+,;<>]/g, function (c) { return '\\' + c; })
             .replace(/\u0000/g, '\\00');
  if (out.charAt(0) === '#' || out.charAt(0) === ' ') {
    out = '\\' + out;
  }
  if (out.charAt(out.length - 1) === ' ') {
    out = out.slice(0, -1) + '\\ ';
  }
  return out;
}

// ---------------------------------------------------------------------------




export {
  from_der,
  extension,
  validity_contains,
  name_matches,
  constraint_permits,
  name_constraints_permit,
  name_constraints_check,
  NAME_CHECK_MAX,
  openssl_unsupported_critical,
  OPENSSL_SUPPORTED,
  hostname_matches,
  parse_ip,
  has_unhandled_critical,
  common_name,
  name_to_string,
  attribute_text,
  name_attribute,

  // Where to go next. These exist because this library had ocsp.js and
  // crl.js before it had the extensions that say where to ask.
  // ⚠ Exported for attrcert.js, which names holders and issuers with the
  // same nine-way CHOICE. A second copy would drift exactly as the EC
  // helpers did between spki.js and pkcs8.js.
  general_name as read_general_name,
  // The same, for the Extension shape csr, crl, attrcert and crmf return.
  extension_entry,
  unenforced_critical,
  CRL_REASONS,
  enforced_set,
  name_key,
  read_extension,

  // Whether this is a precertificate - see precert_poison.
  is_precertificate,

  ocsp_urls,
  issuer_urls,
  crl_urls,

  KEY_USAGE_BITS,
  REASON_FLAGS
};
