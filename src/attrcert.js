// Attribute certificates, RFC 5755.
//
// ⚠ A CERTIFICATE THAT SAYS WHAT YOU MAY DO, NOT WHO YOU ARE.
//
//   a public-key certificate  "this key belongs to alice@example.com"
//   an attribute certificate  "alice may approve orders up to 50,000"
//
// It carries NO PUBLIC KEY. It points at a public-key certificate - by issuer
// and serial, or by name, or by a hash of the key - and adds privileges to
// whoever holds that. Signed by an Attribute Authority, which is usually not
// the CA that issued the identity.
//
// ⚠ WHY THE SEPARATION MATTERS, AND WHY IT IS A TRAP.
//
// Identity is long-lived and authorisation is not: a person keeps their name
// for years and loses a role in an afternoon. Splitting them means the short-
// lived statement can expire in hours without reissuing the key.
//
// The trap is that an attribute certificate LOOKS like a certificate and
// verifies like one, so a system that checks the signature and reads the
// attributes has skipped the step that matters: CONFIRMING THE HOLDER IS THE
// ENTITY IT IS TALKING TO. An attribute certificate naming Alice, presented
// by Bob, verifies perfectly.
//
// So `holder` is reported in full and `holder_binding` says which of the
// three forms was used - because they are not equally strong, and a caller
// has to know which one they are relying on.

import * as DER from './der_reader.js';
import * as F from './fields.js';
import * as OID from './oid.js';
import * as ALG from './algorithm.js';
import * as X509 from './x509.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, hex, int_value } from './commons/bytes.js';

// Imported for the shared PKIX structures.
import './pkix.js';
import './x509.js';

var fail = make_fail_here('attrcert');

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

//   IssuerSerial ::= SEQUENCE {
//        issuer     GeneralNames,
//        serial     CertificateSerialNumber,
//        issuerUID  UniqueIdentifier OPTIONAL }
F.define('AC_IssuerSerial', [
  { name: 'issuer', type: 'raw' },
  { name: 'serial', type: 'integer' },
  { name: 'issuerUID', type: 'bit_string', optional: true }
]);

//   ObjectDigestInfo ::= SEQUENCE {
//        digestedObjectType   ENUMERATED { publicKey(0), publicKeyCert(1),
//                                          otherObjectTypes(2) },
//        otherObjectTypeID    OBJECT IDENTIFIER OPTIONAL,
//        digestAlgorithm      AlgorithmIdentifier,
//        objectDigest         BIT STRING }
F.define('ObjectDigestInfo', [
  { name: 'digestedObjectType', type: 'enumerated' },
  { name: 'otherObjectTypeID',  type: 'oid', optional: true },
  { name: 'digestAlgorithm',    type: 'AlgorithmIdentifier' },
  { name: 'objectDigest',       type: 'bit_string' }
]);

//   AttCertValidityPeriod ::= SEQUENCE {
//        notBeforeTime  GeneralizedTime,
//        notAfterTime   GeneralizedTime }
//
// ⚠ GeneralizedTime FOR BOTH, ALWAYS - unlike a public-key certificate,
// where RFC 5280 requires UTCTime before 2050 and GeneralizedTime after.
// An attribute certificate has no such rule, and a reader that applied the
// X.509 one would refuse a valid file.
F.define('AttCertValidityPeriod', [
  { name: 'notBeforeTime', type: 'generalized_time' },
  { name: 'notAfterTime',  type: 'generalized_time' }
]);

//   Attribute ::= SEQUENCE {
//        type    AttributeType,
//        values  SET OF AttributeValue }
F.define('AC_Attribute', [
  { name: 'type',   type: 'oid' },
  { name: 'values', type: 'raw' }
]);

F.define('AC_Attributes', { kind: 'sequence_of', of: 'AC_Attribute', min: 1 });

//   AttributeCertificateInfo ::= SEQUENCE {
//        version                 AttCertVersion,  -- v2
//        holder                  Holder,
//        issuer                  AttCertIssuer,
//        signature               AlgorithmIdentifier,
//        serialNumber            CertificateSerialNumber,
//        attrCertValidityPeriod  AttCertValidityPeriod,
//        attributes              SEQUENCE OF Attribute,
//        issuerUniqueID          UniqueIdentifier OPTIONAL,
//        extensions              Extensions OPTIONAL }
F.define('AttributeCertificateInfo', [
  { name: 'version',    type: 'unsigned' },
  { name: 'holder',     type: 'raw' },
  { name: 'issuer',     type: 'raw' },
  { name: 'signature',  type: 'AlgorithmIdentifier' },
  { name: 'serialNumber', type: 'integer' },
  { name: 'validity',   type: 'AttCertValidityPeriod' },
  { name: 'attributes', type: 'AC_Attributes' },
  { name: 'issuerUniqueID', type: 'bit_string', optional: true },
  { name: 'extensions', type: 'Extensions', optional: true }
]);

F.define('AttributeCertificate', [
  { name: 'acinfo',             type: 'AttributeCertificateInfo' },
  { name: 'signatureAlgorithm', type: 'AlgorithmIdentifier' },
  { name: 'signatureValue',     type: 'bit_string' }
]);

// ---------------------------------------------------------------------------
// The attributes RFC 5755 defines
// ---------------------------------------------------------------------------

// Section 4.4. Each one names a different kind of privilege, and the value
// shapes differ - which is why they are listed rather than treated as opaque.
var KNOWN_ATTRIBUTES = {
  '1.3.6.1.5.5.7.10.1': { name: 'authenticationInfo', kind: 'service' },
  '1.3.6.1.5.5.7.10.2': { name: 'accessIdentity',     kind: 'service' },
  '1.3.6.1.5.5.7.10.3': { name: 'chargingIdentity',   kind: 'identity' },
  '1.3.6.1.5.5.7.10.4': { name: 'group',              kind: 'identity' },
  '2.5.4.72':           { name: 'role',               kind: 'role' },
  '2.5.4.55':           { name: 'clearance',          kind: 'clearance' }
};

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

function from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var seq = r.read_sequence();

    // ⚠ THE SIGNED PORTION, AS IT ARRIVED.
    //
    // The same rule as every other signed structure here: the bytes are a
    // slice, never a re-encode. A structure whose DER deviates from
    // canonical form would hash differently after a round trip and its
    // signature would fail for reasons that look like a bad key.
    // ⚠ THE SIGNED SPAN, TAKEN BEFORE READING.
    //
    // `peek` the position, read the structure, and the span is what was
    // consumed. The first version reset a reader's cursor to a `start`
    // property that does not exist, which produced a tag read past the end
    // of the input - and that in turn crashed the tag table rather than
    // failing cleanly. Both are fixed; the second was a real bug in
    // tags.js.
    var start = seq.pos;
    var info = read_info(seq);
    var tbs_end = seq.pos;

    var alg = F.read_type(seq, 'AlgorithmIdentifier');
    var sig = seq.read_bit_string();
    seq.expect_end();

    if (sig.unused !== 0) {
      fail('bad-signature-bits',
        'the signature BIT STRING has ' + sig.unused + ' unused bits');
    }

    // RFC 5755 4.1: the two algorithm identifiers must agree. A file where
    // they differ is signed with one algorithm and claims another, and only
    // one of the two is covered by the signature.
    var inner = OID.to_string(info.signature_alg_bytes);
    var outer = OID.to_string(alg.algorithm);

    if (inner !== outer) {
      fail('algorithm-mismatch',
        'the inner algorithm is ' + inner + ' and the outer is ' + outer +
        '. Only the inner one is signed.');
    }

    info.tbs_bytes = bytes.subarray(start, tbs_end);
    info.signature_algorithm = OID.name_of(alg.algorithm) || outer;
    info.signature_params = ALG.describe_signature(alg, sig.bytes, fail);
    info.signature = sig.bytes;
    info.der = bytes;

    return info;
  });
}

function read_info(r) {
  var parsed = F.read_type(r, 'AttributeCertificateInfo');

  // RFC 5755 4.2.6: the validity times "MUST NOT include fractional
  // seconds". GeneralizedTime may carry a minimal fraction in DER (X.690
  // 11.7) - RFC 3161 timestamps do - so the PROFILE rule is applied here,
  // where the profile is known, not in the encoding reader.
  [['notBeforeTime', 'not_before'], ['notAfterTime', 'not_after']].forEach(
    function (k) {
      var t = parsed.validity[k[0]];
      if (t.fraction !== null && t.fraction !== undefined) {
        fail('fractional-seconds',
          k[1] + ' has fractional seconds, which RFC 5755 4.2.6 forbids');
      }
    });
  var version = int_value(parsed.version, 'version');

  // RFC 5755 4.1: version is v2, encoded as 1. There is no v1 in this
  // profile - the v1 form is a different structure entirely, from RFC 3369,
  // and reading one as the other would misplace every field.
  if (version !== 1) {
    fail('bad-version',
      'RFC 5755 attribute certificates are version 2 (encoded as 1), this ' +
      'says ' + version + '. Version 1 is a different structure from RFC ' +
      '3369, not an older spelling of this one.');
  }

  var holder = read_holder(parsed.holder);
  var issuer = read_issuer(parsed.issuer);

  return {
    version:  2,
    holder:   holder,
    // ⚠ WHICH FORM THE HOLDER USES, because they are not equally strong.
    holder_binding: holder.binding,
    issuer:   issuer,
    serial:   parsed.serialNumber,
    serial_hex: hex(parsed.serialNumber),
    validity: {
      not_before: parsed.validity.notBeforeTime,
      not_after:  parsed.validity.notAfterTime
    },
    attributes: read_attributes(parsed.attributes),
    extensions: read_extensions(parsed.extensions),
    signature_alg_bytes: parsed.signature.algorithm
  };
}

//   Holder ::= SEQUENCE {
//        baseCertificateID  [0] IssuerSerial OPTIONAL,
//        entityName         [1] GeneralNames OPTIONAL,
//        objectDigestInfo   [2] ObjectDigestInfo OPTIONAL }
//
// ⚠ THREE WAYS TO NAME A HOLDER, AND THEY BIND DIFFERENTLY.
//
//   baseCertificateID  names one certificate exactly. The strongest: the
//                      privilege attaches to a specific key.
//   entityName         names a person or service. Weaker - anybody holding
//                      A certificate with that name matches, including one
//                      from a different CA.
//   objectDigestInfo   a hash of the key or certificate. Strong, and rare.
//
// A verifier that accepts `entityName` without also pinning which CA may
// issue that name has accepted a privilege that any CA in its trust store
// can grant.
function read_holder(bytes) {
  if (bytes === undefined || bytes === null) {
    fail('no-holder', 'an attribute certificate with no holder grants a ' +
      'privilege to nobody in particular');
  }

  return DER.read(bytes, function (r) {
    var seq = r.read_sequence();
    var out = { base_certificate: null, entity_names: null,
                object_digest: null, binding: null };

    if (seq.peek_tag() === 0xA0) {
      var b = seq.read_implicit(0, 0x30);
      var is = F.read_type_from(b, 'AC_IssuerSerial');
      out.base_certificate = {
        issuer: general_names(is.issuer),
        serial: is.serial,
        serial_hex: hex(is.serial)
      };
      out.binding = 'base-certificate-id';
    }

    if (seq.peek_tag() === 0xA1) {
      var n = seq.read_implicit(1, 0x30);
      out.entity_names = names_in(n);
      if (out.binding === null) {
        out.binding = 'entity-name';
      }
    }

    if (seq.peek_tag() === 0xA2) {
      var d = seq.read_implicit(2, 0x30);
      out.object_digest = F.read_type_from(d, 'ObjectDigestInfo');
      if (out.binding === null) {
        out.binding = 'object-digest';
      }
    }

    seq.expect_end();

    if (out.binding === null) {
      fail('empty-holder',
        'the Holder names nobody: all three fields are absent');
    }

    return out;
  });
}

//   AttCertIssuer ::= CHOICE {
//        v1Form   GeneralNames,
//        v2Form   [0] IMPLICIT V2Form }
function read_issuer(bytes) {
  return DER.read(bytes, function (r) {
    if (r.peek_tag() === 0xA0) {
      var v2 = r.read_implicit(0, 0x30);
      var out = { form: 'v2', names: null, base_certificate: null };

      if (v2.peek_tag() === 0x30) {
        out.names = names_in(v2.read_sequence());
      }

      v2.pos = v2.end;
      return out;
    }

    var seq = r.read_sequence();
    return { form: 'v1', names: names_in(seq), base_certificate: null };
  });
}

function general_names(bytes) {
  return DER.read(bytes, function (r) {
    return names_in(r.read_sequence());
  });
}

// Reuses x509.js's GeneralName reader, so a name in an attribute certificate
// comes back in the same shape as a subjectAltName - including the UPN
// decoding, which is how a Windows deployment names a holder.
function names_in(r) {
  var out = [];

  while (r.remaining() > 0) {
    out.push(X509.read_general_name(r));
  }

  return out;
}

function read_attributes(list) {
  var out = [];
  var i;

  for (i = 0; i < list.length; i++) {
    var dotted = OID.to_string(list[i].type);
    var known = KNOWN_ATTRIBUTES[dotted];

    out.push({
      id:   dotted,
      name: known === undefined
        ? (OID.name_of(list[i].type) || null)
        : known.name,
      kind: known === undefined ? null : known.kind,
      // ⚠ THE VALUES ARE KEPT WHOLE.
      //
      // What an attribute holds depends on its type, and the types outside
      // RFC 5755 are defined by whoever deployed them. Guessing would
      // produce a reading nobody agreed to; the bytes are exact.
      values: list[i].values
    });
  }

  return out;
}

function read_extensions(list) {
  if (list === undefined || list === null) {
    return [];
  }

  var out = [];
  var i;

  for (i = 0; i < list.length; i++) {
    out.push(X509.extension_entry(list[i]));
  }

  return out;
}

// ---------------------------------------------------------------------------
// Using
// ---------------------------------------------------------------------------

// ⚠ THE CHECK A CALLER WILL FORGET.
//
// An attribute certificate naming Alice, presented by Bob, verifies
// perfectly - the signature is real and the structure is sound. What makes
// it Bob's to use is the HOLDER binding, and that has to be checked against
// the identity certificate the caller actually authenticated.
//
// This returns whether the given public-key certificate is the holder, and
// says which form it matched on - because entityName is a weaker statement
// than baseCertificateID and a caller relying on one should know which.
function holder_is(ac, cert) {
  var h = ac.holder;

  if (h.base_certificate !== null) {
    var matches_serial = hex(cert.serial) === h.base_certificate.serial_hex;
    var matches_issuer = h.base_certificate.issuer.some(function (n) {
      return n.type === 'directory' &&
             X509.name_matches(n.value, cert.issuer);
    });

    return {
      holder: matches_serial && matches_issuer,
      by: 'base-certificate-id',
      strength: 'this names one certificate exactly'
    };
  }

  if (h.entity_names !== null) {
    var matched = h.entity_names.some(function (n) {
      if (n.type === 'directory') {
        return X509.name_matches(n.value, cert.subject);
      }
      return false;
    });

    return {
      holder: matched,
      by: 'entity-name',
      // ⚠ THE WARNING THAT BELONGS HERE.
      strength: 'this names a SUBJECT, not a certificate - any certificate ' +
                'with that subject matches, including one from a different ' +
                'CA. Pin which issuers may name this holder, or the ' +
                'privilege is grantable by every CA you trust.'
    };
  }

  return {
    holder: false,
    by: 'object-digest',
    strength: 'the holder is named by a digest of the key or certificate, ' +
              'which this library does not compute'
  };
}

// What has to be verified, and over which bytes.
function verification_plan(ac) {
  return {
    algorithm: ac.signature_algorithm,
    bytes:     ac.tbs_bytes,
    signature: ac.signature,
    // ⚠ AND THE STEP THAT IS NOT A SIGNATURE CHECK.
    also: 'confirm the holder binding against the identity certificate you ' +
          'authenticated - see holder_is(). A valid signature says the ' +
          'Attribute Authority issued this, not that the party in front of ' +
          'you is its holder.'
  };
}

// `when` defaults to now, as x509.validity_contains's does - this one
// required it, and called with one argument threw a TypeError.
function validity_contains(ac, when) {
  var t = (when === undefined ? new Date() : when).getTime();
  return t >= ac.validity.not_before.date.getTime() &&
         t <= ac.validity.not_after.date.getTime();
}

export {
  from_der,
  holder_is,
  verification_plan,
  validity_contains,
  KNOWN_ATTRIBUTES
};
