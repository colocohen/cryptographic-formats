// Building attribute certificates - RFC 5755.
//
// ⚠ THE HOLDER BINDING IS THE WHOLE DECISION, AND build() MAKES YOU MAKE IT.
//
// An attribute certificate says what somebody MAY DO. It carries no public
// key - it points at a public-key certificate and adds privileges to whoever
// holds that. And there are three ways to point:
//
//   baseCertificateID  ONE certificate, by issuer and serial. The privilege
//                      attaches to a specific key.
//   entityName         a SUBJECT NAME. Any certificate with that name
//                      matches, INCLUDING ONE FROM A DIFFERENT CA.
//   objectDigestInfo   a hash of the key.
//
// They are not equally strong, and the second is a trap: an Attribution
// Authority that names a holder by subject has granted a privilege that every
// CA in the relying party's trust store can hand to anybody.
//
// So build() requires the form to be named rather than inferring it from
// which field was passed, and refuses entityName without an explicit
// acknowledgement. This is the only place in the library that makes a caller
// say something twice, and it is because the two forms look identical in
// code and differ completely in what they mean.

import * as W from './der_writer.js';
import * as OID from './oid.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, hex, int_bytes } from './commons/bytes.js';

import './pkix.js';
import { algorithm_to_der, name_to_der, attribute_to_der, assemble_signed,
  raw_extensions_to_der, validity_to_der as pkix_validity_to_der, validity_days }
  from './pkix.js';

var fail = make_fail_here('attrcert');

// ---------------------------------------------------------------------------
// The attributes RFC 5755 defines
// ---------------------------------------------------------------------------

var ATTRIBUTES = {
  role:               '2.5.4.72',
  clearance:          '2.5.4.55',
  group:              '1.3.6.1.5.5.7.10.4',
  accessIdentity:     '1.3.6.1.5.5.7.10.2',
  chargingIdentity:   '1.3.6.1.5.5.7.10.3',
  authenticationInfo: '1.3.6.1.5.5.7.10.1'
};

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

function prepare(parts) {
  if (parts === null || typeof parts !== 'object') {
    fail('bad-input', 'prepare takes an object describing the certificate');
  }

  require_field(parts, 'holder');
  require_field(parts, 'issuer');
  require_field(parts, 'serial');
  require_field(parts, 'validity');
  require_field(parts, 'signature_algorithm');
  require_field(parts, 'attributes');

  var fields = [];

  // ⚠ VERSION 2, ENCODED AS 1, AND THERE IS NO VERSION 1 IN THIS PROFILE.
  //
  // The v1 form is a different structure from RFC 3369 with fields in
  // different places - reading one as the other misplaces all of them. So
  // this is fixed rather than a parameter.
  fields.push(W.unsigned(new Uint8Array([1])));

  fields.push(holder_to_der(parts.holder));
  fields.push(issuer_to_der(parts.issuer));
  fields.push(algorithm_to_der(parts.signature_algorithm));

  var serial = to_bytes(parts.serial);

  if (serial.length === 0) {
    fail('bad-serial', 'a serial number needs at least one byte');
  }

  fields.push(W.unsigned(serial));
  fields.push(validity_to_der(parts.validity));
  fields.push(attributes_to_der(parts.attributes));

  var extensions = extensions_to_der(parts.extensions);

  if (extensions !== null) {
    fields.push(extensions);
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
// The holder
// ---------------------------------------------------------------------------

//   Holder ::= SEQUENCE {
//        baseCertificateID  [0] IssuerSerial OPTIONAL,
//        entityName         [1] GeneralNames OPTIONAL,
//        objectDigestInfo   [2] ObjectDigestInfo OPTIONAL }
function holder_to_der(holder) {
  if (holder === null || typeof holder !== 'object') {
    fail('bad-holder',
      'the holder is { certificate } or { name, i_understand_entity_name }');
  }

  // --- baseCertificateID: the strong form -------------------------------

  if (holder.certificate !== undefined) {
    var cert = holder.certificate;

    if (!cert.issuer || !cert.serial) {
      fail('bad-holder-certificate',
        'the holder certificate is the object x509.from_der returned - the ' +
        'binding names it by issuer and serial');
    }

    return W.sequence([
      W.implicit(0, W.sequence([
        // GeneralNames: the issuer, as a [4] directoryName.
        W.sequence([W.explicit(4, name_to_der(cert.issuer))]),
        // The serial's INTEGER content as the reader kept it - written as
        // IssuerAndSerialNumber writes it (pkix.js).
        W.integer(cert.serial)
      ]))
    ]);
  }

  // --- entityName: the weak form ----------------------------------------

  if (holder.name !== undefined) {
    // ⚠ THE ONLY PLACE IN THIS LIBRARY THAT MAKES A CALLER SAY SOMETHING
    //    TWICE.
    //
    // `{ certificate: c }` and `{ name: n }` look identical in code and
    // differ completely in what they mean. Naming a holder by SUBJECT grants
    // the privilege to anybody holding a certificate with that name - from
    // ANY CA the relying party trusts.
    //
    // That is sometimes exactly right, in a closed system with one issuer.
    // It is a hole everywhere else, and the difference is invisible at the
    // call site - so the acknowledgement is required rather than the form
    // being inferred.
    if (holder.i_understand_entity_name !== true) {
      fail('entity-name-not-acknowledged',
        'naming a holder by SUBJECT NAME grants this privilege to anybody ' +
        'holding a certificate with that name - including one issued by a ' +
        'different CA in the relying party\'s trust store. If that is what ' +
        'you mean, pass { i_understand_entity_name: true }. If you meant ' +
        'one specific certificate, pass { certificate } instead.');
    }

    var names = Array.isArray(holder.name) && holder.name.length > 0 &&
                holder.name[0] && holder.name[0].dns !== undefined
      ? holder.name
      : [{ directory: holder.name }];

    return W.sequence([
      W.implicit(1, W.sequence(names.map(general_name_to_der)))
    ]);
  }

  // --- objectDigestInfo --------------------------------------------------

  if (holder.digest !== undefined) {
    var kinds = { publicKey: 0, publicKeyCert: 1, other: 2 };
    var kind = kinds[holder.digest.of];

    if (kind === undefined) {
      fail('bad-digest-type',
        'the digest is OF publicKey, publicKeyCert or other');
    }

    var digest_fields = [W.enumerated(new Uint8Array([kind]))];

    if (kind === 2) {
      if (holder.digest.type_id === undefined) {
        fail('missing-type-id',
          'digesting `other` needs { type_id } to say what was digested');
      }
      digest_fields.push(W.oid(OID.from_string(holder.digest.type_id)));
    }

    digest_fields.push(algorithm_to_der(holder.digest.algorithm));
    digest_fields.push(W.bit_string(to_bytes(holder.digest.value), 0));

    return W.sequence([W.implicit(2, W.sequence(digest_fields))]);
  }

  fail('empty-holder',
    'the holder names nobody. Pass { certificate }, { name }, or ' +
    '{ digest }.');
}

//   AttCertIssuer ::= CHOICE { v1Form GeneralNames, v2Form [0] V2Form }
//
// ⚠ v2Form IS WRITTEN, AND v1Form IS NOT.
//
// RFC 5755 4.2.3 says an issuer MUST use v1Form for compatibility... and
// then 4.1 defines v2Form and every profile since uses it. The two are
// distinguished by a tag, so a reader handles both - but a writer has to
// pick, and picking the one the RFC's own ASN.1 puts second is the choice
// deployments made.
function issuer_to_der(issuer) {
  var names = Array.isArray(issuer) && issuer.length > 0 &&
              issuer[0] && (issuer[0].dns !== undefined ||
                            issuer[0].directory !== undefined)
    ? issuer
    : [{ directory: issuer }];

  return W.implicit(0, W.sequence([
    W.sequence(names.map(general_name_to_der))
  ]));
}

// ---------------------------------------------------------------------------

//   AttCertValidityPeriod ::= SEQUENCE {
//        notBeforeTime  GeneralizedTime,
//        notAfterTime   GeneralizedTime }
//
// ⚠ GeneralizedTime FOR BOTH, ALWAYS - no 2050 pivot.
//
// Unlike a public-key certificate, where RFC 5280 requires UTCTime before
// 2050. Using the certificate rule here produces a structure conforming
// readers refuse, and this library's own reader is one of them.
function validity_to_der(validity) {
  return pkix_validity_to_der(validity, W.generalized_time, fail);
}

function attributes_to_der(attributes) {
  if (!Array.isArray(attributes) || attributes.length === 0) {
    fail('no-attributes',
      'an attribute certificate with no attributes grants nothing, which ' +
      'is not a statement worth signing');
  }

  return W.sequence(attributes.map(function (a) {
    var dotted = ATTRIBUTES[a.type];

    if (dotted === undefined) {
      if (/^\d+(\.\d+)+$/.test(a.type)) {
        dotted = a.type;
      } else {
        fail('unknown-attribute',
          '"' + a.type + '" is not a known attribute type. The six RFC ' +
          '5755 defines are ' + Object.keys(ATTRIBUTES).join(', ') +
          ' - pass a dotted OID for anything else.');
      }
    }

    if (a.values === undefined) {
      fail('no-attribute-values',
        'attribute "' + a.type + '" has no values');
    }

    var values = Array.isArray(a.values) ? a.values : [a.values];

    // ⚠ THE VALUES GO IN AS BYTES.
    //
    // What an attribute holds depends on its type, and the types outside RFC
    // 5755 are defined by whoever deployed them. Encoding a string as a
    // UTF8String when the deployment expects a GeneralName produces an
    // attribute nothing reads.
    return W.sequence([
      W.oid(OID.from_string(dotted)),
      W.set_of(values.map(function (v) {
        if (!(v instanceof Uint8Array)) {
          fail('bad-attribute-value',
            'attribute values are ENCODED BYTES - what an attribute holds ' +
            'depends on its type, and guessing would produce something ' +
            'nobody agreed to read');
        }
        return v;
      }))
    ]);
  }));
}

function extensions_to_der(extensions) {
  var out = raw_extensions_to_der(extensions, fail, 'attribute certificate');
  return out.length === 0 ? null : W.sequence(out);
}

function general_name_to_der(entry) {
  if (entry.directory !== undefined) {
    return W.explicit(4, name_to_der(entry.directory, attribute_to_der));
  }
  if (entry.dns !== undefined) {
    return W.implicit(2, W.ia5_string(entry.dns));
  }
  if (entry.uri !== undefined) {
    return W.implicit(6, W.ia5_string(entry.uri));
  }
  if (entry.email !== undefined) {
    return W.implicit(1, W.ia5_string(entry.email));
  }

  fail('bad-general-name',
    'a name is { directory }, { dns }, { uri } or { email }');
}

function require_field(parts, name) {
  if (parts[name] === undefined || parts[name] === null) {
    fail('missing-' + name, 'prepare needs { ' + name + ' }');
  }
}

// ---------------------------------------------------------------------------
// Checking
// ---------------------------------------------------------------------------

function check(parts) {
  var problems = [];

  if (parts.holder && parts.holder.name !== undefined) {
    problems.push({
      code: 'weak-holder-binding',
      detail: 'this names the holder by SUBJECT, so any certificate with ' +
              'that name matches - including one from a different CA. ' +
              'Relying parties must pin which issuers may name this holder, ' +
              'and nothing in the certificate says so.'
    });
  }

  var days = validity_days(parts.validity);

  if (days !== null) {
    if (days > 365) {
      problems.push({
        code: 'long-validity',
        detail: Math.round(days) + ' days. The point of separating ' +
                'authorisation from identity is that a role can expire in ' +
                'hours without reissuing a key - a year-long attribute ' +
                'certificate gives that up.'
      });
    }
  }

  var serial = parts.serial ? to_bytes(parts.serial) : new Uint8Array(0);

  if (serial.length < 8) {
    problems.push({
      code: 'short-serial',
      detail: 'a short serial is predictable, and an attribute certificate ' +
              'is revoked by serial like any other'
    });
  }

  return problems;
}

export {
  prepare,
  assemble,
  check,
  ATTRIBUTES
};
