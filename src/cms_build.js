// Building CMS SignedData - RFC 5652.
//
// ⚠ THE ONE BYTE THAT DECIDES EVERYTHING.
//
// signedAttrs travel in the message tagged [0] IMPLICIT - 0xA0 - and the
// signature is computed over the SAME BYTES with a SET tag, 0x31. RFC 5652
// section 5.4 says so in one sentence, and getting it wrong produces a
// message that encodes, parses, and verifies nowhere.
//
// cms.js reports this on the reading side and the note in verification_plan
// spells it out. This module has to produce it, so prepare() returns the
// 0x31 form as `bytes` and assemble() writes the 0xA0 form, from the same
// bytes.
//
// ⚠ AND THE SIGNATURE DOES NOT COVER THE CONTENT DIRECTLY.
//
// When signedAttrs are present - which they must be for anything but the
// simplest message - the signature covers the ATTRIBUTES, and one of those
// attributes holds the digest of the content. Two hashes, and a verifier that
// checks only the second has verified a signature unconnected to anything.
//
// So prepare() requires the content digest as an argument rather than
// computing it: this library performs no cryptography, and a messageDigest
// attribute the caller did not compute is one they cannot check.

import * as W from './der_writer.js';
import * as OID from './oid.js';
import * as CMS from './cms.js';
import * as ALG from './algorithm.js';
import * as X509 from './x509.js';
import { time_to_der, digest_algorithm_to_der, algorithm_to_der,
  encapsulated_to_der,
  name_to_der, issuer_and_serial_to_der } from './pkix.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, hex } from './commons/bytes.js';

var fail = make_fail_here('cms');

// ---------------------------------------------------------------------------
// The attributes RFC 5652 requires
// ---------------------------------------------------------------------------

var ATTR = {
  contentType:   '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime:   '1.2.840.113549.1.9.5',
  // RFC 5035, and CAdES builds on it. Present here because a caller adding
  // it by hand would have to know the OID.
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47'
};

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

// Prepares a SignerInfo and returns the bytes to sign, as every builder
// here does:
//
//   var p   = cms_build.prepare({ ..., content_digest: sha256(content) });
//   var sig = sign(p.signature_algorithm, key, p.bytes);
//   var der = cms_build.assemble(p, sig);
//
// `bytes` is the signedAttrs in their 0x31 form - or, with
// signed_attrs: false, the content itself, which is then what is signed.
function prepare(parts) {
  if (parts === null || typeof parts !== 'object') {
    fail('bad-input', 'prepare takes an object describing the message');
  }

  var cert = parts.certificate;

  if (!cert || !cert.subject || !cert.serial) {
    fail('bad-certificate',
      'prepare needs { certificate }, as x509.from_der returned it - the ' +
      'SignerInfo names the signer by its issuer and serial');
  }

  var digest_name = parts.digest;

  if (typeof digest_name !== 'string') {
    fail('bad-digest', 'prepare needs { digest: "sha256" }');
  }

  if (OID.digest_size(digest_name) === null) {
    fail('unsupported-digest', 'unrecognised digest ' + digest_name);
  }

  var algorithm = parts.signature_algorithm;

  if (typeof algorithm !== 'string') {
    fail('bad-algorithm', 'prepare needs { signature_algorithm: "ecdsaWithSHA256" }');
  }

  try {
    OID.by_name(algorithm);
  } catch (e) {
    fail('unknown-algorithm',
      '"' + algorithm + '" is not a known signature algorithm');
  }

  var content_type = parts.content_type || 'data';
  var content_oid = CMS.CONTENT[content_type];

  if (content_oid === undefined) {
    if (/^\d+(\.\d+)+$/.test(content_type)) {
      content_oid = content_type;
    } else {
      fail('unknown-content-type',
        '"' + content_type + '" is not a known CMS content type');
    }
  }

  // ⚠ DETACHED MEANS THE CONTENT IS NOT IN THE MESSAGE, NOT THAT IT IS
  //    IRRELEVANT.
  //
  // The signature still covers its digest. A caller who set detached and
  // passed no content would get a message nobody can verify without the
  // content they did not keep - so the digest is required either way, and
  // that is the same argument.
  var detached = parts.detached === true;

  if (!detached && parts.content === undefined) {
    fail('no-content',
      'an attached message needs { content }. Set { detached: true } if ' +
      'the content travels separately.');
  }

  var content = detached ? null : to_bytes(parts.content);

  // ⚠ signedAttrs ARE ALL BUT MANDATORY.
  //
  // RFC 5652 5.3: if the content type is anything other than `data`, they
  // are REQUIRED. And without them the signature covers the content
  // directly, which means no signing time, no algorithm binding, and no way
  // to add anything later - so the default is on and turning it off is a
  // decision.
  var use_attrs = parts.signed_attrs !== false;

  if (!use_attrs && content_type !== 'data') {
    fail('attrs-required',
      'RFC 5652 5.3 requires signedAttrs when the content type is not ' +
      '`data`, because contentType is one of them and there would be ' +
      'nothing binding the signature to the type');
  }

  var si = {
    content:      content,
    content_type: content_type,
    content_oid:  content_oid,
    detached:     detached,
    certificate:  cert,
    digest:       digest_name,
    signature_algorithm: algorithm,
    use_attrs:    use_attrs,
    signing_time: parts.signing_time || null,
    extra_attrs:  parts.attributes || [],
    signed_attrs_set: null,
    bytes:        null
  };

  if (use_attrs) {
    // ⚠ THE 0x31 FORM. See the note at the top of this file.
    si.bytes = attrs_to_sign(si, parts.content_digest);
  } else {
    if (content === null) {
      fail('detached-without-attrs',
        'a detached message with no signedAttrs has nothing this module ' +
        'can hand you: the signature covers content you are holding');
    }
    if (parts.content_digest !== undefined) {
      fail('has-no-signed-attrs',
        'without signedAttrs the signature covers the content itself, so ' +
        'no content_digest goes into the message - leave it out');
    }
    si.bytes = content;
  }

  return si;
}

// ---------------------------------------------------------------------------
// The attributes
// ---------------------------------------------------------------------------

// ⚠ RETURNS THE BYTES WITH A SET TAG, WHICH IS NOT THE TAG THEY TRAVEL WITH.
//
// RFC 5652 5.4. assemble() writes the same attributes with 0xA0, and the two
// must be the same bytes otherwise - so they are built once, here, and cached
// on the object.
function attrs_to_sign(si, content_digest) {
  var signed_form = content_attributes({
    content_oid: si.content_oid, digest: si.digest,
    content_digest: content_digest, signing_time: si.signing_time,
    attributes: si.extra_attrs
  });

  // Kept so assemble() writes the same bytes with the other tag.
  si.signed_attrs_set = signed_form;

  return signed_form;
}

// ⚠ THE ATTRIBUTES THAT BIND A SIGNATURE - OR AuthenticatedData's MAC - TO
// THE CONTENT, as the SET OF DER that is signed or MACed (RFC 5652 5.4,
// 9.2): contentType, messageDigest, signingTime when given, and the
// caller's. cms_enveloped_build writes AuthenticatedData's authAttrs with
// this, so the two cannot drift.
function content_attributes(opts) {
  var content_digest = opts.content_digest;

  if (!(content_digest instanceof Uint8Array)) {
    fail('bad-digest-value',
      'prepare needs { content_digest }: the digest OF THE CONTENT, as ' +
      'bytes, with the digest it names. This library computes no hashes.');
  }

  var expected = OID.digest_size(opts.digest);

  if (expected !== null && content_digest.length !== expected) {
    fail('bad-digest-length',
      opts.digest + ' produces ' + expected + ' bytes and this digest is ' +
      content_digest.length + '. A messageDigest of the wrong length means ' +
      'a different hash was used than the one the message names.');
  }

  var attributes = [];

  // ⚠ contentType AND messageDigest ARE REQUIRED, RFC 5652 5.3, and the
  // ORDER IS NOT UP TO US - a SET OF is sorted by encoding, which the writer
  // does. Building them in any order gives the same bytes.
  attributes.push(attribute(ATTR.contentType,
    [W.oid(OID.from_string(opts.content_oid))]));

  attributes.push(attribute(ATTR.messageDigest,
    [W.octet_string(content_digest)]));

  if (opts.signing_time !== null && opts.signing_time !== undefined) {
    attributes.push(attribute(ATTR.signingTime,
      [time_to_der(opts.signing_time)]));
  }

  var extra = opts.attributes || [];
  var i;

  for (i = 0; i < extra.length; i++) {
    attributes.push(extra_attribute(extra[i]));
  }

  // Built as a SET OF, which sorts.
  return W.to_bytes(W.set_of(attributes));
}

// A caller's { type, value } attribute - a name from ATTR or a dotted OID,
// and the value's DER. Shared with cms_enveloped_build, whose AuthEnveloped
// Data carries attributes of the same shape.
function extra_attribute(extra) {
  if (!extra || typeof extra !== 'object' || extra.value === undefined) {
    fail('bad-attribute', 'an attribute is { type, value } - value is DER');
  }

  var oid = /^\d+(\.\d+)+$/.test(extra.type)
    ? extra.type
    : (ATTR[extra.type] || null);

  if (oid === null) {
    fail('unknown-attribute',
      '"' + extra.type + '" is not a known attribute. Pass a dotted OID.');
  }

  return attribute(oid, [to_bytes(extra.value)]);
}

function attribute(oid, values) {
  return W.sequence([
    W.oid(OID.from_string(oid)),
    W.set_of(values)
  ]);
}


// ---------------------------------------------------------------------------
// Assembling
// ---------------------------------------------------------------------------

// An ML-DSA or SLH-DSA signer: its digestAlgorithm goes in without
// parameters (RFC 9882 3.3, RFC 9814 4).
function pq_signer(si) {
  return ALG.signature_length(si.signature_algorithm) !== undefined;
}

function assemble(si, signature, options) {
  if (si === null || typeof si !== 'object' || si.content_oid === undefined) {
    fail('bad-signer',
      'assemble takes what prepare() returned: assemble(prepared, signature)');
  }

  if (!(signature instanceof Uint8Array)) {
    fail('bad-signature', 'the signature is bytes');
  }

  // ⚠ THE SAME CHECK x509_build MAKES, AND FOR THE SAME REASON.
  //
  // A caller holding a 64-byte r||s from a JOSE library would produce a
  // message nothing verifies. A DER signature starts 0x30.
  if (signature.length > 0 && signature[0] !== 0x30 &&
      /ecdsa/i.test(si.signature_algorithm)) {
    fail('raw-signature',
      'this looks like a raw r||s signature. CMS carries ECDSA signatures ' +
      'as SEQUENCE { r, s } - convert it with signature.raw_to_der({ raw: ' +
      'sig, curve: ... }).');
  }

  ALG.check_signature_length({ name: si.signature_algorithm,
    signature_length: ALG.signature_length(si.signature_algorithm) },
    signature, fail);

  var opts = options || {};
  var certificates = opts.certificates || [si.certificate];

  // --- SignerInfo ---------------------------------------------------------

  var signer_fields = [
    // ⚠ VERSION 1 WITH issuerAndSerialNumber, 3 WITH subjectKeyIdentifier -
    // RFC 5652 5.3. This module names the signer by issuer and serial, so
    // the version is 1 and a reader checking the pairing is satisfied.
    W.integer([0x01]),

    // ⚠ THE ISSUER MUST MATCH THE CERTIFICATE BYTE FOR BYTE.
    //
    // That is how a verifier finds the signer's certificate among the ones
    // the message carries. So no attribute encoder is passed: a name written
    // by hand is refused with `bad-name`, because a hand-written name that
    // happens to differ in string type from the certificate's produces a
    // message where nothing matches and the reason is invisible.
    //
    // Hand over the object x509.from_der returned and the bytes pass
    // through untouched.
    issuer_and_serial_to_der(si.certificate, fail),

    digest_algorithm_to_der(si.digest, pq_signer(si))
  ];

  if (si.use_attrs) {
    // ⚠ THE SAME BYTES, THE OTHER TAG. 0x31 was signed; 0xA0 travels.
    var travelling = si.signed_attrs_set.slice();
    travelling[0] = 0xA0;
    signer_fields.push(travelling);
  }

  signer_fields.push(algorithm_to_der(si.signature_algorithm));
  signer_fields.push(W.octet_string(signature));

  var signer_info = W.sequence(signer_fields);

  // --- SignedData ---------------------------------------------------------


  var signed_fields = [
    // ⚠ VERSION 1 unless something in the message needs more - RFC 5652
    // 5.1. Attribute certificates and non-data content types raise it, and
    // neither is produced here.
    W.integer([0x01]),

    // digestAlgorithms: a SET, and it must list every digest any SignerInfo
    // uses. One signer, one digest.
    W.set_of([digest_algorithm_to_der(si.digest, pq_signer(si))]),

    encapsulated_to_der(si.content_oid, si.content)
  ];

  if (certificates.length > 0) {
    signed_fields.push(W.implicit(0, W.set_of(
      certificates.map(certificate_der))));
  }

  signed_fields.push(W.set_of([signer_info]));

  return W.to_bytes(W.sequence([
    W.oid(OID.from_string(CMS.CONTENT.signedData)),
    W.explicit(0, W.sequence(signed_fields))
  ]));
}

// ---------------------------------------------------------------------------

// ⚠ A DEGENERATE SignedData: certificates and no signers.
//
// This is what a .p7b is, and building one needs none of the above - no
// digest, no signature, no signer. RFC 5652 5.1 defines it explicitly.
function bundle(certificates) {
  if (!Array.isArray(certificates) || certificates.length === 0) {
    fail('no-certificates',
      'a certificate bundle with no certificates carries nothing');
  }

  return W.to_bytes(W.sequence([
    W.oid(OID.from_string(CMS.CONTENT.signedData)),
    W.explicit(0, W.sequence([
      W.integer([0x01]),
      // Empty: nothing is signed, so no digest is used.
      W.set_of([]),
      encapsulated_to_der(CMS.CONTENT.data, null),
      W.implicit(0, W.set_of(certificates.map(certificate_der))),
      W.set_of([])
    ]))
  ]));
}

// ---------------------------------------------------------------------------

function certificate_der(cert) {
  if (cert instanceof Uint8Array) {
    return cert;
  }

  if (cert && cert.der instanceof Uint8Array) {
    // ⚠ THE ORIGINAL BYTES, not a re-encode. A certificate re-encoded into
    // a message would hash differently from the one the CA signed, and its
    // own signature would stop verifying.
    return cert.der;
  }

  fail('bad-certificate',
    'a certificate is the DER, or the object x509.from_der returned');
}




export {
  prepare,
  assemble,
  bundle,
  attribute,
  extra_attribute,
  content_attributes,
  ATTR
};
