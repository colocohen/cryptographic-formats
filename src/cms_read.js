// The reader-side pieces of CMS that more than one content type uses:
// SignedData (cms.js), and AuthenticatedData and DigestedData
// (cms_enveloped.js). Internal - cms.js re-exports the two tables.
//
// Readers only: cms_build and cms_enveloped_build write these structures
// with their own code, so a mistake here cannot be cancelled out by the
// same mistake in a writer (src/commons/README.md).

import * as DER from './der_reader.js';
import * as F from './fields.js';
import * as OID from './oid.js';

import { make_fail_here } from './commons/fail.js';
import { to_array, to_bytes } from './commons/bytes.js';

var fail = make_fail_here('cms');

// ---------------------------------------------------------------------------
// Content types
// ---------------------------------------------------------------------------

var CONTENT = {
  data:             '1.2.840.113549.1.7.1',
  signedData:       '1.2.840.113549.1.7.2',
  envelopedData:    '1.2.840.113549.1.7.3',
  digestedData:     '1.2.840.113549.1.7.5',
  encryptedData:    '1.2.840.113549.1.7.6',
  authenticatedData: '1.2.840.113549.1.9.16.1.2',
  // RFC 3274.
  compressedData:   '1.2.840.113549.1.9.16.1.9',
  // RFC 5083: EnvelopedData for an AEAD cipher - the tag travels as `mac`.
  authEnvelopedData: '1.2.840.113549.1.9.16.1.23',
  // RFC 3161. A timestamp token is a CMS SignedData whose content is a
  // TSTInfo, which is why TSP needs almost nothing beyond this module.
  tstInfo:          '1.2.840.113549.1.9.16.1.4'
};

// RFC 5652 section 11. The first two are MANDATORY when signedAttrs is
// present, and a message missing either is one where the link between the
// signature and the content has a hole in it.
var ATTRIBUTE = {
  contentType:   '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime:   '1.2.840.113549.1.9.5',
  // RFC 3161 appendix A: the countersignature that carries a timestamp.
  timeStampToken: '1.2.840.113549.1.9.16.2.14',
  cmsAlgorithmProtection: '1.2.840.113549.1.9.52',
  // RFC 2634 5.4 and RFC 5035: the signer's certificate, bound by hash -
  // RFC 3161 2.4.2 requires one of these in every timestamp token.
  signingCertificate:   '1.2.840.113549.1.9.16.2.12',
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47'
};


// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------


F.define('CmsAttribute', [
  { name: 'type',   type: 'oid' },
  { name: 'values', type: 'raw' }
]);


//   EncapsulatedContentInfo ::= SEQUENCE {
//        eContentType  ContentType,
//        eContent  [0] EXPLICIT OCTET STRING OPTIONAL }
//
// eContent ABSENT is a DETACHED signature: the content travels separately and
// the caller supplies it. That is the normal case for code signing and for a
// signed file, so it is a first-class state rather than an error.
function read_encapsulated(r) {
  var eci = r.read_sequence();
  var type_oid = eci.read_oid();
  var type = OID.name_in_table(type_oid, CONTENT);

  var content = null;

  if (eci.remaining() > 0) {
    var wrapper = eci.read_explicit(0);
    content = wrapper.read_octet_string();
    wrapper.expect_end();
  }

  eci.expect_end();

  return {
    type: type === null ? OID.to_string(type_oid) : type,
    type_oid: type_oid,
    content: content
  };
}

// The attributes, from a captured [0] IMPLICIT or [1] IMPLICIT region.
function read_attributes(raw) {
  var bytes = to_array(raw);

  // Rewrite the context tag to SET so the generic reader can walk it. This
  // is a local copy for PARSING; the signature substitution is a separate
  // operation in signed_attrs_der, and conflating the two is how the wrong
  // bytes end up hashed.
  var copy = bytes.slice();
  copy[0] = 0x31;

  return DER.read(new Uint8Array(copy), function (r) {
    var set = r.read_set_of();
    var out = [];
    var seen = {};

    while (set.remaining() > 0) {
      var attr = F.read_type(set, 'CmsAttribute');
      var id = OID.to_string(attr.type);

      // RFC 5652 5.3: an attribute type appears at most once. Two copies is
      // a message with two answers, and a verifier reading one while a
      // policy check reads the other is the whole problem.
      if (Object.prototype.hasOwnProperty.call(seen, id)) {
        fail('duplicate-attribute',
          'attribute ' + id + ' appears more than once');
      }
      seen[id] = true;

      out.push({
        id:    id,
        oid:   attr.type,
        name:  OID.name_in_table(attr.type, ATTRIBUTE),
        value: attr.values
      });
    }

    set.expect_end();
    return out;
  });
}

// RFC 5652 section 11.1 and 11.2: when signedAttrs - or AuthenticatedData's
// authAttrs, 9.2 - are present, content-type and message-digest MUST be.
//
// Without message-digest the signature (or MAC) covers a set of attributes
// that says nothing about the content, and the content could be replaced
// freely. Without content-type the same attributes could be replayed under
// a different content type.
//
// Returns { message_digest, content_type, signing_time } - the last
// undefined when absent. `what` names the field in the refusal.
function required_attributes(attrs, what) {
  var have = {};
  var i;

  for (i = 0; i < attrs.length; i++) {
    if (attrs[i].name !== null) {
      have[attrs[i].name] = attrs[i];
    }
  }

  if (have.contentType === undefined) {
    fail('missing-content-type',
      what + ' is present without a content-type attribute, so these ' +
      'attributes could be replayed under a different content type');
  }
  if (have.messageDigest === undefined) {
    fail('missing-message-digest',
      what + ' is present without a message-digest attribute, so the ' +
      'signature says nothing about the content');
  }

  var out = {
    message_digest: DER.read(have.messageDigest.value, function (r) {
      var set = r.read_set_of();
      var d = set.read_octet_string();
      set.expect_end();
      return d;
    }),
    content_type: DER.read(have.contentType.value, function (r) {
      var set = r.read_set_of();
      var oid = set.read_oid();
      set.expect_end();
      return OID.name_in_table(oid, CONTENT) || OID.to_string(oid);
    }),
    signing_time: undefined
  };

  if (have.signingTime !== undefined) {
    // NOT trustworthy on its own: it is whatever the signer's clock said,
    // signed by the signer. A timestamp from a third party is the
    // unsignedAttrs timeStampToken, and that is a different claim.
    out.signing_time = DER.read(have.signingTime.value, function (r) {
      var set = r.read_set_of();
      var t = set.read_time();
      set.expect_end();
      return t;
    });
  }

  return out;
}

// When signedAttrs (or authAttrs) is ABSENT, the signature (or MAC) is over
// the content octets
// directly - the OCTET STRING's value, not the OCTET STRING.
function content_signing_input(cms, detached_content) {
  var content = cms.content;

  if (content === null) {
    if (detached_content === undefined || detached_content === null) {
      fail('detached-content',
        'this message is detached; supply the content to build the input');
    }
    content = to_bytes(detached_content);
  }

  return content;
}

// ⚠ THE BYTES A SIGNATURE OR MAC OVER ATTRIBUTES COVERS: the field as it
// travels - [0] IMPLICIT signedAttrs, [2] IMPLICIT authAttrs - with the
// UNIVERSAL SET tag 0x31 in place of its own. RFC 5652 5.4 and 9.2.
function set_tagged(raw) {
  var out = to_bytes(raw).slice();
  out[0] = 0x31;
  return out;
}

export {
  content_signing_input,
  set_tagged,
  CONTENT,
  ATTRIBUTE,
  read_encapsulated,
  read_attributes,
  required_attributes
};
