// CMS EnvelopedData, RFC 5652 section 6. Encrypted CMS and encrypted S/MIME.
//
// ⚠ THIS IS THE OTHER HALF OF CMS, AND ITS SHAPE IS THE MIRROR OF signedData.
//
// A signed message has one content and several signers, each making a claim
// about it. An enveloped message has one content and several RECIPIENTS, each
// holding a different wrapping of the same key:
//
//   EnvelopedData ::= SEQUENCE {
//        version               CMSVersion,
//        originatorInfo    [0] IMPLICIT OriginatorInfo OPTIONAL,
//        recipientInfos        SET OF RecipientInfo,
//        encryptedContentInfo  EncryptedContentInfo,
//        unprotectedAttrs  [1] IMPLICIT UnprotectedAttributes OPTIONAL }
//
// ⚠ FOUR WAYS A RECIPIENT CAN BE NAMED, AND THEY ARE NOT INTERCHANGEABLE.
//
//   ktri  [0]  key transport - the CEK encrypted to an RSA public key
//   kari  [1]  key agreement - an ephemeral key, ECDH, then a key wrap.
//              This is what OpenSSL produces for an EC recipient, and it is
//              the one with the most moving parts.
//   kekri [2]  a previously distributed symmetric key
//   pwri  [3]  a password
//   ori   [4]  anything else, by OID - of which one is read: KEMRecipientInfo
//              (RFC 9629), how ML-KEM recipients are named (RFC 9936)
//
// A reader that handled only ktri - the obvious one, and the one every
// tutorial shows - would find no recipients at all in a message encrypted to
// an EC certificate, which is what a modern deployment produces.
//
// This library performs no cryptography. It reports which recipients are
// present, what each one needs, and the exact bytes to work on.
//
// AuthEnvelopedData (RFC 5083) is the same message for an AEAD cipher -
// AES-GCM, RFC 5084 - and auth_from_der reads it. It is a different
// structure and not a flag on this one, because GCM's tag needs a place to
// travel (`mac`) and the attributes it authenticates need one too
// (`authAttrs`); EnvelopedData has neither.

import * as DER from './der_reader.js';
import * as F from './fields.js';
import * as OID from './oid.js';
import * as ALG from './algorithm.js';
import * as X509 from './x509.js';
import * as PBES2 from './pbes2.js';
import { PQ_KEYS } from './ec_domain.js';
import { CONTENT, read_encapsulated, read_attributes, required_attributes,
  content_signing_input, set_tagged } from './cms_read.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, hex, bytes_equal, int_value, der_wrap, concat_bytes } from './commons/bytes.js';

// Imported for the shared PKIX structures.
import './pkix.js';

var fail = make_fail_here('cms');

// ---------------------------------------------------------------------------
// Content encryption
// ---------------------------------------------------------------------------

// The algorithms an EncryptedContentInfo names, with the sizes a caller has
// to supply. The nonce length is stated because it differs between modes and
// is the sort of thing a table should answer.
var CONTENT_CIPHERS = {
  aes128CBC:    { key: 16, iv: 16, mode: 'cbc' },
  aes192CBC:    { key: 24, iv: 16, mode: 'cbc' },
  aes256CBC:    { key: 32, iv: 16, mode: 'cbc' },
  aes128GCM:    { key: 16, iv: 12, mode: 'gcm', tag: 16 },
  aes192GCM:    { key: 24, iv: 12, mode: 'gcm', tag: 16 },
  aes256GCM:    { key: 32, iv: 12, mode: 'gcm', tag: 16 },
  des_ede3_cbc: { key: 24, iv: 8,  mode: 'cbc' },
  // ⚠ 56 bits: read so an old SCEP client's request can be described and
  // decrypted by a caller that chooses to; never offered by the builder.
  desCBC:       { key: 8,  iv: 8,  mode: 'cbc', weak: true },
  rc2CBC:       { key: null, iv: 8, mode: 'cbc' }
};

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

// ContentInfo { contentType, [0] EXPLICIT content }, opened and checked to be
// the expected type. Returns { ci, content } - the outer reader, to finish,
// and the reader inside [0]. Written out three times in this module before.
function open_content_info(r, oid, code, name) {
  var ci = r.read_sequence();
  var type_oid = ci.read_oid();

  if (OID.to_string(type_oid) !== oid) {
    fail(code, 'the content type is ' + OID.to_string(type_oid) + ', not ' +
      name);
  }

  return { ci: ci, content: ci.read_explicit(0) };
}

function from_der(input, options) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var opened = open_content_info(r, '1.2.840.113549.1.7.3', 'not-enveloped',
      'envelopedData');
    var ci = opened.ci;
    var wrapper = opened.content;
    var out = read_enveloped(wrapper, options);
    wrapper.expect_end();
    ci.expect_end();

    out.der = bytes;
    return out;
  });
}

// ---------------------------------------------------------------------------
// AuthEnvelopedData - RFC 5083, with AES-GCM from RFC 5084
// ---------------------------------------------------------------------------

//   AuthEnvelopedData ::= SEQUENCE {
//        version                   CMSVersion,       -- always 0
//        originatorInfo        [0] IMPLICIT OriginatorInfo OPTIONAL,
//        recipientInfos            RecipientInfos,
//        authEncryptedContentInfo  EncryptedContentInfo,
//        authAttrs             [1] IMPLICIT AuthAttributes OPTIONAL,
//        mac                       MessageAuthenticationCode,
//        unauthAttrs           [2] IMPLICIT UnauthAttributes OPTIONAL }
//
// Decrypting is one AEAD call, and this returns its four inputs:
//
//   plaintext = aes_gcm_decrypt(cek, content.nonce, content.data,
//                               aad, mac)
//
// ⚠ THE AAD IS NOT THE authAttrs BYTES AS THEY TRAVEL. RFC 5083 2.2: the
// [1] tag is replaced by a SET OF tag (0x31) before authenticating, the same
// substitution signedAttrs makes. `aad` is that encoding - or empty when
// there are no authAttrs, which is ZERO bytes of AAD and not an empty SET.
// Getting either wrong makes every tag check fail, and the message looks
// tampered with.
function auth_from_der(input, options) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var opened = open_content_info(r, '1.2.840.113549.1.9.16.1.23',
      'not-auth-enveloped', 'authEnvelopedData');
    var ci = opened.ci;
    var wrapper = opened.content;
    var ad = wrapper.read_sequence();
    var head = read_head(ad, 'AuthEnvelopedData', options);

    if (head.version !== 0) {
      fail('bad-version', 'AuthEnvelopedData is version 0, RFC 5083 2.1');
    }

    var content = read_encrypted_content(ad);

    if (content.mode !== 'gcm') {
      fail('not-aead',
        content.cipher + ' is not an authenticated cipher. ' +
        'AuthEnvelopedData exists for AEAD - with CBC its `mac` would ' +
        'authenticate nothing; that message is an EnvelopedData');
    }

    var auth_attrs = null;
    var aad = new Uint8Array(0);

    if (ad.peek_tag() === 0xA1) {
      var a = ad.read_implicit(1, 0x31);
      var body = a.buf.subarray(a.pos, a.end);
      aad = der_wrap(0x31, body);
      auth_attrs = read_attribute_types(aad);
    }

    // RFC 5083 2.1: authAttrs MUST be present when the content is not
    // id-data - the content type is otherwise unauthenticated, and a
    // message could be re-labelled.
    if (content.content_type !== '1.2.840.113549.1.7.1' && auth_attrs === null) {
      fail('missing-auth-attrs',
        'content of type ' + content.content_type + ' needs authAttrs, ' +
        'RFC 5083 2.1');
    }

    var mac = ad.read_octet_string();

    if (mac.length !== content.tag_length) {
      fail('bad-tag-length',
        'GCMParameters says a ' + content.tag_length + '-byte tag and the ' +
        'mac is ' + mac.length);
    }

    var unauth = null;

    if (ad.peek_tag() === 0xA2) {
      unauth = ad.read_implicit(2, 0x31).capture();
    }

    ad.expect_end();
    wrapper.expect_end();
    ci.expect_end();

    return {
      version:     head.version,
      recipients:  head.recipients,
      originator:  head.originator,
      content:     content,
      auth_attrs:  auth_attrs,
      aad:         aad,
      mac:         mac,
      unauth_attrs_unauthenticated: unauth,
      authenticated: true,
      der:         bytes,
      note: 'decrypt with ' + content.cipher + ' using content.nonce, aad ' +
            'and mac as the tag. Nothing here is authentic until that ' +
            'check passes.'
    };
  });
}

// ---------------------------------------------------------------------------
// AuthenticatedData - RFC 5652 section 9
// ---------------------------------------------------------------------------

//   AuthenticatedData ::= SEQUENCE {
//        version                CMSVersion,
//        originatorInfo     [0] IMPLICIT OriginatorInfo OPTIONAL,
//        recipientInfos         RecipientInfos,
//        macAlgorithm           MessageAuthenticationCodeAlgorithm,
//        digestAlgorithm    [1] DigestAlgorithmIdentifier OPTIONAL,
//        encapContentInfo       EncapsulatedContentInfo,
//        authAttrs          [2] IMPLICIT AuthAttributes OPTIONAL,
//        mac                    MessageAuthenticationCode,
//        unauthAttrs        [3] IMPLICIT UnauthAttributes OPTIONAL }
//
// ⚠ THE OTHER HALF OF SignedData's TWO-STEP CHECK, WITH A MAC FOR THE
// SIGNATURE. The recipients carry a MAC key, as EnvelopedData's carry a
// content key; the content travels IN THE CLEAR. With authAttrs - the usual
// case - the MAC is over the attributes, SET-tagged exactly as signedAttrs
// are (RFC 5652 9.2), and the content enters through message-digest. So the
// same mistakes are available, and mac_plan() returns the bytes for both
// steps, as cms.verification_plan does for a signer.
function authenticated_from_der(input, options) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var opened = open_content_info(r, CONTENT.authenticatedData,
      'not-authenticated', 'authenticatedData');
    var ci = opened.ci;
    var wrapper = opened.content;
    var ad = wrapper.read_sequence();
    var head = read_head(ad, 'AuthenticatedData', options);

    var mac_alg = F.read_type(ad, 'AlgorithmIdentifier');
    var digest = null;

    if (ad.peek_tag() === 0xA1) {
      var d = ad.read_implicit(1, 0x30);
      digest = OID.name_of(d.read_oid()) || null;
      d.pos = d.end;          // parameters: NULL or absent, either is read
    }

    var encap = read_encapsulated(ad);
    var auth_attrs_raw = null;
    var auth_attrs = null;
    var required = null;

    if (ad.peek_tag() === 0xA2) {
      auth_attrs_raw = ad.capture();
      auth_attrs = read_attributes(auth_attrs_raw);
      required = required_attributes(auth_attrs, 'authAttrs');
    }

    var mac = ad.read_octet_string();
    var unauth = null;

    if (ad.peek_tag() === 0xA3) {
      unauth = read_attributes(ad.capture());
    }

    ad.expect_end();
    wrapper.expect_end();
    ci.expect_end();

    // RFC 5652 9.1: digestAlgorithm MUST be present with authAttrs - the
    // message-digest attribute is a digest OF something - and authAttrs
    // MUST be present when the content is not id-data.
    if (auth_attrs !== null && digest === null) {
      fail('missing-digest-algorithm',
        'authAttrs are present and digestAlgorithm is not, RFC 5652 9.1: ' +
        'the message-digest attribute is a digest with no hash named');
    }
    if (auth_attrs === null && encap.type !== 'data') {
      fail('missing-auth-attrs', 'content of type ' + encap.type +
        ' needs authAttrs, RFC 5652 9.1');
    }
    if (required !== null && required.content_type !== encap.type) {
      fail('content-type-mismatch', 'the content-type attribute says ' +
        required.content_type + ' and the content is ' + encap.type);
    }
    if (required !== null) {
      var size = OID.digest_size(digest);
      if (size !== null && required.message_digest.length !== size) {
        fail('bad-digest-length', digest + ' produces ' + size +
          ' bytes and message-digest holds ' + required.message_digest.length);
      }
    }

    return {
      version:       head.version,
      recipients:    head.recipients,
      originator:    head.originator,
      mac_algorithm: OID.name_of(mac_alg.algorithm) || OID.to_string(mac_alg.algorithm),
      mac_parameters: mac_alg.parameters === undefined ? null : mac_alg.parameters,
      digest:        digest,
      content_type:  encap.type,
      content:       encap.content,
      detached:      encap.content === null,
      auth_attrs:    auth_attrs,
      auth_attrs_raw: auth_attrs_raw,
      message_digest: required === null ? null : required.message_digest,
      mac:           mac,
      unauth_attrs_unauthenticated: unauth,
      der:           bytes,
      note: 'nothing here is authentic until the MAC is checked - see mac_plan'
    };
  });
}

// ⚠ WHAT THE MAC IS OVER - the same two shapes as a CMS signature.
//
//   kind 'auth-attrs'   MAC over `bytes` - the authAttrs with the SET tag
//                       (RFC 5652 9.2) - AND hash content_bytes with digest
//                       and compare with expected_digest. Both, or the MAC
//                       is unconnected to the content.
//   kind 'direct'       MAC over `bytes`, the content octets.
//
// A detached message takes its content as the second argument.
function mac_plan(ad, detached_content) {
  var content = content_signing_input(ad, detached_content);

  if (ad.auth_attrs_raw === null) {
    return {
      kind:      'direct',
      bytes:     content,
      mac:       ad.mac,
      algorithm: ad.mac_algorithm,
      note:      'no authAttrs: the MAC is over the content itself (bytes)'
    };
  }

  return {
    kind:            'auth-attrs',
    bytes:           set_tagged(ad.auth_attrs_raw),   // RFC 5652 9.2
    mac:             ad.mac,
    algorithm:       ad.mac_algorithm,
    digest:          ad.digest,
    content_bytes:   content,
    expected_digest: ad.message_digest,
    note:            'RFC 5652 9.2: hash content_bytes with digest and ' +
                     'compare it with expected_digest, THEN check the MAC ' +
                     'over bytes (the authAttrs with the SET tag)'
  };
}

// The authAttrs, as [{ type, values }] with values the DER of each - read
// from the SET-tagged form, so this also checks that form is DER (sorted,
// no duplicates), which RFC 5083 2.1 requires of these attributes even in
// an otherwise BER message.
function read_attribute_types(set_der) {
  return DER.read(set_der, function (r) {
    var set = r.read_set_of();
    var out = [];

    while (set.remaining() > 0) {
      var attr = set.read_sequence();
      var type = attr.read_oid();
      var values = attr.read_set_of();
      var list = [];
      while (values.remaining() > 0) {
        list.push(values.capture());
      }
      attr.expect_end();
      if (list.length === 0) {
        fail('empty-attribute', 'an attribute has at least one value');
      }
      out.push({ type: OID.name_of(type) || OID.to_string(type),
                 oid: OID.to_string(type), values: list });
    }

    return out;
  });
}

function read_enveloped(r, options) {
  var ed = r.read_sequence();
  var head = read_head(ed, 'EnvelopedData', options);
  var content = read_encrypted_content(ed);

  refuse_aead(content, 'an EnvelopedData');

  var unprotected = null;

  if (ed.peek_tag() === 0xA1) {
    // ⚠ NOT covered by anything. An enveloped message has no integrity
    // protection, and these attributes are outside even the encryption -
    // named so nobody trusts them.
    unprotected = ed.read_implicit(1, 0x31).capture();
  }

  ed.expect_end();

  return {
    version:     head.version,
    recipients:  head.recipients,
    content:     content,
    originator:  head.originator,
    unprotected_attrs_unauthenticated: unprotected,
    warnings:    content.warnings,
    // ⚠ THE WARNING THAT BELONGS ON EVERY ENVELOPED MESSAGE.
    //
    // CBC content encryption gives NO integrity: a recipient who decrypts
    // gets plaintext whether or not somebody altered the ciphertext, and
    // padding-oracle attacks on exactly this shape are decades old. The
    // authenticated form is AuthEnvelopedData - auth_from_der.
    authenticated: false,
    note: 'this message uses ' + content.cipher + ', which is NOT ' +
          'authenticated. Decrypting it yields plaintext whether or not the ' +
          'ciphertext was altered, and this structure carries nothing that ' +
          'would say.'
  };
}

// version, originatorInfo and recipientInfos - the same three fields at the
// head of EnvelopedData and AuthEnvelopedData.
function read_head(ed, what, options) {
  var version = int_value(ed.read_unsigned(), what + ' version');

  var originator = null;

  if (ed.peek_tag() === 0xA0) {
    // OriginatorInfo carries certificates and CRLs for the SENDER, which a
    // recipient may need to build a path to the ephemeral key. Kept whole:
    // interpreting it is the same work certificate_for does in cms.js.
    //
    // ⚠ READ ONCE. This called read_implicit twice - once to test for a
    // method, once to keep - and the first call had already consumed the
    // field, so the second read the NEXT one (the recipientInfos SET, which
    // then failed on its tag) and any EnvelopedData carrying originatorInfo
    // was refused.
    var oi = ed.read_implicit(0, 0x30);
    originator = oi.buf.subarray(oi.pos, oi.end);
  }

  var set = ed.read_set_of();
  var recipients = [];

  while (set.remaining() > 0) {
    recipients.push(read_recipient(set, options));
  }

  if (recipients.length === 0) {
    fail('no-recipients',
      'an enveloped message with no recipients cannot be decrypted by ' +
      'anybody, which is not a state a message should be in');
  }

  return { version: version, originator: originator, recipients: recipients };
}

// ⚠ AN AEAD CIPHER IN A STRUCTURE WITH NOWHERE TO PUT THE TAG.
//
// EnvelopedData and EncryptedData have no field for GCM's authentication
// tag, so a GCM message in either is one whose tag was either dropped -
// and then nothing was authenticated - or appended to the ciphertext by a
// convention no standard names. This reader reported such a message as
// `authenticated: true`, which was the one answer it could not support.
// RFC 5084 puts GCM in AuthEnvelopedData; that is where it is read.
function refuse_aead(content, what) {
  if (content.mode === 'gcm') {
    fail('aead-without-tag',
      what + ' with ' + content.cipher + ' has no field for the ' +
      'authentication tag. AES-GCM in CMS is AuthEnvelopedData (RFC 5083, ' +
      '5084) - read it with auth_from_der');
  }
}

// ---------------------------------------------------------------------------
// Recipients
// ---------------------------------------------------------------------------

function read_recipient(r, options) {
  var tag = r.peek_tag();

  // ⚠ ktri IS THE ONLY ONE WITHOUT A CONTEXT TAG. RFC 5652 6.2 makes it the
  // default arm of the CHOICE, so it arrives as a plain SEQUENCE and every
  // other form arrives tagged - which is why a reader written for ktri alone
  // finds nothing in an EC message rather than failing loudly.
  if (tag === 0x30) {
    return read_ktri(r);
  }
  if (tag === 0xA1) {
    return read_kari(r);
  }
  if (tag === 0xA2) {
    return read_kekri(r);
  }
  if (tag === 0xA3) {
    return read_pwri(r, options);
  }
  if (tag === 0xA4) {
    return read_ori(r);
  }

  fail('bad-recipient',
    'unrecognised RecipientInfo tag 0x' +
    (tag === null ? '(end)' : tag.toString(16)));
}

//   OtherRecipientInfo ::= SEQUENCE {
//        oriType    OBJECT IDENTIFIER,
//        oriValue   ANY DEFINED BY oriType }
function read_ori(r) {
  var ori = r.read_implicit(4, 0x30);
  var type = ori.read_oid();

  if (OID.name_of(type) === 'ori_kem') {
    var out = read_kemri(ori);
    ori.expect_end();
    return out;
  }

  var value = ori.capture();
  ori.expect_end();
  return { kind: 'other', ori_type: OID.to_string(type), value: value,
           note: 'an OtherRecipientInfo, identified by an OID this ' +
                 'module does not interpret' };
}

//   KEMRecipientInfo ::= SEQUENCE {
//        version     CMSVersion,  -- always set to 0
//        rid         RecipientIdentifier,
//        kem         KEMAlgorithmIdentifier,
//        kemct       OCTET STRING,
//        kdf         KeyDerivationAlgorithmIdentifier,
//        kekLength   INTEGER (1..65535),
//        ukm     [0] EXPLICIT UserKeyingMaterial OPTIONAL,
//        wrap        KeyEncryptionAlgorithmIdentifier,
//        encryptedKey EncryptedKey }
//
// ⚠ THREE STEPS, AND THE MESSAGE NAMES EACH ALGORITHM SEPARATELY.
//
//   ss  = KEM.Decapsulate(private key, kem_ciphertext)
//   kek = kdf(ss, kdf_info, kek_length)       - HKDF: no salt, RFC 9629 5
//   cek = unwrap(wrap, kek, encrypted_key)
//
// The KDF's info is a DER structure - CMSORIforKEMOtherInfo, made of the
// wrap, kekLength and ukm - not the ukm alone, exactly as kari's SharedInfo
// is. It is built here from the message's own bytes as kdf_info.
//
// ⚠ VERSION 0 WITH EITHER RecipientIdentifier. Not ktri's rule, where the
// subjectKeyIdentifier form is version 2: RFC 9629 3 says always 0.
function read_kemri(r) {
  var seq = r.read_sequence();
  var version = int_value(seq.read_unsigned(), 'KEMRecipientInfo version');

  if (version !== 0) {
    fail('bad-version', 'RFC 9629 3: KEMRecipientInfo version MUST be 0, ' +
      'this says ' + version);
  }

  var rid = seq.peek_tag() === 0x80
    ? read_recipient_id(seq, 2) : read_recipient_id(seq, 0);
  var kem = F.read_type(seq, 'AlgorithmIdentifier');
  var kem_name = OID.name_of(kem.algorithm) || OID.to_string(kem.algorithm);
  var kemct = seq.read_octet_string();

  var kdf = F.read_type(seq, 'AlgorithmIdentifier');
  var kdf_name = OID.name_of(kdf.algorithm) || OID.to_string(kdf.algorithm);
  var kek_length = int_value(seq.read_unsigned(), 'kekLength');
  var ukm = null;

  if (seq.peek_tag() === 0xA0) {
    var u = seq.read_explicit(0);
    ukm = u.read_octet_string();
    u.expect_end();
  }

  var wrap_start = seq.pos;
  var wrap = F.read_type(seq, 'AlgorithmIdentifier');
  var wrap_der = seq.buf.subarray(wrap_start, seq.pos);
  var wrap_name = OID.name_of(wrap.algorithm) || OID.to_string(wrap.algorithm);
  var encrypted = seq.read_octet_string();
  seq.expect_end();

  // RFC 9935 / FIPS 203: the ciphertext length is fixed by the parameter
  // set, and the identifier's parameters MUST be absent.
  var pq = PQ_KEYS[kem_name];
  if (pq !== undefined && pq.family === 'ml-kem') {
    if (kem.parameters !== undefined) {
      fail('unexpected-parameters', kem_name + ' takes no parameters ' +
        '(RFC 9936 3)');
    }
    if (kemct.length !== pq.ciphertext) {
      fail('bad-ciphertext-length', kem_name + ' ciphertexts are ' +
        pq.ciphertext + ' bytes; this one is ' + kemct.length);
    }
  }

  // RFC 8619 2: the HKDF identifiers carry no parameters.
  if (HKDF_HASH[kdf_name] !== undefined && kdf.parameters !== undefined) {
    fail('unexpected-parameters', kdf_name + ' takes no parameters (RFC 8619)');
  }

  if (kek_length < 1 || kek_length > 65535) {
    fail('bad-kek-length', 'kekLength is 1..65535, RFC 9629 3');
  }

  // "Implementations MUST confirm that the value provided is consistent
  // with the key-encryption algorithm" - RFC 9629 3.
  if (WRAP_BITS[wrap_name] !== undefined &&
      WRAP_BITS[wrap_name] !== kek_length * 8) {
    fail('inconsistent-kek-length', wrap_name + ' takes a ' +
      WRAP_BITS[wrap_name] / 8 + '-byte key and kekLength says ' + kek_length);
  }

  return {
    kind:           'kem',
    version:        version,
    recipient:      rid,
    kem:            kem_name,
    kem_parameters: kem.parameters === undefined ? null : kem.parameters,
    kem_ciphertext: kemct,
    kdf:            kdf_name,
    kdf_parameters: kdf.parameters === undefined ? null : kdf.parameters,
    kdf_hash:       HKDF_HASH[kdf_name] || null,
    kek_length:     kek_length,
    ukm:            ukm,
    // The KDF's info - CMSORIforKEMOtherInfo, from the bytes received.
    kdf_info:       kem_kdf_info(wrap_der, kek_length, ukm),
    wrap:           wrap_name,
    encrypted_key:  encrypted,
    note: 'decapsulate kem_ciphertext with the ' + kem_name + ' private key; ' +
          'derive kek_length bytes from the shared secret with ' + kdf_name +
          ' and kdf_info as the info' +
          (HKDF_HASH[kdf_name] ? ' (no salt, RFC 9629 5)' : '') +
          '; unwrap encrypted_key with ' + wrap_name
  };
}

var HKDF_HASH = { hkdfWithSha256: 'sha256', hkdfWithSha384: 'sha384',
                  hkdfWithSha512: 'sha512' };

//   CMSORIforKEMOtherInfo ::= SEQUENCE {
//        wrap       KeyEncryptionAlgorithmIdentifier,
//        kekLength  INTEGER (1..65535),
//        ukm    [0] EXPLICIT UserKeyingMaterial OPTIONAL }
//
// The wrap AlgorithmIdentifier goes in as the message carries it.
function kem_kdf_info(wrap_der, kek_length, ukm) {
  var len = kek_length > 0xFF
    ? (kek_length >= 0x8000 ? [0, kek_length >> 8, kek_length & 0xFF]
                            : [kek_length >> 8, kek_length & 0xFF])
    : (kek_length >= 0x80 ? [0, kek_length] : [kek_length]);
  var parts = [wrap_der, der_wrap(0x02, new Uint8Array(len))];

  if (ukm !== null) {
    parts.push(der_wrap(0xA0, der_wrap(0x04, ukm)));
  }
  return der_wrap(0x30, concat_bytes(parts));
}

//   KeyTransRecipientInfo ::= SEQUENCE {
//        version                CMSVersion,
//        rid                    RecipientIdentifier,
//        keyEncryptionAlgorithm AlgorithmIdentifier,
//        encryptedKey           OCTET STRING }
function read_ktri(r) {
  var seq = r.read_sequence();
  var version = int_value(seq.read_unsigned(), 'ktri version');
  var rid = read_recipient_id(seq, version);
  var alg = F.read_type(seq, 'AlgorithmIdentifier');
  var key = seq.read_octet_string();
  seq.expect_end();

  return {
    kind:      'key-transport',
    version:   version,
    recipient: rid,
    algorithm: OID.name_of(alg.algorithm) || OID.to_string(alg.algorithm),
    parameters: alg.parameters === undefined ? null : alg.parameters,
    // For RSA-OAEP the hashes and label decide what decrypts - read, not
    // left as bytes. See algorithm.js.
    key_params: ALG.describe(alg),
    encrypted_key: key,
    note: 'unwrap encrypted_key with the recipient private key to get the ' +
          'content key'
  };
}

//   KeyAgreeRecipientInfo ::= SEQUENCE {
//        version                 CMSVersion,
//        originator          [0] EXPLICIT OriginatorIdentifierOrKey,
//        ukm                 [1] EXPLICIT UserKeyingMaterial OPTIONAL,
//        keyEncryptionAlgorithm  AlgorithmIdentifier,
//        recipientEncryptedKeys  SEQUENCE OF RecipientEncryptedKey }
//
// ⚠ THIS IS WHAT OPENSSL PRODUCES FOR AN EC RECIPIENT, and it has the most
// moving parts: an ephemeral public key, a key derivation, and then a key
// wrap - three steps where key transport has one.
function read_kari(r) {
  var seq = r.read_implicit(1, 0x30);
  var version = int_value(seq.read_unsigned(), 'kari version');

  if (version !== 3) {
    fail('bad-version',
      'a KeyAgreeRecipientInfo is version 3, got ' + version);
  }

  var originator = read_originator(seq);

  var ukm = null;

  if (seq.peek_tag() === 0xA1) {
    // User keying material: extra input to the key derivation, which both
    // sides must use identically. Omitting it silently would derive a
    // different key and the unwrap would fail with nothing to say why.
    var u = seq.read_explicit(1);
    ukm = u.read_octet_string();
    u.expect_end();
  }

  var alg = F.read_type(seq, 'AlgorithmIdentifier');
  var kdf_name = OID.name_of(alg.algorithm) || OID.to_string(alg.algorithm);

  // The key-encryption algorithm's own parameters name the KEY WRAP that
  // follows the derivation - a second algorithm inside the first.
  var wrap = null;

  if (alg.parameters !== undefined) {
    wrap = DER.read(alg.parameters, function (p) {
      var w = F.read_type(p, 'AlgorithmIdentifier');
      return OID.name_of(w.algorithm) || OID.to_string(w.algorithm);
    });
  }

  var list = seq.read_sequence();
  var keys = [];

  while (list.remaining() > 0) {
    var rek = list.read_sequence();
    var rid = read_kari_recipient_id(rek);
    var encrypted = rek.read_octet_string();
    rek.expect_end();

    keys.push({ recipient: rid, encrypted_key: encrypted });
  }

  seq.expect_end();

  return {
    kind:       'key-agreement',
    // ⚠ THE KDF'S SharedInfo, AS BYTES. RFC 5753 7.2: the X9.63 KDF is
    // run over Z || counter || ECC-CMS-SharedInfo, a DER structure built
    // from the wrap algorithm, the ukm and the key length in bits. This
    // module used to say "run it through the kdf with the ukm" and leave
    // the caller to discover that the third input is DER - and to build it
    // byte-exact. It is built here, from the message's own bytes.
    shared_info: alg.parameters === undefined ? null
      : kari_shared_info(alg.parameters, ukm, wrap),
    kdf_hash:   KDF_HASH[kdf_name] || null,
    version:    version,
    originator: originator,
    ukm:        ukm,
    kdf:        kdf_name,
    // ⚠ TWO ALGORITHMS, NOT ONE. The kdf derives a key-encryption key and
    // the wrap uses it - a caller that treated `kdf` as the whole operation
    // would stop one step short.
    wrap:       wrap,
    keys:       keys,
    note: 'derive a shared secret from the originator key and the recipient ' +
          'private key, run it through ' + kdf_name +
          (ukm === null ? '' : ' with the ukm') +
          ', then unwrap encrypted_key with ' + (wrap || 'the named wrap')
  };
}

// The hash inside each X9.63 KDF scheme name. Cofactor variants differ only
// for curves with a cofactor above one, which no NIST prime curve has.
var KDF_HASH = {
  dhSinglePass_stdDH_sha1kdf:      'sha1',
  dhSinglePass_cofactorDH_sha1kdf: 'sha1',
  ecdhX963KDF_SHA224: 'sha224', ecdhX963KDF_SHA256: 'sha256',
  ecdhX963KDF_SHA384: 'sha384', ecdhX963KDF_SHA512: 'sha512',
  eccofactordhX963KDF_SHA224: 'sha224', eccofactordhX963KDF_SHA256: 'sha256',
  eccofactordhX963KDF_SHA384: 'sha384', eccofactordhX963KDF_SHA512: 'sha512'
};

var WRAP_BITS = { aes128Wrap: 128, aes192Wrap: 192, aes256Wrap: 256 };

//   ECC-CMS-SharedInfo ::= SEQUENCE {
//      keyInfo         AlgorithmIdentifier,
//      entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
//      suppPubInfo [2] EXPLICIT OCTET STRING }
//
// keyInfo is the wrap AlgorithmIdentifier exactly as the message carries it
// - which is `wrap_alg_der`, the key-encryption algorithm's parameters - and
// suppPubInfo is the wrap key's length in BITS, as four big-endian bytes.
function kari_shared_info(wrap_alg_der, ukm, wrap_name) {
  var bits = WRAP_BITS[wrap_name];

  if (bits === undefined) {
    return null;
  }

  var parts = [wrap_alg_der];

  if (ukm !== null) {
    parts.push(der_wrap(0xA0, der_wrap(0x04, ukm)));
  }

  parts.push(der_wrap(0xA2, der_wrap(0x04, new Uint8Array([
    (bits >>> 24) & 0xFF, (bits >>> 16) & 0xFF, (bits >>> 8) & 0xFF,
    bits & 0xFF]))));

  return der_wrap(0x30, concat_bytes(parts));
}

//   OriginatorIdentifierOrKey ::= CHOICE {
//        issuerAndSerialNumber  IssuerAndSerialNumber,
//        subjectKeyIdentifier   [0] SubjectKeyIdentifier,
//        originatorKey          [1] OriginatorPublicKey }
function read_originator(r) {
  var wrapper = r.read_explicit(0);
  var tag = wrapper.peek_tag();
  var out;

  if (tag === 0xA1) {
    // An ephemeral public key, sent inline. This is the ECDH case, and the
    // key is the sender's half of the agreement.
    var ok = wrapper.read_implicit(1, 0x30);
    var alg = F.read_type(ok, 'AlgorithmIdentifier');
    var point = ok.read_bit_string();
    ok.expect_end();

    out = {
      by:        'ephemeral-key',
      algorithm: OID.name_of(alg.algorithm) || OID.to_string(alg.algorithm),
      point:     point.bytes
    };
  } else if (tag === 0x80) {
    out = { by: 'key-id', key_id: wrapper.read_implicit(0, 0x04).bytes };
  } else {
    var ias = F.read_type(wrapper, 'IssuerAndSerialNumber');
    out = { by: 'issuer-and-serial', issuer: ias.issuer,
            serial: ias.serial, serial_hex: hex(ias.serial) };
  }

  wrapper.expect_end();
  return out;
}

//   KeyAgreeRecipientIdentifier ::= CHOICE {
//        issuerAndSerialNumber  IssuerAndSerialNumber,
//        rKeyId             [0] IMPLICIT RecipientKeyIdentifier }
function read_kari_recipient_id(r) {
  if (r.peek_tag() === 0xA0) {
    var rk = r.read_implicit(0, 0x30);
    var key_id = rk.read_octet_string();
    rk.pos = rk.end;             // date and other attributes, not needed
    return { by: 'key-id', key_id: key_id };
  }

  var ias = F.read_type(r, 'IssuerAndSerialNumber');
  return { by: 'issuer-and-serial', issuer: ias.issuer,
           serial: ias.serial, serial_hex: hex(ias.serial) };
}

//   RecipientIdentifier ::= CHOICE {
//        issuerAndSerialNumber  IssuerAndSerialNumber,
//        subjectKeyIdentifier   [0] SubjectKeyIdentifier }
//
// RFC 5652 6.2.1 ties the version: 0 with issuerAndSerialNumber, 2 with
// subjectKeyIdentifier. A message where they disagree names its recipient
// two ways.
function read_recipient_id(r, version) {
  if (r.peek_tag() === 0x80) {
    if (version !== 2) {
      fail('version-rid-mismatch',
        'subjectKeyIdentifier requires ktri version 2, this says ' + version);
    }
    return { by: 'key-id', key_id: r.read_implicit(0, 0x04).bytes };
  }

  if (version !== 0) {
    fail('version-rid-mismatch',
      'issuerAndSerialNumber requires ktri version 0, this says ' + version);
  }

  var ias = F.read_type(r, 'IssuerAndSerialNumber');
  return { by: 'issuer-and-serial', issuer: ias.issuer,
           serial: ias.serial, serial_hex: hex(ias.serial) };
}

// KEKRecipientInfo and PasswordRecipientInfo: kept shallow, because both
// depend on a key or a password the caller supplies out of band and neither
// carries anything to interpret beyond the algorithm.
function read_kekri(r) {
  var seq = r.read_implicit(2, 0x30);
  int_value(seq.read_unsigned(), 'kekri version');

  var kid = seq.read_sequence();
  var identifier = kid.read_octet_string();
  kid.pos = kid.end;

  var alg = F.read_type(seq, 'AlgorithmIdentifier');
  var key = seq.read_octet_string();
  seq.expect_end();

  return {
    kind:       'kek',
    identifier: identifier,
    algorithm:  OID.name_of(alg.algorithm) || OID.to_string(alg.algorithm),
    encrypted_key: key,
    note: 'unwrap encrypted_key with the previously distributed key this ' +
          'identifier names'
  };
}

//   PasswordRecipientInfo ::= SEQUENCE {
//        version                 CMSVersion,   -- always 0
//        keyDerivationAlgorithm  [0] KeyDerivationAlgorithmIdentifier OPTIONAL,
//        keyEncryptionAlgorithm  KeyEncryptionAlgorithmIdentifier,
//        encryptedKey            EncryptedKey }
//
// ⚠ [0] IS IMPLICIT. The CMS module is written with IMPLICIT TAGS, so the
// tag REPLACES the AlgorithmIdentifier's SEQUENCE: an OID follows it
// directly. This reader expected a SEQUENCE inside and refused every
// message `openssl cms -pwri_password` writes - the first one it was ever
// shown.
//
// What comes back is everything the caller needs, parsed:
//
//   kdf   { algorithm: 'pbkdf2', prf, salt, iterations, key_length, weak }
//         - or null, when the KEK was agreed out of band
//   kek   { cipher, key_length, iv } - the CBC cipher RFC 3211 applies
//         twice. Its key is the PBKDF2 output, and key_length is how much
//         of it to derive.
//
// and the order is: kek_key = pbkdf2(prf, password, salt, iterations,
// kek.key_length); block = rfc3211_unwrap(kek.cipher, kek_key, kek.iv,
// encrypted_key); cek = pwri_key_from_block(block).
function read_pwri(r, options) {
  var seq = r.read_implicit(3, 0x30);
  var version = int_value(seq.read_unsigned(), 'pwri version');

  if (version !== 0) {
    fail('bad-version', 'a PasswordRecipientInfo is version 0, RFC 3211');
  }

  var kdf = null;

  if (seq.peek_tag() === 0xA0) {
    var k = seq.read_implicit(0, 0x30);
    var kdf_alg = DER.read(der_wrap(0x30, k.buf.subarray(k.pos, k.end)),
      function (a) {
        return F.read_type(a, 'AlgorithmIdentifier');
      });
    var kdf_name = OID.name_of(kdf_alg.algorithm);

    if (kdf_name === 'pbkdf2') {
      var p = PBES2.read_pbkdf2(kdf_alg, options);
      kdf = {
        algorithm:  'pbkdf2',
        prf:        p.prf,
        salt:       p.salt,
        iterations: p.iterations,
        key_length: p.key_length,
        weak:       p.weak
      };
    } else {
      // RFC 3211 names PBKDF2 and allows others. Reported, not refused:
      // the caller may hold a KDF this library has no table for.
      kdf = {
        algorithm:  kdf_name || OID.to_string(kdf_alg.algorithm),
        parameters: kdf_alg.parameters === undefined
          ? null : kdf_alg.parameters
      };
    }
  }

  var alg = F.read_type(seq, 'AlgorithmIdentifier');
  var key = seq.read_octet_string();
  seq.expect_end();

  var name = OID.name_of(alg.algorithm) || OID.to_string(alg.algorithm);
  var kek = null;

  if (name === 'pwri_kek') {
    if (alg.parameters === undefined) {
      fail('missing-parameters',
        'id-alg-PWRI-KEK names its inner cipher in its parameters');
    }
    var inner = DER.read(alg.parameters, function (a) {
      return F.read_type(a, 'AlgorithmIdentifier');
    });
    var c = PBES2.read_cipher(inner);
    kek = { cipher: c.cipher, key_length: c.key_length, iv: c.iv };

    if (kdf !== null && kdf.key_length !== undefined &&
        kdf.key_length !== null && kdf.key_length !== c.key_length) {
      fail('key-length-mismatch',
        'the KDF derives ' + kdf.key_length + ' bytes and ' + c.cipher +
        ' takes ' + c.key_length);
    }

    var block = c.iv.length;
    if (key.length < 2 * block || key.length % block !== 0) {
      fail('bad-encrypted-key',
        'an RFC 3211 wrapped key is a multiple of the ' + block +
        '-byte block and at least two blocks, got ' + key.length);
    }
  }

  return {
    kind:      'password',
    version:   0,
    kdf:       kdf,
    algorithm: name,
    kek:       kek,
    encrypted_key: key,
    note: kek === null
      ? 'derive a key from the password with the named KDF, then unwrap ' +
        'encrypted_key with ' + name
      : 'derive kek.key_length bytes with the KDF, undo RFC 3211\'s double ' +
        kek.cipher + ' over encrypted_key, then pass the result to ' +
        'pwri_key_from_block'
  };
}

// ⚠ THE CHECK THAT TELLS A WRONG PASSWORD FROM A RIGHT ONE.
//
// RFC 3211 2.3: the decrypted block is
//
//   LEN (1 byte) || ~CEK[0..2] (3 bytes) || CEK (LEN bytes) || padding
//
// and the three complemented bytes are the only thing that says the KEK was
// right. Skipping the check yields a key of plausible length from ANY
// password, which then decrypts the content to noise - and with CBC, noise
// with valid padding one time in 256.
//
// `block`: the cleartext after the caller removed both CBC layers.
// `block_size`: the inner cipher's block, 16 for AES (default).
function pwri_key_from_block(block, block_size) {
  var b = to_bytes(block);
  var size = block_size === undefined ? 16 : block_size;

  if (b.length < 2 * size || b.length % size !== 0) {
    fail('bad-key-block', 'the unwrapped block is a multiple of ' + size +
      ' bytes and at least two blocks, got ' + b.length);
  }

  var len = b[0];

  if (len < 3 || len > b.length - 4) {
    fail('pwri-check-failed',
      'the key length byte is ' + len + ' in a ' + b.length + '-byte ' +
      'block - the password is wrong or the message altered');
  }

  if ((b[1] ^ b[4]) !== 0xFF || (b[2] ^ b[5]) !== 0xFF ||
      (b[3] ^ b[6]) !== 0xFF) {
    fail('pwri-check-failed',
      'the check bytes do not match - the password is wrong or the ' +
      'message altered');
  }

  return b.slice(4, 4 + len);
}

// ---------------------------------------------------------------------------
// The content
// ---------------------------------------------------------------------------

//   EncryptedContentInfo ::= SEQUENCE {
//        contentType                 ContentType,
//        contentEncryptionAlgorithm  AlgorithmIdentifier,
//        encryptedContent        [0] IMPLICIT OCTET STRING OPTIONAL }
function read_encrypted_content(r) {
  var eci = r.read_sequence();
  var type = eci.read_oid();
  var alg = F.read_type(eci, 'AlgorithmIdentifier');
  var name = OID.name_of(alg.algorithm) || OID.to_string(alg.algorithm);
  var spec = CONTENT_CIPHERS[name];

  var data = null;
  var segmented = false;

  if (eci.peek_tag() === 0x80) {
    data = eci.read_implicit(0, 0x04).bytes;
  } else if (eci.peek_tag() === 0xA0) {
    // ⚠ THE CONSTRUCTED FORM: [0] holding OCTET STRING segments - BER, which
    // the Go pkcs7 package writes, and with it every micromdm SCEP client
    // and server (and OpenSSL reads). The octets are the concatenation, so
    // the meaning is plain, and nothing here is signed by itself - so it is
    // read, and said (`warnings`). Segments are primitive, with definite
    // lengths: a segment that is itself constructed, or an indefinite
    // length, is still refused.
    var seg = eci.read_explicit(0);
    var parts = [];
    while (seg.remaining() > 0) {
      parts.push(seg.read_octet_string());
    }
    data = concat_bytes(parts);
    segmented = true;
  }

  eci.expect_end();

  var out = {
    content_type: OID.to_string(type),
    cipher:       name,
    known:        spec !== undefined,
    key_length:   spec === undefined ? null : spec.key,
    mode:         spec === undefined ? null : spec.mode,
    // Single DES: readable, and broken.
    weak:         spec !== undefined && spec.weak === true,
    // ⚠ ABSENT encryptedContent is a DETACHED enveloped message: the
    // ciphertext travels separately and the caller supplies it. Legal, and
    // rarer than the detached signed form - so it is reported rather than
    // treated as an empty message.
    detached:     data === null,
    data:         data,
    iv:           null,
    warnings:     segmented ? [{ code: 'constructed-encrypted-content',
      detail: 'the encrypted content is a constructed [0] of OCTET STRING segments - BER, ' +
        'as the Go pkcs7 package writes it; read as their concatenation' }] : []
  };

  if (spec !== undefined && spec.mode === 'gcm') {
    read_gcm_parameters(alg, name, out);
  } else if (alg.parameters !== undefined && spec !== undefined) {
    out.iv = DER.read(alg.parameters, function (p) {
      return p.read_octet_string();
    });

    if (out.iv.length !== spec.iv) {
      fail('bad-iv-length',
        name + ' takes a ' + spec.iv + '-byte IV, got ' + out.iv.length);
    }
  }

  return out;
}

//   GCMParameters ::= SEQUENCE {
//      aes-nonce   OCTET STRING,       -- 12 octets recommended
//      aes-ICVlen  AES-GCM-ICVlen DEFAULT 12 }     -- 12 | 13 | 14 | 15 | 16
//
// RFC 5084 3.2. The parameters are a SEQUENCE, not the bare IV a CBC cipher
// takes - read as an OCTET STRING, every GCM message failed. `iv` is set to
// the nonce, so a caller who reads iv for every cipher still gets the right
// bytes, and `tag_length` says how long the tag is.
function read_gcm_parameters(alg, name, out) {
  if (alg.parameters === undefined) {
    fail('missing-parameters', name + ' requires GCMParameters');
  }

  DER.read(alg.parameters, function (r) {
    var p = r.read_sequence();
    var nonce = p.read_octet_string();
    var icv = 12;

    if (p.peek_tag() === 0x02) {
      icv = int_value(p.read_unsigned(), 'aes-ICVlen');
      if (icv === 12) {
        fail('non-der-default',
          'aes-ICVlen 12 is the DEFAULT and DER omits it');
      }
    }
    p.expect_end();

    if (nonce.length === 0) {
      fail('bad-nonce', 'the GCM nonce is empty');
    }
    if (icv < 12 || icv > 16) {
      fail('bad-tag-length', 'aes-ICVlen is 12 to 16, RFC 5084, got ' + icv);
    }

    out.iv = nonce;
    out.nonce = nonce;
    out.tag_length = icv;
  });
}

// ---------------------------------------------------------------------------
// Selecting
// ---------------------------------------------------------------------------

// Finds the recipient a given certificate can decrypt for.
//
// ⚠ NOT DONE AUTOMATICALLY. A message may name several recipients, and which
// one the caller holds a key for is something only they know - trying each in
// turn would be an oracle.
function recipient_for(enveloped, cert) {
  var i, j;

  for (i = 0; i < enveloped.recipients.length; i++) {
    var rec = enveloped.recipients[i];

    if (rec.kind === 'key-transport' || rec.kind === 'kem') {
      if (matches(rec.recipient, cert)) {
        return rec;
      }
      continue;
    }

    if (rec.kind === 'key-agreement') {
      for (j = 0; j < rec.keys.length; j++) {
        if (matches(rec.keys[j].recipient, cert)) {
          return {
            kind: rec.kind, originator: rec.originator, ukm: rec.ukm,
            kdf: rec.kdf, wrap: rec.wrap, note: rec.note,
            encrypted_key: rec.keys[j].encrypted_key,
            recipient: rec.keys[j].recipient
          };
        }
      }
    }
  }

  return null;
}

function matches(rid, cert) {
  if (rid.by === 'issuer-and-serial') {
    return hex(cert.serial) === rid.serial_hex &&
           X509.name_matches(cert.issuer, rid.issuer);
  }

  if (rid.by === 'key-id') {
    var ski = X509.extension(cert, 'ext_subjectKeyId');
    return ski !== null && ski.parsed !== null &&
           bytes_equal(ski.parsed, rid.key_id);
  }

  return false;
}

// ---------------------------------------------------------------------------
// The content types that are not enveloped
// ---------------------------------------------------------------------------
//
// ⚠ RFC 5652 DEFINES SIX CONTENT TYPES AND THIS LIBRARY READ THREE.
//
// These two are small, and that is precisely why they were missed: nothing
// forced them. `openssl cms -digest_create` and
// `openssl cms -EncryptedData_encrypt` both produce files that reported
// `unrecognised-der`, and both are one-line commands.

//   DigestedData ::= SEQUENCE {
//        version            CMSVersion,
//        digestAlgorithm    DigestAlgorithmIdentifier,
//        encapContentInfo   EncapsulatedContentInfo,
//        digest             Digest }
//
// ⚠ A DIGEST IS NOT A SIGNATURE, AND NOTHING HERE SAYS WHO COMPUTED IT.
//
// Anybody can alter the content and recompute the digest. This structure
// gives integrity against ACCIDENT and none against intent, and a caller who
// treated a matching digest as authentication would be treating a checksum
// as a proof.
function digested_from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var opened = open_content_info(r, '1.2.840.113549.1.7.5', 'not-digested',
      'digestedData');
    var ci = opened.ci;
    var w = opened.content;
    var dd = w.read_sequence();

    var version = int_value(dd.read_unsigned(), 'DigestedData version');
    var alg = F.read_type(dd, 'AlgorithmIdentifier');
    var digest_name = OID.name_of(alg.algorithm) ||
                      OID.to_string(alg.algorithm);

    var encap = read_encapsulated(dd);
    var content = encap.content;

    var digest = dd.read_octet_string();
    dd.expect_end();
    w.expect_end();
    ci.expect_end();

    var expected = OID.digest_size(digest_name);

    if (expected !== null && digest.length !== expected) {
      fail('bad-digest-length',
        digest_name + ' produces ' + expected + ' bytes, and this ' +
        'structure carries ' + digest.length);
    }

    return {
      version:      version,
      digest_algorithm: digest_name,
      content_type: OID.to_string(encap.type_oid),
      content:      content,
      detached:     content === null,
      digest:       digest,
      der:          bytes,
      // ⚠ THE WARNING THAT BELONGS ON EVERY ONE OF THESE.
      note: 'a digest is not a signature: anybody who alters the content ' +
            'can recompute it. This gives integrity against ACCIDENT and ' +
            'none against intent.'
    };
  });
}

//   CompressedData ::= SEQUENCE {
//        version               CMSVersion,       -- always 0
//        compressionAlgorithm  CompressionAlgorithmIdentifier,
//        encapContentInfo      EncapsulatedContentInfo }
//
// RFC 3274. ZLIB is the one algorithm (id-alg-zlibCompress, RFC 1950), with
// no parameters. The content comes back COMPRESSED - inflating it is the
// caller's, as decrypting is: node:zlib's inflateSync, or any zlib.
//
// ⚠ A COMPRESSED MESSAGE IS NOT A PROTECTED ONE, and inflating one is where
// a decompression bomb goes off: limit the output when inflating -
// inflateSync(data, { maxOutputLength }) - since a few kilobytes here can
// be gigabytes there.
function compressed_from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var opened = open_content_info(r, CONTENT.compressedData,
      'not-compressed', 'compressedData');
    var ci = opened.ci;
    var w = opened.content;
    var cd = w.read_sequence();

    var version = int_value(cd.read_unsigned(), 'CompressedData version');

    if (version !== 0) {
      fail('bad-version', 'CompressedData is version 0, RFC 3274 1.1');
    }

    var alg = F.read_type(cd, 'AlgorithmIdentifier');
    var name = OID.name_of(alg.algorithm) || OID.to_string(alg.algorithm);

    if (name === 'zlibCompress' && alg.parameters !== undefined) {
      fail('unexpected-parameters', 'id-alg-zlibCompress takes no ' +
        'parameters, RFC 3274 2');
    }

    var encap = read_encapsulated(cd);
    cd.expect_end();
    w.expect_end();
    ci.expect_end();

    return {
      version:      version,
      algorithm:    name,
      content_type: encap.type,
      compressed:   encap.content,
      detached:     encap.content === null,
      der:          bytes,
      note: name === 'zlibCompress'
        ? 'inflate `compressed` with zlib (RFC 1950) - and limit the output ' +
          'size, since a small input can inflate to gigabytes'
        : 'compressed with ' + name + ', which RFC 3274 does not define'
    };
  });
}

//   EncryptedData ::= SEQUENCE {
//        version               CMSVersion,
//        encryptedContentInfo  EncryptedContentInfo,
//        unprotectedAttrs  [1] IMPLICIT UnprotectedAttributes OPTIONAL }
//
// ⚠ AN EnvelopedData WITH THE RECIPIENTS TAKEN OUT.
//
// The key is distributed by some means outside the message entirely, so
// there is nothing here that says who can decrypt it or how they got the
// key - and, like EnvelopedData with a CBC cipher, nothing that says whether
// the ciphertext was altered.
function encrypted_from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var opened = open_content_info(r, '1.2.840.113549.1.7.6',
      'not-encrypted-data', 'encryptedData');
    var ci = opened.ci;
    var w = opened.content;
    var ed = w.read_sequence();

    var version = int_value(ed.read_unsigned(), 'EncryptedData version');
    var content = read_encrypted_content(ed);

    refuse_aead(content, 'an EncryptedData');

    var unprotected = null;

    if (ed.peek_tag() === 0xA1) {
      unprotected = ed.read_implicit(1, 0x31).capture();
    }

    ed.expect_end();
    w.expect_end();
    ci.expect_end();

    return {
      version:       version,
      content:       content,
      unprotected_attrs_unauthenticated: unprotected,
      authenticated: false,
      der:           bytes,
      note: 'the key for this message travels outside it entirely - nothing ' +
            'here says who holds it, and ' + content.cipher + ' does not ' +
            'authenticate, so decrypting yields plaintext whether or not ' +
            'the ciphertext was altered.'
    };
  });
}

export {
  from_der,
  auth_from_der,
  authenticated_from_der,
  mac_plan,
  pwri_key_from_block,
  digested_from_der,
  compressed_from_der,
  encrypted_from_der,
  recipient_for,
  CONTENT_CIPHERS
};
