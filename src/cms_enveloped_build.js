// Building CMS EnvelopedData - RFC 5652 section 6. Encrypting to recipients.
//
// cms_enveloped.js reads every recipient kind; this writes the three a
// sender uses:
//
//   ktri    key transport: the content key encrypted to an RSA certificate,
//           with PKCS#1 v1.5 or OAEP
//   kari    key agreement: an ephemeral EC key, ECDH with the recipient's
//           certificate, an X9.63 KDF and an AES key wrap
//   kekri   a previously shared key-encryption key, AES-wrapped
//   pwri    a password: PBKDF2, then RFC 3211's double-CBC key wrap
//   kemri   a KEM - ML-KEM (RFC 9936) - in RFC 9629's KEMRecipientInfo:
//           encapsulate to the certificate, HKDF, an AES key wrap
//
// and it writes AuthEnvelopedData (RFC 5083) - the same message for AES-GCM,
// which auth_enveloped_data() writes and the same recipients serve.
//
// ⚠ THIS LIBRARY ENCRYPTS NOTHING, SO EVERY STEP IS THE CALLER'S - and each
//   recipient kind has one input that is easy to get wrong, which is what
//   this module computes or checks:
//
//   ktri    which algorithm identifier goes with the padding the caller
//           used. OAEP with SHA-256 written as plain rsaEncryption decrypts
//           nowhere. Pass { name: 'rsaOAEP', hash: 'sha256' }.
//   kari    the KDF's SharedInfo - a DER structure, not the ukm alone.
//           kari_shared_info() returns it byte-exact, and the reader returns
//           the same bytes from a received message.
//   kemri   the KDF's info: CMSORIforKEMOtherInfo, DER again - from
//           kem_kdf_info(), and the reader returns it as kdf_info.
//   all     the IV in the content algorithm's parameters, and its length.
//
// For a kemri recipient (RFC 9629 2, RFC 9936):
//
//   cek = random(16)
//   [ss, kemct] = mlkem512.encapsulate(recipient_cert.public)
//   kek = hkdf(sha256, salt: none, ss, kem_kdf_info({ wrap: 'aes128Wrap' }), 16)
//   wrapped = aes_key_wrap(kek, cek)
//   recipient = { type: 'kemri', key_id: ski, kem: 'mlKem512',
//                 kem_ciphertext: kemct, wrap: 'aes128Wrap',
//                 encrypted_key: wrapped }
//
// The order, for a kari recipient:
//
//   cek = random(32); iv = random(16)
//   ct  = aes256cbc(cek, iv, content)
//   eph = ecdh.generate(curve)
//   z   = ecdh(eph.private, recipient_cert.public)
//   kek = x963kdf(sha256, z, kari_shared_info({ wrap: 'aes256Wrap' }), 32)
//   wrapped = aes_key_wrap(kek, cek)
//   der = enveloped_data({ cipher: 'aes256CBC', iv, encrypted_content: ct,
//                 recipients: [{ type: 'kari', certificate, kdf: 'sha256',
//                   wrap: 'aes256Wrap', ephemeral_point: eph.public,
//                   encrypted_key: wrapped }] })

import * as W from './der_writer.js';
import * as OID from './oid.js';
import * as ALG from './algorithm.js';
import * as PBES2 from './pbes2.js';
import { PQ_KEYS } from './ec_domain.js';
import { CONTENT } from './cms.js';
import { extra_attribute, content_attributes } from './cms_build.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, int_bytes } from './commons/bytes.js';

import './pkix.js';
import { issuer_and_serial_to_der, encapsulated_to_der,
  digest_algorithm_to_der } from './pkix.js';

var fail = make_fail_here('cms');

// ⚠ 3DES ONLY ON REQUEST. A SCEP client older than AES (RFC 8894 3.5.2
// still lists DES3) cannot open anything else; anyone else should not be
// sent it. `allow_weak: true` says the caller means it (DECISIONS 35).
// Single DES is read (cms_enveloped.js) and never written.
var CIPHERS = {
  aes128CBC: { key: 16, iv: 16, block: 16 },
  aes192CBC: { key: 24, iv: 16, block: 16 },
  aes256CBC: { key: 32, iv: 16, block: 16 },
  des_ede3_cbc: { key: 24, iv: 8, block: 8, weak: true }
};

var WRAPS = { aes128Wrap: 128, aes192Wrap: 192, aes256Wrap: 256 };

// RFC 5753 table 2 (SHA-1, X9.63 arc) and RFC 5753 8.1 (SHA-2, SECG arc).
var KDFS = {
  sha1:   'dhSinglePass_stdDH_sha1kdf',
  sha224: 'ecdhX963KDF_SHA224',
  sha256: 'ecdhX963KDF_SHA256',
  sha384: 'ecdhX963KDF_SHA384',
  sha512: 'ecdhX963KDF_SHA512'
};

// ---------------------------------------------------------------------------

//   EnvelopedData ::= SEQUENCE {
//      version               CMSVersion,
//      originatorInfo    [0] IMPLICIT OriginatorInfo OPTIONAL,
//      recipientInfos        RecipientInfos,
//      encryptedContentInfo  EncryptedContentInfo,
//      unprotectedAttrs  [1] IMPLICIT UnprotectedAttributes OPTIONAL }
//
// parts:
//   cipher             'aes128CBC' | 'aes192CBC' | 'aes256CBC'
//   iv                 the IV the content was encrypted with
//   encrypted_content  the ciphertext; omit with detached: true
//   recipients         [{ type: 'ktri' | 'kari' | 'kekri', ... }]
//   content_type       dotted OID or 'data' (default)
//
// Returns ContentInfo DER, ready to send or wrap in S/MIME.
function enveloped_data(parts) {
  if (!parts || typeof parts !== 'object') {
    fail('bad-input', 'enveloped_data takes an object describing the message');
  }

  var cipher_name = canonical_or_null(parts.cipher);
  var cipher = cipher_name === null ? undefined : CIPHERS[cipher_name];

  if (cipher === undefined) {
    fail('unsupported-cipher', 'the content cipher is one of ' +
      Object.keys(CIPHERS).join(', ') + ' - for AES-GCM, CMS uses ' +
      'AuthEnvelopedData (RFC 5083): auth_enveloped_data()');
  }

  if (cipher.weak && parts.allow_weak !== true) {
    fail('weak-cipher', cipher_name + ' is for clients that have nothing ' +
      'better; pass { allow_weak: true } to send it');
  }

  var iv = to_bytes(parts.iv || new Uint8Array(0));

  if (iv.length !== cipher.iv) {
    fail('bad-iv-length', cipher_name + ' takes a ' + cipher.iv +
      '-byte IV, got ' + iv.length);
  }

  var rs = recipient_infos(parts.recipients);

  // RFC 5652 6.1, for a message with no originatorInfo and no
  // unprotectedAttrs - neither of which this writes:
  //   3   when any recipient is pwri (or ori)
  //   0   when every RecipientInfo is version 0
  //   2   otherwise
  var version = rs.pwri ? 3 : rs.all_v0 ? 0 : 2;

  var ci = encrypted_content_info(parts,
    W.sequence([W.oid(OID.by_name(cipher_name)), W.octet_string(iv)]),
    function (ct) {
      if (ct.length === 0 || ct.length % cipher.block !== 0) {
        fail('bad-ciphertext',
          'CBC ciphertext is a non-empty multiple of ' + cipher.block +
          ' bytes - PKCS#7 padding always adds at least one byte');
      }
    });

  var ed = W.sequence([W.integer([version]), rs.der, ci]);

  return W.to_bytes(W.sequence([
    W.oid(OID.from_string(CONTENT.envelopedData)),
    W.explicit(0, ed)
  ]));
}

// The RecipientInfos SET, and the two facts the version rule needs.
function recipient_infos(list) {
  if (!Array.isArray(list) || list.length === 0) {
    fail('no-recipients', 'an enveloped message needs at least one recipient');
  }

  var infos = [];
  var all_v0 = true;
  var pwri = false;
  var i;

  for (i = 0; i < list.length; i++) {
    var r = recipient_info(list[i], i);
    infos.push(r.der);
    if (r.version !== 0) { all_v0 = false; }
    // RFC 5652 6.1: version 3 "if any RecipientInfo structures include
    // pwri or ori" - and a kemri is an ori.
    if (list[i].type === 'pwri' || list[i].type === 'kemri') { pwri = true; }
  }

  return { der: W.set_of(infos), all_v0: all_v0, pwri: pwri };
}

//   EncryptedContentInfo ::= SEQUENCE {
//      contentType                 ContentType,
//      contentEncryptionAlgorithm  AlgorithmIdentifier,
//      encryptedContent        [0] IMPLICIT OCTET STRING OPTIONAL }
function encrypted_content_info(parts, algorithm, check) {
  var eci = [
    W.oid(OID.from_string(content_type_oid(parts.content_type))),
    algorithm
  ];

  if (parts.detached !== true) {
    if (!parts.encrypted_content) {
      fail('bad-input', 'encrypted_content is required unless detached');
    }
    var ct = to_bytes(parts.encrypted_content);
    check(ct);
    eci.push(W.implicit(0, W.octet_string(ct)));
  }

  return W.sequence(eci);
}

// ---------------------------------------------------------------------------
// AuthEnvelopedData - RFC 5083, AES-GCM per RFC 5084
// ---------------------------------------------------------------------------

var GCM = {
  aes128GCM: { key: 16 },
  aes192GCM: { key: 24 },
  aes256GCM: { key: 32 }
};

// ⚠ THE AAD, WHICH THE CALLER NEEDS BEFORE ENCRYPTING.
//
// GCM authenticates the authAttrs, so they are fixed first and their bytes
// go into the encryption call. RFC 5083 2.2: the DER of the attributes with
// a SET OF tag (0x31) - not the [1] they travel with - or ZERO bytes when
// there are none. auth_enveloped_data writes the same attributes with the same
// encoder, so the two cannot drift.
//
//   var aad = auth_aad({ content_type, auth_attrs });
//   var out = aes_gcm(cek, nonce, content, aad);       // ciphertext + tag
//   var der = auth_enveloped_data({ cipher, nonce, content_type, auth_attrs,
//                          encrypted_content: out.ct, mac: out.tag,
//                          recipients });
function auth_aad(parts) {
  var attrs = auth_attributes(parts || {});
  return attrs === null ? new Uint8Array(0) : W.to_bytes(W.set_of(attrs));
}

// [{ type, value }] as cms_build takes them, plus - when the content is not
// id-data - the contentType attribute RFC 5083 2.1 makes authAttrs carry.
// messageDigest is refused: RFC 5083 says it SHOULD NOT be there, because
// the tag already covers the content, and a digest of the plaintext beside
// the ciphertext is a confirmation oracle for a guessed message.
function auth_attributes(parts) {
  var list = parts.auth_attrs || [];
  var out = [];
  var has_type = false;
  var i;

  if (!Array.isArray(list)) {
    fail('bad-input', 'auth_attrs is a list of { type, value }');
  }

  for (i = 0; i < list.length; i++) {
    if (list[i] && list[i].type === 'messageDigest') {
      fail('bad-attribute', 'messageDigest does not belong in authAttrs - ' +
        'RFC 5083 2.1. The tag authenticates the content');
    }
    if (list[i] && list[i].type === 'contentType') { has_type = true; }
    out.push(extra_attribute(list[i]));
  }

  var type = content_type_oid(parts.content_type);

  if (type !== CONTENT.data && !has_type) {
    out.push(extra_attribute({ type: 'contentType',
      value: W.to_bytes(W.oid(OID.from_string(type))) }));
  }

  return out.length === 0 ? null : out;
}

//   AuthEnvelopedData ::= SEQUENCE {
//      version                   CMSVersion,   -- 0
//      originatorInfo        [0] IMPLICIT OriginatorInfo OPTIONAL,
//      recipientInfos            RecipientInfos,
//      authEncryptedContentInfo  EncryptedContentInfo,
//      authAttrs             [1] IMPLICIT AuthAttributes OPTIONAL,
//      mac                       MessageAuthenticationCode,
//      unauthAttrs           [2] IMPLICIT UnauthAttributes OPTIONAL }
//
// parts:
//   cipher             'aes128GCM' | 'aes192GCM' | 'aes256GCM'
//   nonce              12 bytes - the length RFC 5084 recommends and the
//                      only one GCM uses without hashing it first
//   tag_length         12 to 16 (default 16, what OpenSSL writes)
//   encrypted_content  the ciphertext WITHOUT the tag
//   mac                the tag, tag_length bytes
//   content_type, auth_attrs   as given to auth_aad - the same values
//   recipients         as for enveloped_data()
function auth_enveloped_data(parts) {
  if (!parts || typeof parts !== 'object') {
    fail('bad-input', 'auth_enveloped_data takes an object describing the message');
  }
  var gcm_name = canonical_or_null(parts.cipher);

  if (gcm_name === null || GCM[gcm_name] === undefined) {
    fail('unsupported-cipher', 'the content cipher is one of ' +
      Object.keys(GCM).join(', ') + ' - CBC goes in enveloped_data()');
  }

  var nonce = to_bytes(parts.nonce || new Uint8Array(0));

  if (nonce.length !== 12) {
    fail('bad-nonce-length', 'the GCM nonce is 12 bytes, got ' + nonce.length);
  }

  var tag_length = parts.tag_length === undefined ? 16 : parts.tag_length;

  if (typeof tag_length !== 'number' || tag_length % 1 !== 0 ||
      tag_length < 12 || tag_length > 16) {
    fail('bad-tag-length', 'tag_length is 12 to 16, RFC 5084');
  }

  var mac = to_bytes(parts.mac || new Uint8Array(0));

  if (mac.length !== tag_length) {
    fail('bad-tag-length', 'the mac is the ' + tag_length + '-byte GCM tag, ' +
      'got ' + mac.length + ' - pass the tag separately from the ciphertext');
  }

  // aes-ICVlen DEFAULT 12 - omitted when 12, as DER requires.
  var gcm_params = [W.octet_string(nonce)];
  if (tag_length !== 12) {
    gcm_params.push(W.integer([tag_length]));
  }

  var rs = recipient_infos(parts.recipients);
  var ci = encrypted_content_info(parts,
    W.sequence([W.oid(OID.by_name(gcm_name)), W.sequence(gcm_params)]),
    function () {});

  var fields = [W.integer([0]), rs.der, ci];
  var attrs = auth_attributes(parts);

  if (attrs !== null) {
    fields.push(W.implicit(1, W.set_of(attrs)));
  }

  fields.push(W.octet_string(mac));

  return W.to_bytes(W.sequence([
    W.oid(OID.from_string(CONTENT.authEnvelopedData)),
    W.explicit(0, W.sequence(fields))
  ]));
}

// ---------------------------------------------------------------------------
// AuthenticatedData - RFC 5652 section 9
// ---------------------------------------------------------------------------

// ⚠ THE BYTES TO MAC, WHICH THE CALLER NEEDS FIRST. With a digest - the usual
// form - the MAC is over the authAttrs (contentType, messageDigest and the
// caller's), SET-tagged; without one it is over the content itself, which
// RFC 5652 9.1 allows only for id-data. Written by cms_build's
// content_attributes, as a SignedData's signedAttrs are.
//
//   var input = authenticated_mac_input({ digest: 'sha256',
//                 content_digest: sha256(content) });
//   var der = authenticated_data({ mac_algorithm: 'hmacWithSHA256',
//                 digest: 'sha256', content_digest, content,
//                 mac: hmac_sha256(mac_key, input), recipients });
function authenticated_mac_input(parts) {
  var p = parts || {};
  var attrs = authenticated_attributes(p);
  if (attrs !== null) { return attrs; }
  if (p.content === undefined || p.content === null) {
    fail('bad-input', 'without a digest the MAC is over the content - ' +
      'pass content');
  }
  return to_bytes(p.content);
}

// The authAttrs SET, or null when no digest is named.
function authenticated_attributes(p) {
  var type = content_type_oid(p.content_type);

  if (p.digest === undefined || p.digest === null) {
    if (type !== CONTENT.data) {
      fail('missing-auth-attrs', 'content of type ' + type + ' needs ' +
        'authAttrs (RFC 5652 9.1): name the digest and pass content_digest');
    }
    if (p.auth_attrs !== undefined || p.signing_time !== undefined) {
      fail('bad-input', 'attributes need a digest - RFC 5652 9.1 makes ' +
        'message-digest one of them');
    }
    return null;
  }

  if (OID.digest_size(p.digest) === null) {
    fail('unsupported-digest', 'unrecognised digest ' + p.digest);
  }

  return content_attributes({ content_oid: type, digest: p.digest,
    content_digest: p.content_digest, signing_time: p.signing_time,
    attributes: p.auth_attrs });
}

//   AuthenticatedData ::= SEQUENCE {
//      version             CMSVersion,       -- 0: no originatorInfo here
//      recipientInfos      RecipientInfos,
//      macAlgorithm        MessageAuthenticationCodeAlgorithm,
//      digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
//      encapContentInfo    EncapsulatedContentInfo,
//      authAttrs       [2] IMPLICIT AuthAttributes OPTIONAL,
//      mac                 MessageAuthenticationCode }
function authenticated_data(parts) {
  if (!parts || typeof parts !== 'object') {
    fail('bad-input', 'authenticated_data takes an object describing the message');
  }

  var mac_name = canonical_or_null(parts.mac_algorithm);

  if (mac_name === null || !/^hmacWith/.test(mac_name)) {
    fail('unsupported-mac', 'mac_algorithm is an HMAC: hmacWithSHA256, ' +
      'or another hmacWith... name');
  }

  var mac = to_bytes(parts.mac || new Uint8Array(0));

  if (mac.length === 0) {
    fail('bad-input', 'mac is the MAC the caller computed over ' +
      'authenticated_mac_input(parts)');
  }

  var content = null;

  if (parts.detached !== true) {
    if (parts.content === undefined || parts.content === null) {
      fail('bad-input', 'content is required unless detached');
    }
    content = to_bytes(parts.content);
  }

  var attrs = authenticated_attributes(parts);
  var fields = [W.integer([0]), recipient_infos(parts.recipients).der,
                ALG.to_der(mac_name)];

  if (attrs !== null) {
    // [1] IMPLICIT: the AlgorithmIdentifier's SEQUENCE tag becomes 0xA1.
    fields.push(retag_constructed(digest_algorithm_to_der(parts.digest), 1));
  }

  fields.push(encapsulated_to_der(content_type_oid(parts.content_type), content));

  if (attrs !== null) {
    fields.push(retag_constructed(attrs, 2));   // the SET that was MACed, as [2]
  }

  fields.push(W.octet_string(mac));

  return W.to_bytes(W.sequence([
    W.oid(OID.from_string(CONTENT.authenticatedData)),
    W.explicit(0, W.sequence(fields))
  ]));
}

// ---------------------------------------------------------------------------
// CompressedData - RFC 3274
// ---------------------------------------------------------------------------

// The content goes in already compressed - ZLIB (RFC 1950), node:zlib's
// deflateSync - since this library compresses nothing, as it encrypts
// nothing. RFC 3274: version 0, id-alg-zlibCompress with no parameters.
function compressed_data(parts) {
  if (!parts || typeof parts !== 'object') {
    fail('bad-input', 'compressed_data takes { compressed, content_type? }');
  }

  var compressed = null;

  if (parts.detached !== true) {
    if (!parts.compressed) {
      fail('bad-input', 'compressed is the zlib stream (RFC 1950) - the ' +
        'output of deflateSync - unless detached');
    }
    compressed = to_bytes(parts.compressed);

    // RFC 1950 2.2: CMF says deflate (8) and the header is a multiple of 31.
    // A raw deflate or gzip stream - what deflateRawSync and gzipSync
    // write - fails this, and decompresses nowhere.
    if (compressed.length < 2 || (compressed[0] & 0x0F) !== 8 ||
        ((compressed[0] << 8) | compressed[1]) % 31 !== 0) {
      fail('not-zlib', 'compressed is not a zlib stream (RFC 1950): ' +
        'deflateSync writes one; deflateRawSync and gzipSync do not');
    }
  }

  return W.to_bytes(W.sequence([
    W.oid(OID.from_string(CONTENT.compressedData)),
    W.explicit(0, W.sequence([
      W.integer([0]),
      W.sequence([W.oid(OID.by_name('zlibCompress'))]),
      encapsulated_to_der(content_type_oid(parts.content_type), compressed)
    ]))
  ]));
}

function content_type_oid(t) {
  if (t === undefined || t === 'data') {
    return CONTENT.data;
  }
  if (/^\d+(\.\d+)+$/.test(t)) {
    return t;
  }
  fail('unknown-content-type', 'content_type is "data" or a dotted OID');
}

function recipient_info(r, i) {
  if (!r || typeof r !== 'object') {
    fail('bad-input', 'recipient ' + i + ' is an object');
  }
  if (!r.encrypted_key || to_bytes(r.encrypted_key).length === 0) {
    fail('bad-input', 'recipient ' + i + ' needs encrypted_key');
  }

  if (r.type === 'ktri') { return ktri(r); }
  if (r.type === 'kari') { return kari(r); }
  if (r.type === 'kekri') { return kekri(r); }
  if (r.type === 'pwri') { return pwri(r); }
  if (r.type === 'kemri') { return kemri(r); }

  fail('bad-recipient', 'recipient ' + i + ' type is ktri, kari, kekri, ' +
    'pwri or kemri');
}

//   KeyTransRecipientInfo ::= SEQUENCE {
//      version                 CMSVersion,  -- 0 or 2
//      rid                     RecipientIdentifier,
//      keyEncryptionAlgorithm  KeyEncryptionAlgorithmIdentifier,
//      encryptedKey            EncryptedKey }
function ktri(r) {
  var rid = recipient_id(r);
  var algorithm = r.algorithm === undefined ? 'rsaEncryption' : r.algorithm;
  var name = typeof algorithm === 'string' ? algorithm : algorithm.name;

  if (name !== 'rsaEncryption' && name !== 'rsaOAEP') {
    fail('unsupported-algorithm',
      'key transport is rsaEncryption (PKCS#1 v1.5) or rsaOAEP');
  }

  return {
    version: rid.version,
    der: W.sequence([
      W.integer([rid.version]),
      rid.der,
      ALG.to_der(algorithm),
      W.octet_string(to_bytes(r.encrypted_key))
    ])
  };
}

// RecipientIdentifier: issuerAndSerialNumber (version 0), or
// [0] subjectKeyIdentifier (version 2). By certificate unless `key_id` is
// given - the SKI form is what a recipient without a certificate needs.
function recipient_id(r) {
  if (r.key_id !== undefined) {
    return { version: 2, der: W.implicit(0, W.octet_string(to_bytes(r.key_id))) };
  }
  return { version: 0, der: issuer_and_serial(r.certificate) };
}

// IssuerAndSerialNumber - the shared writer, as cms_build names a signer.
function issuer_and_serial(cert) {
  return issuer_and_serial_to_der(cert, fail);
}

//   KeyAgreeRecipientInfo ::= SEQUENCE {
//      version                 CMSVersion,  -- always 3
//      originator          [0] EXPLICIT OriginatorIdentifierOrKey,
//      ukm                 [1] EXPLICIT UserKeyingMaterial OPTIONAL,
//      keyEncryptionAlgorithm  KeyEncryptionAlgorithmIdentifier,
//      recipientEncryptedKeys  RecipientEncryptedKeys }
function kari(r) {
  if (!r.ephemeral_point) {
    fail('bad-input', 'a kari recipient needs the ephemeral public key ' +
      'point, uncompressed, as ephemeral_point');
  }
  var wrap = wrap_name(r.wrap);
  var hash = r.kdf === undefined ? 'sha256' : r.kdf;

  if (KDFS[hash] === undefined) {
    fail('unsupported-kdf', 'kdf is the X9.63 hash: ' +
      Object.keys(KDFS).join(', '));
  }

  // OriginatorPublicKey ::= SEQUENCE { algorithm, publicKey BIT STRING }.
  // id-ecPublicKey with ABSENT parameters, which is what OpenSSL writes and
  // what RFC 5753 7.1.2 permits - the curve is the recipient's.
  var originator = W.explicit(0, W.implicit(1, W.sequence([
    W.sequence([W.oid(OID.by_name('ecPublicKey'))]),
    W.bit_string(to_bytes(r.ephemeral_point), 0)
  ])));

  var fields = [W.integer([3]), originator];

  if (r.ukm !== undefined && r.ukm !== null) {
    fields.push(W.explicit(1, W.octet_string(to_bytes(r.ukm))));
  }

  fields.push(W.sequence([
    W.oid(OID.by_name(KDFS[hash])),
    wrap_algorithm(wrap)
  ]));

  fields.push(W.sequence([
    W.sequence([issuer_and_serial(r.certificate),
                W.octet_string(to_bytes(r.encrypted_key))])
  ]));

  return { version: 3, der: W.implicit(1, W.sequence(fields)) };
}

// 'aes256Wrap', or node's 'id-aes256-wrap'.
function wrap_name(name) {
  var w = canonical_or_null(name);

  if (w === null || WRAPS[w] === undefined) {
    fail('unsupported-wrap', 'wrap is one of ' + Object.keys(WRAPS).join(', '));
  }
  return w;
}

// The AES key wraps take ABSENT parameters - RFC 3565 2.3.2.
function wrap_algorithm(name) {
  return W.sequence([W.oid(OID.by_name(name))]);
}

// ⚠ THE BYTES THE X9.63 KDF NEEDS BESIDES Z. See cms_enveloped.js, which
// builds the same structure from a received message - and the two are
// written separately, as every reader and writer pair here is.
//
//   ECC-CMS-SharedInfo ::= SEQUENCE {
//      keyInfo         AlgorithmIdentifier,        -- the wrap
//      entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,   -- the ukm
//      suppPubInfo [2] EXPLICIT OCTET STRING }     -- wrap key bits, uint32
function kari_shared_info(options) {
  var opts = options || {};
  var wrap = wrap_name(opts.wrap);
  var bits = WRAPS[wrap];

  var fields = [wrap_algorithm(wrap)];

  if (opts.ukm !== undefined && opts.ukm !== null) {
    fields.push(W.explicit(0, W.octet_string(to_bytes(opts.ukm))));
  }

  var len = int_bytes(bits);
  while (len.length < 4) { len.unshift(0); }
  fields.push(W.explicit(2, W.octet_string(len)));

  return W.to_bytes(W.sequence(fields));
}

//   [4] OtherRecipientInfo { id-ori-kem, KEMRecipientInfo ::= SEQUENCE {
//      version       CMSVersion,  -- always 0
//      rid           RecipientIdentifier,
//      kem           KEMAlgorithmIdentifier,
//      kemct         OCTET STRING,
//      kdf           KeyDerivationAlgorithmIdentifier,
//      kekLength     INTEGER (1..65535),
//      ukm       [0] EXPLICIT UserKeyingMaterial OPTIONAL,
//      wrap          KeyEncryptionAlgorithmIdentifier,
//      encryptedKey  EncryptedKey } }
//
// The kem, kdf and wrap identifiers are all written without parameters:
// RFC 9936 3 for ML-KEM, RFC 8619 for HKDF, RFC 3565 for the AES wraps.
function kemri(r) {
  var kem = r.kem;

  if (typeof kem !== 'string' || PQ_KEYS[kem] === undefined ||
      PQ_KEYS[kem].family !== 'ml-kem') {
    fail('unsupported-kem', 'kem is mlKem512, mlKem768 or mlKem1024');
  }

  var kemct = to_bytes(r.kem_ciphertext || new Uint8Array(0));

  if (kemct.length !== PQ_KEYS[kem].ciphertext) {
    fail('bad-ciphertext-length', kem + ' ciphertexts are ' +
      PQ_KEYS[kem].ciphertext + ' bytes - pass what encapsulate returned ' +
      'as kem_ciphertext; got ' + kemct.length);
  }

  var kdf = r.kdf === undefined ? 'hkdfWithSha256' : r.kdf;

  if (HKDFS.indexOf(kdf) === -1) {
    fail('unsupported-kdf', 'kdf is one of ' + HKDFS.join(', '));
  }

  var wrap = wrap_name(r.wrap);
  var kek_length = kem_kek_length(wrap, r.kek_length);

  // A KEMRecipientInfo is version 0 with either identifier, RFC 9629 3.
  var rid = recipient_id(r);
  var fields = [
    W.integer([0]),
    rid.der,
    W.sequence([W.oid(OID.by_name(kem))]),
    W.octet_string(kemct),
    W.sequence([W.oid(OID.by_name(kdf))]),
    W.unsigned(int_bytes(kek_length))
  ];

  if (r.ukm !== undefined && r.ukm !== null) {
    fields.push(W.explicit(0, W.octet_string(to_bytes(r.ukm))));
  }

  fields.push(wrap_algorithm(wrap));
  fields.push(W.octet_string(to_bytes(r.encrypted_key)));

  return {
    version: 0,
    der: W.implicit(4, W.sequence([W.oid(OID.by_name('ori_kem')),
                                   W.sequence(fields)]))
  };
}

var HKDFS = ['hkdfWithSha256', 'hkdfWithSha384', 'hkdfWithSha512'];

// kekLength: the wrap's key size, which RFC 9629 3 requires it to match.
// Given, it is checked; left out, it is the wrap's.
function kem_kek_length(wrap, given) {
  var want = WRAPS[wrap] / 8;

  if (given === undefined) {
    return want;
  }
  if (given !== want) {
    fail('inconsistent-kek-length', wrap + ' takes a ' + want +
      '-byte key; kek_length says ' + given);
  }
  return given;
}

// ⚠ THE KDF'S info FOR A kemri RECIPIENT. RFC 9629 5:
//
//   CMSORIforKEMOtherInfo ::= SEQUENCE {
//      wrap       KeyEncryptionAlgorithmIdentifier,
//      kekLength  INTEGER (1..65535),
//      ukm    [0] EXPLICIT UserKeyingMaterial OPTIONAL }
//
// Written separately from the reader's, which builds it from a received
// message - the pair agreeing is the check.
function kem_kdf_info(options) {
  var opts = options || {};
  var wrap = wrap_name(opts.wrap);
  var fields = [wrap_algorithm(wrap),
                W.unsigned(int_bytes(kem_kek_length(wrap, opts.kek_length)))];

  if (opts.ukm !== undefined && opts.ukm !== null) {
    fields.push(W.explicit(0, W.octet_string(to_bytes(opts.ukm))));
  }
  return W.to_bytes(W.sequence(fields));
}

//   KEKRecipientInfo ::= SEQUENCE {
//      version                 CMSVersion,  -- always 4
//      kekid                   KEKIdentifier,
//      keyEncryptionAlgorithm  KeyEncryptionAlgorithmIdentifier,
//      encryptedKey            EncryptedKey }
function kekri(r) {
  if (!r.kek_id) {
    fail('bad-input', 'a kekri recipient needs kek_id, the key identifier ' +
      'both sides agreed');
  }
  var wrap = wrap_name(r.wrap);

  return {
    version: 4,
    der: W.implicit(2, W.sequence([
      W.integer([4]),
      W.sequence([W.octet_string(to_bytes(r.kek_id))]),
      wrap_algorithm(wrap),
      W.octet_string(to_bytes(r.encrypted_key))
    ]))
  };
}

//   PasswordRecipientInfo ::= SEQUENCE {
//      version                     CMSVersion,   -- always 0
//      keyDerivationAlgorithm  [0] KeyDerivationAlgorithmIdentifier OPTIONAL,
//      keyEncryptionAlgorithm      KeyEncryptionAlgorithmIdentifier,
//      encryptedKey                EncryptedKey }
//
// RFC 3211. r: { type: 'pwri', kdf: { prf, salt, iterations }, cipher
// ('aes-256-cbc'), iv, encrypted_key }. kdf may be omitted when the KEK was
// agreed some other way. The order:
//
//   kek   = pbkdf2(prf, password, salt, iterations, key length of cipher)
//   block = pwri_key_block(cek, random(pwri_padding_length(cek.length)))
//   c1    = cbc_encrypt(cipher, kek, iv, block)             // no padding
//   wrapped = cbc_encrypt(cipher, kek, c1.last_block, c1)   // and again
//
// ⚠ [0] IS IMPLICIT - the CMS module's default - so the PBKDF2
// AlgorithmIdentifier's SEQUENCE tag is REPLACED by [0], not wrapped.
function pwri(r) {
  var fields = [W.integer([0])];

  if (r.kdf !== undefined && r.kdf !== null) {
    fields.push(retag_constructed(PBES2.pbkdf2_to_der(r.kdf), 0));
  }

  var inner = PBES2.cipher_to_der(r.cipher, r.iv);
  var block = PBES2.CIPHERS[pbes2_name(r.cipher)].iv;
  var key = to_bytes(r.encrypted_key);

  if (key.length < 2 * block || key.length % block !== 0) {
    fail('bad-encrypted-key',
      'an RFC 3211 wrapped key is a multiple of the cipher block and at ' +
      'least two blocks - see pwri_key_block');
  }

  fields.push(W.sequence([W.oid(OID.by_name('pwri_kek')), inner]));
  fields.push(W.octet_string(key));

  return { version: 0, der: W.implicit(3, W.sequence(fields)) };
}

function pbes2_name(cipher) {
  var name = canonical_or_null(cipher);

  if (name === null || PBES2.CIPHERS[name] === undefined) {
    fail('unsupported-cipher', 'the pwri cipher is one of ' +
      Object.keys(PBES2.CIPHERS).join(', '));
  }
  return name;
}

// A name in either spelling, as the library's own - or null when it is not
// one, so the caller's own "unsupported" message, naming the choices, is
// the one that is seen.
function canonical_or_null(name) {
  try {
    return ALG.canonical_name(name);
  } catch (e) {
    return null;
  }
}

// A SEQUENCE written by another writer, with its tag replaced by a
// constructed [n] - an IMPLICIT tag on a type the caller already encoded.
function retag_constructed(seq, n) {
  var bytes = W.to_bytes(seq);
  var out = new Uint8Array(bytes);
  out[0] = 0xA0 | n;
  return out;
}

// RFC 3211 2.3.1: the bytes the caller encrypts (twice) to wrap the CEK.
//
//   LEN || ~CEK[0] ~CEK[1] ~CEK[2] || CEK || padding
//
// padded to a multiple of the cipher block and at least two blocks. The
// padding is RANDOM and the caller supplies it - this library has no
// random source - exactly pwri_padding_length(cek.length) bytes.
function pwri_key_block(cek, padding, block_size) {
  var key = to_bytes(cek);
  var size = block_size === undefined ? 16 : block_size;

  if (key.length < 3 || key.length > 255) {
    fail('bad-input', 'the CEK is 3 to 255 bytes - RFC 3211 checks three ' +
      'and counts in one');
  }

  var need = pwri_padding_length(key.length, size);
  var pad = to_bytes(padding || new Uint8Array(0));

  if (pad.length !== need) {
    fail('bad-padding', 'a ' + key.length + '-byte key needs exactly ' +
      need + ' bytes of random padding, got ' + pad.length);
  }

  var out = new Uint8Array(4 + key.length + need);
  out[0] = key.length;
  out[1] = key[0] ^ 0xFF;
  out[2] = key[1] ^ 0xFF;
  out[3] = key[2] ^ 0xFF;
  out.set(key, 4);
  out.set(pad, 4 + key.length);
  return out;
}

function pwri_padding_length(cek_length, block_size) {
  var size = block_size === undefined ? 16 : block_size;
  var total = Math.ceil((cek_length + 4) / size) * size;
  if (total < 2 * size) {
    total = 2 * size;
  }
  return total - 4 - cek_length;
}

export {
  enveloped_data,
  auth_enveloped_data,
  auth_aad,
  authenticated_data,
  compressed_data,
  authenticated_mac_input,
  pwri_key_block,
  pwri_padding_length,
  kari_shared_info,
  kem_kdf_info,
  CIPHERS,
  GCM,
  KDFS
};
