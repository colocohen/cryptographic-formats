// Cryptographic Message Syntax, RFC 5652. Also called PKCS#7.
//
// The container for a SIGNED DOCUMENT, as opposed to a signed key. Code
// signing, PDF signatures, S/MIME and timestamp tokens all sit on it.
//
// ⚠ THE ONE THING THAT MAKES CMS DIFFERENT FROM EVERY OTHER SIGNED FORMAT
//    IN THIS LIBRARY, AND THE REASON MOST IMPLEMENTATIONS GET IT WRONG ONCE.
//
// RFC 5652 section 5.4. When `signedAttrs` is present - which it almost
// always is - THE SIGNATURE IS NOT OVER THE CONTENT. It is over the DER
// encoding of the SignedAttributes SET, and the content only enters through
// a `message-digest` attribute inside it.
//
// And the encoding used for the signature is not the bytes as they appear in
// the message: the field is `[0] IMPLICIT`, so it arrives tagged 0xA0, and
// RFC 5652 requires the signature to be computed with the UNIVERSAL SET tag
// 0x31 in its place.
//
//   in the message      A0 81 E4 ...        [0] IMPLICIT
//   what was signed     31 81 E4 ...        SET
//
// One byte. Get it wrong and every signature fails to verify, on a message
// that is perfectly good, for a reason nothing reports. signed_attrs_der()
// below does the substitution and is the only correct way to build the input.
//
// This library performs no cryptography: it returns the bytes to hash and the
// digest to compare against, and the caller does both.

import * as DER from './der_reader.js';
import * as W from './der_writer.js';
import * as F from './fields.js';

// Imported for its side effect: pkix.js defines AlgorithmIdentifier,
// RDNSequence, Extension and the other structures PKIX shares.
import './pkix.js';
import * as OID from './oid.js';
import * as ALG from './algorithm.js';
import * as X509 from './x509.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, hex, bytes_equal, int_value } from './commons/bytes.js';

var fail = make_fail_here('cms');

// The pieces cms.js shares with cms_enveloped.js - the content-type and
// attribute tables, EncapsulatedContentInfo, and the attributes - one copy.
import { CONTENT, ATTRIBUTE, read_encapsulated, read_attributes,
  required_attributes, content_signing_input, set_tagged } from './cms_read.js';

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

function from_der(input) {
  var bytes = to_bytes(input);

  return DER.read(bytes, function (r) {
    var ci = r.read_sequence();
    var type_oid = ci.read_oid();
    var type = OID.name_in_table(type_oid, CONTENT);

    if (type === null) {
      fail('unknown-content-type',
        'unrecognised CMS content type ' + OID.to_string(type_oid));
    }
    if (type !== 'signedData') {
      fail('unsupported-content-type',
        'this module reads signedData; the outer type is ' + type);
    }

    var wrapper = ci.read_explicit(0);
    var out = read_signed_data(wrapper);
    wrapper.expect_end();
    ci.expect_end();

    out.der = bytes;
    return out;
  });
}

//   SignedData ::= SEQUENCE {
//        version            CMSVersion,
//        digestAlgorithms   SET OF DigestAlgorithmIdentifier,
//        encapContentInfo   EncapsulatedContentInfo,
//        certificates   [0] IMPLICIT CertificateSet OPTIONAL,
//        crls           [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//        signerInfos        SET OF SignerInfo }
function read_signed_data(r) {
  var sd = r.read_sequence();
  var version = int_value(sd.read_unsigned(), 'SignedData version');

  if (version < 1 || version > 5) {
    fail('bad-version', 'SignedData version ' + version);
  }

  // The digest algorithms the signers used, listed up front so a verifier
  // knows what to compute before walking the signers.
  var digest_set = sd.read_set_of();
  var digests = [];

  while (digest_set.remaining() > 0) {
    var alg = F.read_type(digest_set, 'AlgorithmIdentifier');
    digests.push(OID.name_of(alg.algorithm) || OID.to_string(alg.algorithm));
  }

  var encap = read_encapsulated(sd);

  var certificates = [];
  var crls = [];

  if (sd.peek_tag() === 0xA0) {
    var cert_set = sd.read_implicit(0, 0x31);
    while (cert_set.remaining() > 0) {
      certificates.push(cert_set.capture());
    }
  }

  if (sd.peek_tag() === 0xA1) {
    var crl_set = sd.read_implicit(1, 0x31);
    while (crl_set.remaining() > 0) {
      crls.push(crl_set.capture());
    }
  }

  var signer_set = sd.read_set_of();
  var signers = [];

  while (signer_set.remaining() > 0) {
    signers.push(read_signer_info(signer_set));
  }

  // ⚠ A SignedData WITH NO SIGNERS IS A CERTIFICATE BUNDLE, NOT AN ERROR.
  //
  // RFC 5652 section 5.1 calls it the "degenerate" case and defines it
  // explicitly: an empty signerInfos, an empty digestAlgorithms, and no
  // eContent - the message exists only to carry the certificates and CRLs.
  //
  // This is what a `.p7b` file is, and a .p7b is how a certificate chain
  // travels: Windows exports them, Java keytool imports them, and every CA
  // download page offers one. Refusing it meant refusing the commonest
  // non-signature use of CMS there is.
  //
  // Reported as `degenerate` so a caller cannot mistake a bundle for a
  // message whose signature they forgot to check.
  var degenerate = signers.length === 0;

  if (degenerate) {
    if (encap.content !== null) {
      fail('degenerate-with-content',
        'a SignedData with no signers carries only certificates, and this ' +
        'one has content nobody has signed');
    }
    if (certificates.length === 0 && crls.length === 0) {
      fail('empty-signed-data',
        'no signers, no certificates and no CRLs - this message says ' +
        'nothing at all');
    }
  }

  sd.expect_end();

  return {
    version:      version,
    // ⚠ TRUE means this carries certificates and NOTHING IS SIGNED. A caller
    // that treated it as a verified message would be treating a bundle as a
    // proof.
    degenerate:   degenerate,
    digests:      digests,
    content_type: encap.type,
    content:      encap.content,
    detached:     encap.content === null,
    certificates: certificates,
    crls:         crls,
    signers:      signers
  };
}

//   SignerInfo ::= SEQUENCE {
//        version             CMSVersion,
//        sid                 SignerIdentifier,
//        digestAlgorithm     DigestAlgorithmIdentifier,
//        signedAttrs     [0] IMPLICIT SignedAttributes OPTIONAL,
//        signatureAlgorithm  SignatureAlgorithmIdentifier,
//        signature           SignatureValue,
//        unsignedAttrs   [1] IMPLICIT UnsignedAttributes OPTIONAL }
function read_signer_info(r) {
  var si = r.read_sequence();
  var version = int_value(si.read_unsigned(), 'SignerInfo version');

  //   SignerIdentifier ::= CHOICE {
  //        issuerAndSerialNumber  IssuerAndSerialNumber,
  //        subjectKeyIdentifier   [0] SubjectKeyIdentifier }
  //
  // RFC 5652 5.3 ties the version to which form is used: version 1 with
  // issuerAndSerialNumber, version 3 with subjectKeyIdentifier. A message
  // where they disagree is one whose signer is identified two ways.
  var sid;
  var tag = si.peek_tag();

  if (tag === 0x80) {
    sid = { by: 'key-id', key_id: si.read_implicit(0, 0x04).bytes };
    if (version !== 3) {
      fail('version-sid-mismatch',
        'subjectKeyIdentifier requires SignerInfo version 3, this says ' +
        version);
    }
  } else {
    var ias = F.read_type(si, 'IssuerAndSerialNumber');
    sid = { by: 'issuer-and-serial', issuer: ias.issuer,
            serial: ias.serial, serial_hex: hex(ias.serial) };
    if (version !== 1) {
      fail('version-sid-mismatch',
        'issuerAndSerialNumber requires SignerInfo version 1, this says ' +
        version);
    }
  }

  var digest_alg = F.read_type(si, 'AlgorithmIdentifier');

  // ⚠ THE BYTES THE SIGNATURE COVERS.
  //
  // Captured whole, tag included, because signed_attrs_der() has to rewrite
  // that tag from [0] IMPLICIT to SET before hashing - see the note at the
  // top of this file.
  var signed_attrs_raw = null;
  var signed_attrs = null;

  if (si.peek_tag() === 0xA0) {
    signed_attrs_raw = si.capture();
    signed_attrs = read_attributes(signed_attrs_raw);
  }

  var sig_alg = F.read_type(si, 'AlgorithmIdentifier');
  var signature = si.read_octet_string();

  var unsigned_attrs = null;

  if (si.peek_tag() === 0xA1) {
    // NOT covered by the signature, and named so nobody forgets. A timestamp
    // countersignature lives here, which is exactly why it has its own
    // signature rather than relying on this one.
    unsigned_attrs = read_attributes(si.capture());
  }

  si.expect_end();

  var out = {
    version:        version,
    sid:            sid,
    digest:         OID.name_of(digest_alg.algorithm) ||
                    OID.to_string(digest_alg.algorithm),
    signature_algorithm:  OID.name_of(sig_alg.algorithm) ||
                    OID.to_string(sig_alg.algorithm),
    signature_params: cms_signature_params(sig_alg, digest_alg, signature),
    signature:      signature,
    signed_attrs:   signed_attrs,
    signed_attrs_raw: signed_attrs_raw,
    unsigned_attrs_unsigned: unsigned_attrs
  };

  if (signed_attrs !== null) {
    var req = required_attributes(signed_attrs, 'signedAttrs');
    out.message_digest = req.message_digest;
    out.signed_content_type = req.content_type;
    if (req.signing_time !== undefined) {
      out.signing_time_claimed = req.signing_time;
    }
  }

  return out;
}

// ---------------------------------------------------------------------------
// The signing input
// ---------------------------------------------------------------------------

// ⚠ THE BYTES A CMS SIGNATURE COVERS, WITH THE TAG SUBSTITUTION RFC 5652
//    SECTION 5.4 REQUIRES.
//
// The signedAttrs field arrives as [0] IMPLICIT - tag 0xA0 - and the
// signature was computed with the UNIVERSAL SET tag 0x31 in its place.
// Everything after the first byte is unchanged.
//
// This is the single most common CMS mistake, and its symptom is that every
// signature fails on messages that are perfectly good. Nothing reports it,
// because a wrong hash and a wrong key look identical.
function signed_attrs_der(signer) {
  if (signer.signed_attrs_raw === null) {
    fail('no-signed-attrs',
      'this signer has no signedAttrs, so the signature is over the content ' +
      'itself - use content_signing_input instead');
  }

  return set_tagged(signer.signed_attrs_raw);   // RFC 5652 5.4
}

// The bytes to hash for a given signer, whichever form the message uses.
//
// Returns what to hash AND what the result should be compared against, so a
// caller cannot do half the check: with signedAttrs there are TWO digests -
// one over the content, compared against the message-digest attribute, and
// one over the attributes, which the signature covers.
function verification_plan(cms, signer, detached_content) {
  // { bytes, signature, algorithm } as every verification_plan here, plus
  // what CMS adds: the digest, and - with signedAttrs - the second check.
  if (signer.signed_attrs_raw === null) {
    return {
      kind:      'direct',
      bytes:     content_signing_input(cms, detached_content),
      signature: signer.signature,
      algorithm: signer.signature_algorithm,
      digest:    signer.digest,
      // ⚠ PURE ML-DSA AND SLH-DSA SIGN THE MESSAGE, NOT A HASH OF IT - so
      // without signedAttrs the digestAlgorithm means nothing, and RFC 9882
      // 3.3 / RFC 9814 4 say a verifier MUST ignore it.
      note:      /^(ml-dsa|slh-dsa)$/.test(signer.signature_params.scheme)
        ? 'no signedAttrs: verify the signature over the content itself ' +
          '(bytes), whole. ' + signer.signature_params.scheme + ' signs the ' +
          'message, and digest is to be ignored (RFC 9882 3.3, RFC 9814 4)'
        : 'no signedAttrs: verify the signature over the content ' +
          'itself (bytes), hashed with digest'
    };
  }

  return {
    kind:            'signed-attrs',
    // Step two: verify the signature over THESE bytes.
    bytes:           signed_attrs_der(signer),
    signature:       signer.signature,
    algorithm:       signer.signature_algorithm,
    digest:          signer.digest,
    // Step one: hash the content and compare with the attribute.
    content_bytes:   content_signing_input(cms, detached_content),
    expected_digest: signer.message_digest,
    note:            'RFC 5652 5.4: hash content_bytes and compare it with ' +
                     'expected_digest (the message-digest attribute), THEN ' +
                     'verify the signature over bytes ' +
                     '(the signedAttrs, with the SET tag substituted). ' +
                     'Skipping the first step leaves the signature ' +
                     'unconnected to the content.'
  };
}

// Whether a computed content digest matches the message-digest attribute.
// The comparison is here because getting it wrong is silent; the hashing is
// the caller's.
function digest_matches(signer, computed) {
  if (signer.message_digest === undefined) {
    fail('no-message-digest',
      'this signer has no message-digest attribute to compare against');
  }
  return bytes_equal(to_bytes(computed), signer.message_digest);
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

// Finds the certificate a signer names, among those the message carries.
//
// Returns null rather than throwing when it is absent: a detached
// certificate set is legitimate, and the caller may have the certificate
// from elsewhere.
function certificate_for(cms, signer) {
  var i;

  for (i = 0; i < cms.certificates.length; i++) {
    var cert;

    try {
      cert = X509.from_der(cms.certificates[i]);
    } catch (e) {
      continue;                  // a CertificateSet may hold other things
    }

    if (signer.sid.by === 'issuer-and-serial') {
      if (hex(cert.serial) === signer.sid.serial_hex &&
          X509.name_matches(cert.issuer, signer.sid.issuer)) {
        return cert;
      }
    } else {
      var ski = X509.extension(cert, 'ext_subjectKeyId');
      if (ski !== null && ski.parsed !== null &&
          bytes_equal(ski.parsed, signer.sid.key_id)) {
        return cert;
      }
    }
  }

  return null;
}

// ⚠ CMS SAYS "rsaEncryption" WHERE X.509 SAYS "sha256WithRSAEncryption".
//
// RFC 5754 3.2 and RFC 3370: a SignerInfo may name just the key algorithm -
// rsaEncryption, or id-ecPublicKey - and leave the hash to digestAlgorithm.
// OpenSSL writes rsaEncryption by default. So the scheme and hash are
// completed from the digest here, where both are in hand, rather than left
// for a caller to discover that "rsaEncryption" is a signature algorithm.
function cms_signature_params(sig_alg, digest_alg, signature) {
  var p = ALG.describe_signature(sig_alg, signature, fail);
  var digest = OID.name_of(digest_alg.algorithm);

  if (p.name === 'rsaEncryption') {
    p.scheme = 'pkcs1';
    p.hash = digest;
  } else if (p.name === 'ecPublicKey') {
    p.scheme = 'ecdsa';
    p.hash = digest;
  }
  // ⚠ RECOMPUTED, because the hash just changed. describe() saw
  // rsaEncryption with no hash and said weak: false - so a SHA-1
  // signature written the old way (rsaEncryption + digestAlgorithm sha1,
  // which is what most CMS signers write) came back not weak.
  p.weak = ALG.is_weak_hash(p.hash);
  return p;
}

export {
  from_der,
  signed_attrs_der,
  content_signing_input,
  verification_plan,
  digest_matches,
  certificate_for,
  CONTENT,
  ATTRIBUTE
};
