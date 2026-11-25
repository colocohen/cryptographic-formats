// Object identifiers, held as their DER content octets rather than as dotted
// strings.
//
// Two reasons, and the second is the one that matters. Comparing against a
// known OID is a byte comparison either way. But a dotted string DISCARDS the
// encoding, and the encoding is part of what must be validated: an OID with a
// sub-identifier written wider than it needs to be is a second encoding of
// the same identifier, and once it has become "1.2.840.113549.1.1.1" there is
// nothing left to refuse.
//
// So bytes are the representation, and to_string exists for error messages
// and for output the caller will show a human.

import * as W from './der_writer.js';

import { hex, bytes_equal, append } from './commons/bytes.js';
import { make_fail_here } from './commons/fail.js';

var fail = make_fail_here('oid');


// ---------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------

// The first two arcs are packed into one sub-identifier: 40*first + second.
// The first arc is 0, 1 or 2, and when it is 0 or 1 the second is limited to
// 0..39. When it is 2 the second is unbounded, which is why the reverse
// direction below has to check the packed value rather than assume.
function to_string(bytes) {
  if (bytes.length === 0) {
    fail('empty-oid', 'OID has no content octets');
  }

  var arcs = [];
  var value = 0;
  var started = false;
  var i;

  for (i = 0; i < bytes.length; i++) {
    var b = bytes[i];

    if (!started && b === 0x80) {
      fail('non-minimal-oid', 'sub-identifier has a leading 0x80');
    }
    started = true;

    // Values beyond 2^53 cannot be held exactly. Real OIDs do not reach
    // this, and silently losing precision would produce a plausible dotted
    // string that names a different identifier.
    if (value > 0x1FFFFFFFFFFFF) {
      fail('oid-arc-too-large', 'sub-identifier exceeds safe integer range');
    }

    value = (value * 128) + (b & 0x7F);

    if ((b & 0x80) === 0) {
      if (arcs.length === 0) {
        // Unpack the first two arcs.
        if (value < 40) {
          arcs.push(0);
          arcs.push(value);
        } else if (value < 80) {
          arcs.push(1);
          arcs.push(value - 40);
        } else {
          arcs.push(2);
          arcs.push(value - 80);
        }
      } else {
        arcs.push(value);
      }
      value = 0;
      started = false;
    }
  }

  if (started) {
    fail('truncated-oid', 'OID ends mid sub-identifier');
  }

  return arcs.join('.');
}

// The reverse. Used when a caller has a dotted string - from a config file,
// or from a spec they are reading - and needs the encoding to compare or to
// write.
function from_string(text) {
  var parts = String(text).split('.');
  var arcs  = [];
  var i;

  if (parts.length < 2) {
    fail('bad-oid-string', 'an OID needs at least two arcs: ' + text);
  }

  for (i = 0; i < parts.length; i++) {
    if (!/^\d+$/.test(parts[i])) {
      fail('bad-oid-string', 'arc "' + parts[i] + '" is not a number');
    }
    var n = parseInt(parts[i], 10);
    if (!isFinite(n) || n > Number.MAX_SAFE_INTEGER) {
      fail('oid-arc-too-large', 'arc ' + parts[i] + ' is out of range');
    }
    arcs.push(n);
  }

  if (arcs[0] > 2) {
    fail('bad-oid-string', 'first arc must be 0, 1 or 2, got ' + arcs[0]);
  }
  if (arcs[0] < 2 && arcs[1] > 39) {
    fail('bad-oid-string',
      'second arc must be 0 to 39 when the first is ' + arcs[0]);
  }

  var out = W.base128(arcs[0] * 40 + arcs[1]);
  for (i = 2; i < arcs.length; i++) {
    append(out, W.base128(arcs[i]));
  }
  return new Uint8Array(out);
}


// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

function equal(a, b) {
  return bytes_equal(a, b);
}

// ---------------------------------------------------------------------------
// Known identifiers
// ---------------------------------------------------------------------------

// Held as dotted strings here for readability and converted once at load. A
// table of raw byte arrays would be unreadable, and an unreadable table is
// one nobody checks.
//
// The curve identifiers are the load-bearing ones. brainpoolP256t1 and
// brainpoolP256r1 share points, so a key labelled t1 whose point lies on r1
// must be refused on the strength of the LABEL - the point alone cannot say.
// Discarding the algorithm identifier makes those cases unanswerable.

var DOTTED = {
  // key algorithms
  rsaEncryption:      '1.2.840.113549.1.1.1',
  rsassaPss:          '1.2.840.113549.1.1.10',
  ecPublicKey:        '1.2.840.10045.2.1',
  // X9.62's field type for explicit ECParameters over GF(p) - the one kind
  // ec_domain.js reads, and only as a named curve's (DECISIONS 46).
  primeField:         '1.2.840.10045.1.1',
  ecDH:               '1.3.132.1.12',
  ecMQV:              '1.3.132.1.13',
  X25519:             '1.3.101.110',
  X448:               '1.3.101.111',
  Ed25519:            '1.3.101.112',
  Ed448:              '1.3.101.113',

  // ⚠ THE POST-QUANTUM ALGORITHMS - NIST's CSOR arc, as RFC 9881 (ML-DSA),
  // RFC 9909 (SLH-DSA) and RFC 9935 (ML-KEM) use them. Each names the
  // parameter set itself; the parameters field MUST be absent. dumpasn1
  // writes `mldsa44`; this library `mlDsa44`, as it writes `ecdsaWithSHA256`.
  mlDsa44:            '2.16.840.1.101.3.4.3.17',
  mlDsa65:            '2.16.840.1.101.3.4.3.18',
  mlDsa87:            '2.16.840.1.101.3.4.3.19',
  slhDsaSha2_128s:    '2.16.840.1.101.3.4.3.20',
  slhDsaSha2_128f:    '2.16.840.1.101.3.4.3.21',
  slhDsaSha2_192s:    '2.16.840.1.101.3.4.3.22',
  slhDsaSha2_192f:    '2.16.840.1.101.3.4.3.23',
  slhDsaSha2_256s:    '2.16.840.1.101.3.4.3.24',
  slhDsaSha2_256f:    '2.16.840.1.101.3.4.3.25',
  slhDsaShake_128s:   '2.16.840.1.101.3.4.3.26',
  slhDsaShake_128f:   '2.16.840.1.101.3.4.3.27',
  slhDsaShake_192s:   '2.16.840.1.101.3.4.3.28',
  slhDsaShake_192f:   '2.16.840.1.101.3.4.3.29',
  slhDsaShake_256s:   '2.16.840.1.101.3.4.3.30',
  slhDsaShake_256f:   '2.16.840.1.101.3.4.3.31',
  // The pre-hash variants (HashML-DSA, HashSLH-DSA). Named so they can be
  // reported; RFC 9881 and RFC 9909 do not use them in certificates.
  hashMlDsa44WithSha512: '2.16.840.1.101.3.4.3.32',
  hashMlDsa65WithSha512: '2.16.840.1.101.3.4.3.33',
  hashMlDsa87WithSha512: '2.16.840.1.101.3.4.3.34',
  mlKem512:           '2.16.840.1.101.3.4.4.1',
  mlKem768:           '2.16.840.1.101.3.4.4.2',
  mlKem1024:          '2.16.840.1.101.3.4.4.3',
  // The SHAKE hashes RFC 9814 names for SLH-DSA in CMS.
  shake128:           '2.16.840.1.101.3.4.2.11',
  shake256:           '2.16.840.1.101.3.4.2.12',
  // RFC 8619 HKDF - the KDF RFC 9936 requires for ML-KEM in CMS.
  hkdfWithSha256:     '1.2.840.113549.1.9.16.3.28',
  hkdfWithSha384:     '1.2.840.113549.1.9.16.3.29',
  hkdfWithSha512:     '1.2.840.113549.1.9.16.3.30',
  // RFC 9629 - the OtherRecipientInfo type of a KEMRecipientInfo.
  ori_kem:            '1.2.840.113549.1.9.16.13.3',
  // RFC 3274: CMS CompressedData, and its one algorithm.
  zlibCompress:       '1.2.840.113549.1.9.16.3.8',
  dsa:                '1.2.840.10040.4.1',
  dhKeyAgreement:     '1.2.840.113549.1.3.1',

  // named curves
  secp192r1:          '1.2.840.10045.3.1.1',
  secp224r1:          '1.3.132.0.33',
  secp256r1:          '1.2.840.10045.3.1.7',
  secp384r1:          '1.3.132.0.34',
  secp521r1:          '1.3.132.0.35',
  secp256k1:          '1.3.132.0.10',
  brainpoolP256r1:    '1.3.36.3.3.2.8.1.1.7',
  brainpoolP256t1:    '1.3.36.3.3.2.8.1.1.8',
  brainpoolP320r1:    '1.3.36.3.3.2.8.1.1.9',
  brainpoolP320t1:    '1.3.36.3.3.2.8.1.1.10',
  brainpoolP384r1:    '1.3.36.3.3.2.8.1.1.11',
  brainpoolP384t1:    '1.3.36.3.3.2.8.1.1.12',
  brainpoolP512r1:    '1.3.36.3.3.2.8.1.1.13',
  brainpoolP512t1:    '1.3.36.3.3.2.8.1.1.14',

  // digests
  sha1:               '1.3.14.3.2.26',
  sha224:             '2.16.840.1.101.3.4.2.4',
  sha256:             '2.16.840.1.101.3.4.2.1',
  sha384:             '2.16.840.1.101.3.4.2.2',
  sha512:             '2.16.840.1.101.3.4.2.3',
  sha3_224:           '2.16.840.1.101.3.4.2.7',
  sha3_256:           '2.16.840.1.101.3.4.2.8',
  sha3_384:           '2.16.840.1.101.3.4.2.9',
  sha3_512:           '2.16.840.1.101.3.4.2.10',

  // signature algorithms
  sha224WithRSA:      '1.2.840.113549.1.1.14',
  sha256WithRSA:      '1.2.840.113549.1.1.11',
  sha384WithRSA:      '1.2.840.113549.1.1.12',
  sha512WithRSA:      '1.2.840.113549.1.1.13',
  ecdsaWithSHA256:    '1.2.840.10045.4.3.2',
  ecdsaWithSHA384:    '1.2.840.10045.4.3.3',
  ecdsaWithSHA512:    '1.2.840.10045.4.3.4',

  // key derivation and encryption, for PBES2 and PKCS#12
  pbkdf2:             '1.2.840.113549.1.5.12',
  pbes2:              '1.2.840.113549.1.5.13',
  // RFC 9579: PBKDF2-then-HMAC, the MAC a PKCS#12 file uses in place of the
  // PKCS#12 KDF. FIPS-compatible, which the old MAC is not.
  pbmac1:             '1.2.840.113549.1.5.14',
  // RFC 3211: the key wrap a CMS password recipient uses - a CBC cipher
  // applied twice, named inside this identifier's parameters.
  pwri_kek:           '1.2.840.113549.1.9.16.3.9',
  hmacWithSHA1:       '1.2.840.113549.2.7',
  hmacWithSHA224:     '1.2.840.113549.2.8',
  hmacWithSHA256:     '1.2.840.113549.2.9',
  hmacWithSHA384:     '1.2.840.113549.2.10',
  hmacWithSHA512:     '1.2.840.113549.2.11',
  aes128CBC:          '2.16.840.1.101.3.4.1.2',
  aes192CBC:          '2.16.840.1.101.3.4.1.22',
  aes256CBC:          '2.16.840.1.101.3.4.1.42',
  // ECB: no IV, and equal blocks encrypt equally. Named because OpenSSL
  // writes PKCS#8 with it when asked (-v2 aes-256-ecb, or node's export with
  // cipher 'aes-256-ecb'); pbes2.js reads it there, marked weak.
  aes128ECB:          '2.16.840.1.101.3.4.1.1',
  aes192ECB:          '2.16.840.1.101.3.4.1.21',
  aes256ECB:          '2.16.840.1.101.3.4.1.41',
  des_ede3_cbc:       '1.2.840.113549.3.7',
  // Single DES, OIW's arc: a 56-bit key, broken for decades - and what the
  // micromdm SCEP client still encrypts with by default. Named so it is
  // described rather than shown as a dotted OID; refusing it is policy.
  desCBC:             '1.3.14.3.2.7',

  // X.509 attribute types
  commonName:         '2.5.4.3',
  countryName:        '2.5.4.6',
  localityName:       '2.5.4.7',
  // ⚠ The RFC spells these stateOrProvinceName and organizationalUnitName.
  // This library drops the suffix, because every attribute in this arc ends
  // in Name and the word carries nothing - but the SHORTENING WAS NOT
  // APPLIED CONSISTENTLY: commonName and countryName kept it while
  // stateOrProvince and organizationalUnit lost it.
  //
  // Left as they are rather than renamed, because these names appear in
  // every caller's output and in this library's own tests, and a rename to
  // settle a matter of taste is a breaking change for no gain. Recorded so
  // the inconsistency is a known one rather than a puzzle.
  stateOrProvince:    '2.5.4.8',
  organizationName:   '2.5.4.10',
  organizationalUnit: '2.5.4.11',
  emailAddress:       '1.2.840.113549.1.9.1',

  // ---------------------------------------------------------------------
  // X.520 name attributes
  // ---------------------------------------------------------------------
  //
  // ⚠ A SWEEP AGAINST RFC 5280 4.1.2.4 FOUND FIVE OF THE TEN IT SAYS AN
  //    IMPLEMENTATION MUST BE PREPARED TO RECEIVE.
  //
  // An unnamed attribute is not lost - name_to_string falls back to the
  // dotted form and name_matches compares the encodings - so nothing was
  // wrong. But a subject printed as `2.5.4.5=12345` instead of
  // `serialNumber=12345` is a subject an operator cannot read, and
  // domainComponent is how Active Directory and LDAP write every name they
  // issue.
  serialNumber:       '2.5.4.5',
  title:              '2.5.4.12',
  dnQualifier:        '2.5.4.46',
  pseudonym:          '2.5.4.65',

  // The ones RFC 5280 says SHOULD be supported.
  surname:            '2.5.4.4',
  givenName:          '2.5.4.42',
  initials:           '2.5.4.43',
  generationQualifier: '2.5.4.44',
  streetAddress:      '2.5.4.9',
  postalCode:         '2.5.4.17',
  postalAddress:      '2.5.4.16',
  // RFC 4519. Every name Active Directory and LDAP issue is built from
  // these, and a certificate from an enterprise CA is mostly dc= components.
  domainComponent:    '0.9.2342.19200300.100.1.25',
  // RFC 4519 uid - LDAP's user ID, beside dc= in directory names.
  userId:             '0.9.2342.19200300.100.1.1',

  // Seen in EV and QWAC certificates, which is where a name is most likely
  // to be read by a person rather than a program.
  businessCategory:   '2.5.4.15',
  telephoneNumber:    '2.5.4.20',
  organizationIdentifier: '2.5.4.97',


  // ---------------------------------------------------------------------
  // Added after a sweep against Peter Gutmann's dumpasn1.cfg
  // ---------------------------------------------------------------------
  //
  // ⚠ 91 OF OUR 93 WERE CONFIRMED, AND THE GAP WAS IN WHAT WE DID NOT HAVE.
  //
  // The two Gutmann does not list are SECG's ecDH and ecMQV arcs, which are
  // real - so nothing here was wrong. What the sweep found is what a real
  // file will contain and this table could not name:
  //
  //   sha1WithRSAEncryption   the signature algorithm of EVERY certificate
  //                           issued before about 2016. A library that
  //                           reports it as a dotted string cannot tell an
  //                           operator why their old certificate is weak.
  //   the AES GCM and wrap    what JWE and CMS actually use. aes256CBC was
  //     identifiers           here and aes256GCM was not.
  //   rsaOAEP and mgf1        RSA-OAEP names its mask function by OID
  //   dsaWithSHA*             DSA certificates are rare and not extinct
  //
  // Names follow this library's style rather than Gutmann's - `aes256GCM`
  // and not `aes256-GCM` - because a JavaScript identifier cannot hold a
  // hyphen and the table is read from code. The dotted values are his.
  md2WithRSAEncryption:   '1.2.840.113549.1.1.2',  // md2WithRSAEncryption
  md4WithRSAEncryption:   '1.2.840.113549.1.1.3',  // md4WithRSAEncryption
  md5WithRSAEncryption:   '1.2.840.113549.1.1.4',  // md5WithRSAEncryption
  sha1WithRSAEncryption:  '1.2.840.113549.1.1.5',  // sha1WithRSAEncryption
  // ⚠ The OIW arc's SHA-1 with RSA - OpenSSL's "RSA-SHA1-2". Old
  // certificates and some Java signers still carry it, and reported as a
  // dotted string it could not be flagged weak.
  oiwSha1WithRSA:         '1.3.14.3.2.29',      // sha-1WithRSAEncryption
  // And the OIW arc's DSA with SHA-1, for the same reason: as a dotted
  // string it was never flagged weak (reported from lemon, which flags it).
  oiwDsaWithSHA1:         '1.3.14.3.2.27',      // dsaWithSHA1
  rsaOAEP:                '1.2.840.113549.1.1.7',  // rsaOAEP
  mgf1:                   '1.2.840.113549.1.1.8',  // pkcs1-MGF
  pSpecified:             '1.2.840.113549.1.1.9',  // rsaOAEP-pSpecified
  ecdsaWithSHA1:          '1.2.840.10045.4.1',  // ecdsaWithSHA1
  dsa:                    '1.2.840.10040.4.1',  // dsa
  dsaWithSHA1:            '1.2.840.10040.4.3',  // dsaWithSha1
  dsaWithSHA224:          '2.16.840.1.101.3.4.3.1',  // dsaWithSha224
  dsaWithSHA256:          '2.16.840.1.101.3.4.3.2',  // dsaWithSha256
  // ⚠ THE dumpasn1 CROSS-CHECK CAUGHT A TRANSCRIPTION ERROR HERE.
  //
  // This was written as ecdsaWithSHA3_256 against .3.9, which is
  // ecdsaWithSha3-224. Off by one, and a signature algorithm reported as the
  // wrong hash is the kind of mistake that survives every round-trip test in
  // the suite - the bytes go in and come out unchanged, and only the NAME is
  // wrong.
  ecdsaWithSHA3_224:      '2.16.840.1.101.3.4.3.9',
  ecdsaWithSHA3_256:      '2.16.840.1.101.3.4.3.10',
  ecdsaWithSHA3_384:      '2.16.840.1.101.3.4.3.11',
  ecdsaWithSHA3_512:      '2.16.840.1.101.3.4.3.12',
  aes128Wrap:             '2.16.840.1.101.3.4.1.5',  // aes128-wrap
  aes128GCM:              '2.16.840.1.101.3.4.1.6',  // aes128-GCM
  aes128CCM:              '2.16.840.1.101.3.4.1.7',  // aes128-CCM
  aes192Wrap:             '2.16.840.1.101.3.4.1.25',  // aes192-wrap
  aes192GCM:              '2.16.840.1.101.3.4.1.26',  // aes192-GCM
  aes192CCM:              '2.16.840.1.101.3.4.1.27',  // aes192-CCM
  aes256Wrap:             '2.16.840.1.101.3.4.1.45',  // aes256-wrap
  aes256GCM:              '2.16.840.1.101.3.4.1.46',  // aes256-GCM
  aes256CCM:              '2.16.840.1.101.3.4.1.47',  // aes256-CCM
  rc2CBC:                 '1.2.840.113549.3.2',  // rc2CBC
  rc4:                    '1.2.840.113549.3.4',  // rc4
  ct_tstInfo:             '1.2.840.113549.1.9.16.1.4',  // tSTInfo
  aa_timeStampToken:      '1.2.840.113549.1.9.16.2.14',  // timeStampToken
  sect163k1:              '1.3.132.0.1',  // sect163k1
  secp224r1:              '1.3.132.0.33',  // secp224r1
  prime192v2:             '1.2.840.10045.3.1.2',  // prime192v2
  brainpoolP160r1:        '1.3.36.3.3.2.8.1.1.1',  // brainpoolP160r1
  brainpoolP192r1:        '1.3.36.3.3.2.8.1.1.3',  // brainpoolP192r1
  brainpoolP224r1:        '1.3.36.3.3.2.8.1.1.5',  // brainpoolP224r1

  // PKCS#9 attributes, RFC 2985
  extensionRequest:   '1.2.840.113549.1.9.14',
  challengePassword:  '1.2.840.113549.1.9.7',

  // X.509 extensions
  ext_subjectKeyId:      '2.5.29.14',
  ext_keyUsage:          '2.5.29.15',
  ext_subjectAltName:    '2.5.29.17',
  ext_issuerAltName:     '2.5.29.18',
  ext_basicConstraints:  '2.5.29.19',
  ext_nameConstraints:   '2.5.29.30',
  ext_crlDistribution:   '2.5.29.31',
  ext_certificatePolicy: '2.5.29.32',
  ext_authorityKeyId:    '2.5.29.35',
  ext_extKeyUsage:       '2.5.29.37',

  // ⚠ RFC 6962 - Certificate Transparency. Chrome has required these since
  // 2018, so every public TLS certificate carries one.
  //
  // In the Google private arc rather than the PKIX one, which is why it
  // looks nothing like the extensions above.
  ext_sct_list:          '1.3.6.1.4.1.11129.2.4.2',
  // Device attestation (device_attestation.js): Apple's WebAuthn / App
  // Attest nonce, its Managed Device Attestation values, and Android's
  // KeyDescription.
  ext_appleNonce:        '1.2.840.113635.100.8.2',
  ext_appleSerialNumber: '1.2.840.113635.100.8.9.1',
  ext_appleUdid:         '1.2.840.113635.100.8.9.2',
  ext_appleOsVersion:    '1.2.840.113635.100.8.10.1',
  ext_appleSepOsVersion: '1.2.840.113635.100.8.10.2',
  ext_appleLlbVersion:   '1.2.840.113635.100.8.10.3',
  ext_appleFreshnessCode: '1.2.840.113635.100.8.11.1',
  ext_androidKeyDescription: '1.3.6.1.4.1.11129.2.1.17',
  // The precertificate poison extension: a critical extension with a NULL
  // value, present so that a precertificate CANNOT be used as a
  // certificate. Every conforming implementation refuses it, which is the
  // point.
  ext_precert_poison:    '1.3.6.1.4.1.11129.2.4.3',

  // ---------------------------------------------------------------------
  // ECDH key agreement schemes, RFC 3278 and RFC 5753
  // ---------------------------------------------------------------------
  //
  // ⚠ WHAT `openssl cms -encrypt` PRODUCES FOR AN EC RECIPIENT, and what a
  // KeyAgreeRecipientInfo names.
  //
  // The 1.3.133.16.840.63.* arc is ANSI X9.63 by way of RFC 3278, and it is
  // NOT in Gutmann's table - the only identifiers in this library that are
  // not. Verified against RFC 3278 section 8.2 and against what openssl
  // writes, which is the pair of references that matters here.
  // RFC 4210 password-based MAC and the HMAC identifiers it names.
  //
  // ⚠ THE NAMES COME FROM dumpasn1, AND MINE WERE WRONG TWICE.
  //
  // I wrote `hmac_sha1` for 1.3.6.1.5.5.8.1.1 and `hmac_sha256` for .1.2.
  // The registry says hmacMD5 and hmacSHA - so the first named the wrong
  // digest entirely and the second named a digest the identifier does not
  // specify.
  //
  // A CMP message using .1.1 is MAC'd with MD5, and a library reporting it
  // as SHA-1 would tell an operator their enrolment is stronger than it is.
  // An encoder test cannot catch that; only a second naming source can.
  passwordBasedMac:      '1.2.840.113533.7.66.13',
  hmacMD5:               '1.3.6.1.5.5.8.1.1',
  hmacSHA:               '1.3.6.1.5.5.8.1.2',

  dhSinglePass_stdDH_sha1kdf:   '1.3.133.16.840.63.0.2',
  dhSinglePass_cofactorDH_sha1kdf: '1.3.133.16.840.63.0.3',

  // ⚠ RFC 5753 added the SHA-2 variants in the SECG arc, and SECG NAMES THEM
  // DIFFERENTLY - ecdhX963KDF rather than dhSinglePass.
  //
  // The first draft here carried the dhSinglePass names across from the X9.63
  // arc above, on the assumption that the same scheme keeps the same name in
  // a new arc. It does not, and the dumpasn1 cross-check said so
  // immediately - which is the whole reason that check exists: an encoder
  // test cannot tell you a name is wrong.
  ecdhX963KDF_SHA224: '1.3.132.1.11.0',
  ecdhX963KDF_SHA256: '1.3.132.1.11.1',
  ecdhX963KDF_SHA384: '1.3.132.1.11.2',
  ecdhX963KDF_SHA512: '1.3.132.1.11.3',
  eccofactordhX963KDF_SHA224: '1.3.132.1.14.0',
  eccofactordhX963KDF_SHA256: '1.3.132.1.14.1',
  ext_policyMappings:    '2.5.29.33',
  ext_policyConstraints: '2.5.29.36',
  ext_inhibitAnyPolicy:  '2.5.29.54',
  ext_freshestCRL:       '2.5.29.46',
  ext_subjectDirectoryAttributes: '2.5.29.9',

  // RFC 5280 section 4.2.2. Private extensions, in the PKIX arc rather than
  // the X.500 one - which is why they are numbered so differently from the
  // rest and easy to miss when transcribing a table.
  ext_authorityInfoAccess: '1.3.6.1.5.5.7.1.1',
  ext_subjectInfoAccess:   '1.3.6.1.5.5.7.1.11',

  // The access methods those two name.
  ad_ocsp:               '1.3.6.1.5.5.7.48.1',
  ad_caIssuers:          '1.3.6.1.5.5.7.48.2',
  ad_timeStamping:       '1.3.6.1.5.5.7.48.3',
  ad_caRepository:       '1.3.6.1.5.5.7.48.5',

  // The policy qualifiers certificatePolicies carries.
  policy_qualifier_cps:    '1.3.6.1.5.5.7.2.1',
  policy_qualifier_unotice: '1.3.6.1.5.5.7.2.2',
  // The "any policy" wildcard, which inhibitAnyPolicy exists to switch off.
  any_policy:            '2.5.29.32.0',

  // OCSP, RFC 6960
  ocsp_basic:            '1.3.6.1.5.5.7.48.1.1',
  ocsp_nonce:            '1.3.6.1.5.5.7.48.1.2',
  ocsp_noCheck:          '1.3.6.1.5.5.7.48.1.5',
  ext_crlReason:         '2.5.29.21',
  ext_crlNumber:         '2.5.29.20',
  ext_invalidityDate:    '2.5.29.24',

  // Extended key usage purposes, RFC 5280 4.2.1.12
  eku_serverAuth:        '1.3.6.1.5.5.7.3.1',
  eku_clientAuth:        '1.3.6.1.5.5.7.3.2',
  eku_codeSigning:       '1.3.6.1.5.5.7.3.3',
  eku_emailProtection:   '1.3.6.1.5.5.7.3.4',
  eku_timeStamping:      '1.3.6.1.5.5.7.3.8',
  eku_OCSPSigning:       '1.3.6.1.5.5.7.3.9',
  // RFC 5280 4.2.1.12's "any purpose" - missing, so it came back dotted.
  eku_anyExtendedKeyUsage: '2.5.29.37.0',

  // CMP InfoTypeAndValue types (id-it), RFC 4210 5.3.19 and RFC 9480 - in
  // a header's generalInfo and in genm / genp.
  it_signKeyPairTypes:   '1.3.6.1.5.5.7.4.2',
  it_implicitConfirm:    '1.3.6.1.5.5.7.4.13',
  it_confirmWaitTime:    '1.3.6.1.5.5.7.4.14',
  it_origPKIMessage:     '1.3.6.1.5.5.7.4.15',
  it_caCerts:            '1.3.6.1.5.5.7.4.17',
  it_rootCaKeyUpdate:    '1.3.6.1.5.5.7.4.18',
  it_rootCaCert:         '1.3.6.1.5.5.7.4.20',
  it_certReqTemplate:    '1.3.6.1.5.5.7.4.19',
  it_certProfile:        '1.3.6.1.5.5.7.4.21',
  it_crlStatusList:      '1.3.6.1.5.5.7.4.22',
  it_crls:               '1.3.6.1.5.5.7.4.23',

  // otherName type-ids x509.js decodes: Microsoft's UPN, and the device
  // identities of RFC 4043 and RFC 4108 5 (id-on, 1.3.6.1.5.5.7.8).
  on_userPrincipalName:  '1.3.6.1.4.1.311.20.2.3',
  on_permanentIdentifier: '1.3.6.1.5.5.7.8.3',
  on_hardwareModuleName: '1.3.6.1.5.5.7.8.4',

  // SCEP's signed attributes, RFC 8894 3.2.1 (table 2) - VeriSign's arc,
  // from before SCEP was an RFC - and failInfoText, RFC 8894 6 (id-scep 1).
  scep_messageType:      '2.16.840.1.113733.1.9.2',
  scep_pkiStatus:        '2.16.840.1.113733.1.9.3',
  scep_failInfo:         '2.16.840.1.113733.1.9.4',
  scep_senderNonce:      '2.16.840.1.113733.1.9.5',
  scep_recipientNonce:   '2.16.840.1.113733.1.9.6',
  scep_transactionID:    '2.16.840.1.113733.1.9.7',
  scep_failInfoText:     '1.3.6.1.5.5.7.24.1'
};

// name -> encoding bytes
var BY_NAME = {};
// hex of encoding -> name, for the reverse lookup an error message needs
var BY_HEX = {};

// ⚠ THE LOOKUP INDEX: first byte, then length, then a short list.
//
// Almost every OID in circulation starts 0x2A (1.2), 0x60 (2.16), 0x2B
// (1.3) or 0x55 (2.5), so the first byte alone does not narrow much - but
// first byte AND length reduces 154 identifiers to at most a handful, and
// the comparison that follows touches no memory beyond them.
var BY_FIRST = {};

(function build() {
  var name;
  for (name in DOTTED) {
    if (Object.prototype.hasOwnProperty.call(DOTTED, name)) {
      var bytes = from_string(DOTTED[name]);
      BY_NAME[name] = bytes;
      BY_HEX[hex(bytes)] = name;

      // The byte-indexed table name_of uses - see the note there.
      if (BY_FIRST[bytes[0]] === undefined) {
        BY_FIRST[bytes[0]] = {};
      }
      if (BY_FIRST[bytes[0]][bytes.length] === undefined) {
        BY_FIRST[bytes[0]][bytes.length] = [];
      }
      BY_FIRST[bytes[0]][bytes.length].push({ bytes: bytes, name: name });
    }
  }
}());


// Returns the known name for an encoding, or null. Callers should treat null
// as "not a name I know" and keep the bytes - an unknown OID is not
// automatically an error, and in X.509 extensions it very often is not.
// ⚠ MEASURED, THEN CHANGED.
//
// This was `BY_HEX[hex(bytes)]`, which is a hash lookup and looks free - but
// hex() BUILDS A STRING on every call, and a rich certificate looks up about
// forty identifiers. At 116ns for the string and 172ns for the whole lookup,
// that was 8 microseconds of a 46-microsecond parse: a sixth of the work,
// spent producing strings that are thrown away immediately.
//
// The fix is a two-level table keyed on the FIRST BYTE and then the length,
// which narrows to a handful of candidates before comparing any bytes at
// all. Nothing is allocated.
//
// The hex table stays for describe(), which needs the string anyway.
function name_of(bytes) {
  if (bytes.length === 0) {
    return null;
  }

  var bucket = BY_FIRST[bytes[0]];

  if (bucket === undefined) {
    return null;
  }

  var candidates = bucket[bytes.length];

  if (candidates === undefined) {
    return null;
  }

  var i, j;

  for (i = 0; i < candidates.length; i++) {
    var encoded = candidates[i].bytes;
    var same = true;

    // Start at 1: the first byte is what selected the bucket.
    for (j = 1; j < bytes.length; j++) {
      if (bytes[j] !== encoded[j]) {
        same = false;
        break;
      }
    }

    if (same) {
      return candidates[i].name;
    }
  }

  return null;
}

// Returns the encoding for a known name. Throws rather than returning null,
// because a caller asking by name has a literal in their source and a typo
// there should not silently become a comparison that never matches.
// ⚠ TWO SPELLINGS FOR THE RSA SIGNATURE ALGORITHMS, AND BOTH ARE IN USE.
//
// This table names SHA-2 RSA as `sha256WithRSA` and SHA-1 as
// `sha1WithRSAEncryption` - the second from Gutmann's list, added later. So
// a caller who wrote what x509.js reported for one certificate could not
// pass the same style for another: x509_build refused
// `sha256WithRSAEncryption`, and saml.js mapped rsa-sha1 to `sha1WithRSA`,
// which nothing here knew. name_of keeps returning one canonical name per
// OID; by_name now accepts either spelling. The same holds for the two
// attribute names below.
var ALIASES = {
  md2WithRSA:              'md2WithRSAEncryption',
  md5WithRSA:              'md5WithRSAEncryption',
  sha1WithRSA:             'sha1WithRSAEncryption',
  sha224WithRSAEncryption: 'sha224WithRSA',
  sha256WithRSAEncryption: 'sha256WithRSA',
  sha384WithRSAEncryption: 'sha384WithRSA',
  sha512WithRSAEncryption: 'sha512WithRSA',
  // The X.520 / RFC 5280 spellings of the two attributes the note at
  // stateOrProvince explains: accepted, while name_of keeps this library's.
  // ocspSigning was the builder's spelling; RFC 5280 writes id-kp-OCSPSigning.
  eku_ocspSigning:         'eku_OCSPSigning',
  stateOrProvinceName:     'stateOrProvince',
  organizationalUnitName:  'organizationalUnit'
};

function canonical_name(name) {
  return Object.prototype.hasOwnProperty.call(ALIASES, name)
    ? ALIASES[name] : name;
}

function by_name(name) {
  var n = canonical_name(name);
  if (!Object.prototype.hasOwnProperty.call(BY_NAME, n)) {
    fail('unknown-oid-name', 'no known OID named "' + name + '"');
  }
  return BY_NAME[n];
}

// For error messages: the name if there is one, the dotted form otherwise.
function describe(bytes) {
  var n = name_of(bytes);
  if (n !== null) {
    return n;
  }
  try {
    return to_string(bytes);
  } catch (e) {
    return '<malformed OID ' + hex(bytes) + '>';
  }
}

// Convenience for building: writes a known OID as a complete TLV.
function encode(name) {
  return W.oid(by_name(name));
}

// ---------------------------------------------------------------------------
// Digest sizes
// ---------------------------------------------------------------------------

// ⚠ ONE TABLE. pkcs12.js and tsp.js each carried an identical copy of this,
// found by a structural similarity sweep rather than by jscpd - the two were
// byte-identical, but jscpd's default threshold is longer than the function.
//
// It lives beside the OID table because that is where a name like 'sha256'
// comes from in the first place: every caller of this got the name by looking
// up an algorithm identifier.
//
// Safe to share - it is a lookup, and a mistake makes every module read the
// same wrong size, which shows up against the first real file.
// Reverse lookup in a table of dotted strings: given an encoded OID, the key
// whose value matches. cms.js and pkcs12.js each had an identical copy.
//
// Distinct from name_of, which searches this module's own registry - this
// searches a table the CALLER holds, because CMS content types and PKCS#12
// bag types are namespaces of their own.
function name_in_table(bytes, table) {
  var dotted = to_string(bytes);
  var k;

  for (k in table) {
    if (Object.prototype.hasOwnProperty.call(table, k) &&
        table[k] === dotted) {
      return k;
    }
  }

  return null;
}

function digest_size(name) {
  if (name === 'sha1')   { return 20; }
  if (name === 'sha224') { return 28; }
  if (name === 'sha256') { return 32; }
  if (name === 'sha384') { return 48; }
  if (name === 'sha512') { return 64; }
  if (name === 'sha3_224') { return 28; }
  if (name === 'sha3_256') { return 32; }
  if (name === 'sha3_384') { return 48; }
  if (name === 'sha3_512') { return 64; }
  // RFC 8702 3: in CMS, SHAKE128 gives 256 bits and SHAKE256 512.
  if (name === 'shake128') { return 32; }
  if (name === 'shake256') { return 64; }
  return null;
}

// The size, or a refusal in the CALLER's family - pkcs12.js and tsp.js each
// carried this wrapper, word for word.
function checked_digest_size(name, fail) {
  var size = digest_size(name);

  if (size === null) {
    fail('unsupported-digest', 'unrecognised digest ' + name);
  }
  return size;
}

export {
  canonical_name,
  digest_size,
  checked_digest_size,
  name_in_table,
  to_string,
  from_string,
  equal,
  name_of,
  by_name,
  describe,
  encode,
  DOTTED
};
