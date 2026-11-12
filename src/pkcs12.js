// PKCS#12, RFC 7292. The container keys travel in.
//
// ⚠ THE STRUCTURE IS NESTED INSIDE THE ENCRYPTION, NOT WRAPPED AROUND IT.
//
// This is the format DECISIONS 0.1 was argued over. Reading one goes:
//
//   PFX
//     └ authSafe: an OCTET STRING holding
//         └ AuthenticatedSafe: a SEQUENCE OF ContentInfo, each of which is
//             ├ data           an OCTET STRING holding SafeContents
//             └ encryptedData  ciphertext holding SafeContents
//                 └ SafeContents: a SEQUENCE OF SafeBag, each of which may be
//                     └ pkcs8ShroudedKeyBag: MORE ciphertext, holding PKCS#8
//
// Three or four rounds of parse-decrypt-parse. The version of this library
// that performed the decryption would need a state machine, and a state
// machine has rounds - which is the brief's own test for what belongs to a
// protocol library rather than a format one.
//
// So every function here is bytes in, values out, and the NESTING BELONGS TO
// THE CALLER'S LOOP where they can see it. pkcs12_read at the bottom is a
// convenience written entirely against the public API, taking the primitives
// as arguments; it has no privileges the caller does not.
//
// ⚠ ENCODING: MEASURED, NOT ASSUMED.
//
// DECISIONS 2.1 justified the BER reader with "real .p12 files are
// frequently BER". Current OpenSSL writes DEFINITE-length DER, and the
// strict reader opens those files end to end - verified.
//
// ⚠ AND THE CLAIM ABOUT JAVA WAS WRONG, WHICH THE SAME NOTE INVITED.
//
// This comment used to say "Windows CryptoAPI, Java keytool and older
// OpenSSL do write BER" - stated while asserting that the encoding had been
// MEASURED. It had been measured for OpenSSL and assumed for the other two.
//
// keytool from OpenJDK 21 writes DEFINITE-LENGTH DER, and the fixture set
// now contains one to prove it. What remains true is that OLDER producers
// wrote BER, and the fallback is why a file from one still opens.
//
// The lesson is not about PKCS#12: a note that says "measured" beside a
// claim that was not is worse than no note, because it stops the next
// person checking.
//
// So this module tries DER FIRST and falls back to BER, and REPORTS WHICH -
// `encoding: 'der'` or `encoding: 'ber'` in the output. A file that needed
// the fallback used encodings a strict parser refuses, and the caller should
// know rather than have the difference normalised away.

import * as DER from './der_reader.js';
import * as BER from './ber_reader.js';
import * as OID from './oid.js';
import { CIPHERS as PBES2_CIPHERS, PRFS as PBES2_PRFS,
         read_pbkdf2 } from './pbes2.js';
import * as F from './fields.js';
import { check_iterations } from './commons/limits.js';
import { make_fail_here } from './commons/fail.js';
import { to_bytes, int_value, hex , bytes_equal } from './commons/bytes.js';

var fail = make_fail_here('pkcs12');

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

var CONTENT = {
  data:          '1.2.840.113549.1.7.1',
  signedData:    '1.2.840.113549.1.7.2',
  envelopedData: '1.2.840.113549.1.7.3',
  encryptedData: '1.2.840.113549.1.7.6'
};

var BAG = {
  keyBag:              '1.2.840.113549.1.12.10.1.1',
  pkcs8ShroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
  certBag:             '1.2.840.113549.1.12.10.1.3',
  crlBag:              '1.2.840.113549.1.12.10.1.4',
  secretBag:           '1.2.840.113549.1.12.10.1.5',
  safeContentsBag:     '1.2.840.113549.1.12.10.1.6'
};

var CERT_TYPE = {
  x509Certificate: '1.2.840.113549.1.9.22.1',
  sdsiCertificate: '1.2.840.113549.1.9.22.2'
};

var ATTRIBUTE = {
  friendlyName: '1.2.840.113549.1.9.20',
  localKeyId:   '1.2.840.113549.1.9.21'
};

// The PKCS#12 key derivation, RFC 7292 appendix B. NOT PBKDF2: it is its own
// construction with an ID byte that differs per purpose, and a caller who
// reaches for PBKDF2 derives the wrong key and sees a failure that looks
// like a wrong password.
var PBE = {
  // The cipher by its OID-table name, as everywhere in this library;
  // algorithm.node_name(cipher, key_length) gives 'des-ede3-cbc' and
  // 'rc2-40-cbc' - RC2's node name carries the key length.
  '1.2.840.113549.1.12.1.3': { name: 'pbeWithSHAAnd3KeyTripleDES-CBC',
                               kdf: 'pkcs12', cipher: 'des_ede3_cbc',
                               key: 24, iv: 8 },
  '1.2.840.113549.1.12.1.6': { name: 'pbeWithSHAAnd40BitRC2-CBC',
                               kdf: 'pkcs12', cipher: 'rc2CBC',
                               key: 5, iv: 8 },
  '1.2.840.113549.1.5.13':   { name: 'PBES2', kdf: 'pbes2' }
};

// The three purposes the PKCS#12 KDF distinguishes by its ID byte. Passing
// the wrong one produces a valid-looking key that decrypts to noise.
var KDF_ID = { key: 1, iv: 2, mac: 3 };

function oid_string(bytes) {
  return OID.to_string(bytes);
}


// ---------------------------------------------------------------------------
// The outer container
// ---------------------------------------------------------------------------

// Reads the PFX and returns what is needed to verify the MAC and to walk the
// safes. Decrypts nothing.
//
// `options.max_iterations` raises the ceiling every KDF here is checked
// against - see commons/limits.js. A container names its own iteration
// counts, and the caller is the one who runs them.
function from_der(input, options) {
  var bytes = to_bytes(input);
  var encoding = 'der';
  var parsed;

  try {
    parsed = read_pfx(DER, bytes, options);
  } catch (e) {
    // The fallback is not silent. A file that needs it used encodings a
    // strict parser refuses, and `encoding: 'ber'` in the result is how the
    // caller finds out.
    try {
      parsed = read_pfx(BER, bytes, options);
      encoding = 'ber';
    } catch (e2) {
      // Report the STRICT error, not the lenient one: if both fail, the
      // strict message is the more precise description of what is wrong.
      throw e;
    }
  }

  parsed.encoding = encoding;
  parsed.der = bytes;

  if (parsed.mac !== null) {
    check_iterations(parsed.mac.iterations, options, fail,
      'the MAC iteration count');
  }

  var i;
  for (i = 0; i < parsed.safes.length; i++) {
    if (parsed.safes[i].encrypted !== undefined) {
      check_iterations(parsed.safes[i].encrypted.iterations, options, fail,
        'the iteration count of safe ' + i);
    }
  }

  return parsed;
}

function read_pfx(R, bytes, options) {
  return R.read(bytes, function (r) {
    var pfx = r.read_sequence();
    var version = int_value(pfx.read_unsigned(), 'PFX version');

    // RFC 7292 fixes it at 3. Anything else is a structure this parser has
    // not been written against.
    if (version !== 3) {
      fail('bad-version', 'a PFX is version 3, got ' + version);
    }

    var auth_safe = read_content_info(R, pfx);

    if (auth_safe.type !== 'data') {
      fail('unsupported-authsafe',
        'the authSafe is ' + auth_safe.type + '; only data is supported');
    }

    var out = {
      version:  version,
      // The bytes the MAC covers. NOT the whole PFX and not the ContentInfo -
      // just the content OCTET STRING's value. Hashing anything else gives a
      // MAC that never matches, and the failure looks like a wrong password.
      mac_data: auth_safe.content,
      safes:    read_authenticated_safe(R, auth_safe.content),
      mac:      null
    };

    if (pfx.remaining() > 0) {
      out.mac = read_mac_data(R, pfx, options);
    }

    pfx.expect_end();
    return out;
  });
}

//   ContentInfo ::= SEQUENCE {
//        contentType  OID,
//        content  [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
function read_content_info(R, r) {
  var ci = r.read_sequence();
  var type_oid = ci.read_oid();
  var type = OID.name_in_table(type_oid, CONTENT);

  if (type === null) {
    fail('unknown-content-type',
      'unrecognised content type ' + oid_string(type_oid));
  }

  var out = { type: type };

  if (ci.remaining() > 0) {
    var wrapper = ci.read_explicit(0);

    if (type === 'data') {
      out.content = wrapper.read_octet_string();
    } else if (type === 'encryptedData') {
      out.encrypted = read_encrypted_data(R, wrapper);
    } else {
      fail('unsupported-content-type',
        type + ' content is not read by this module');
    }

    wrapper.expect_end();
  }

  ci.expect_end();
  return out;
}

//   EncryptedData ::= SEQUENCE {
//        version                  INTEGER,
//        encryptedContentInfo     EncryptedContentInfo }
function read_encrypted_data(R, r) {
  var ed = r.read_sequence();
  var ed_version = int_value(ed.read_unsigned(), 'EncryptedData version');

  // Read and then discarded, so any version was accepted. RFC 5652 8:
  // version 0 when there are no unprotected attributes, and RFC 7292 never
  // has any.
  if (ed_version !== 0) {
    fail('bad-version', 'EncryptedData in a PFX is version 0, got ' +
      ed_version);
  }

  var eci = ed.read_sequence();
  var type_oid = eci.read_oid();

  if (OID.name_in_table(type_oid, CONTENT) !== 'data') {
    fail('unsupported-content-type',
      'encrypted content is ' + oid_string(type_oid) + ', expected data');
  }

  var alg = read_pbe_algorithm(R, eci);

  // [0] IMPLICIT: the ciphertext, with the OCTET STRING's tag replaced.
  var got = eci.read_implicit(0, 0x04);
  alg.data = got.bytes;

  eci.expect_end();
  ed.expect_end();
  return alg;
}

// Reads whichever password-based scheme the container uses, and reports the
// parameters the caller needs. Two families appear:
//
//   PBES2                 PBKDF2 plus a modern cipher, RFC 8018
//   pbeWithSHAAnd*        the PKCS#12 KDF, RFC 7292 appendix B
//
// The second is why this is not simply pbes2.js: the derivation is a
// different construction, with an ID byte that differs for the key, the IV
// and the MAC.
function read_pbe_algorithm(R, r) {
  var alg = r.read_sequence();
  var alg_oid = alg.read_oid();
  var dotted = oid_string(alg_oid);
  var scheme = PBE[dotted];

  if (scheme === undefined) {
    fail('unsupported-scheme',
      'unrecognised encryption scheme ' + dotted);
  }

  if (scheme.kdf === 'pbes2') {
    // Delegated in shape but not in code: the parameters are read here so
    // that the result has one form whichever scheme the file used.
    var p2 = alg.read_sequence();
    var kdf = p2.read_sequence();
    var kdf_oid = kdf.read_oid();

    if (oid_string(kdf_oid) !== '1.2.840.113549.1.5.12') {
      fail('unsupported-kdf',
        'PBES2 with ' + oid_string(kdf_oid) + ' rather than PBKDF2');
    }

    var kp = kdf.read_sequence();
    var salt = kp.read_octet_string();
    var iterations = int_value(kp.read_unsigned(), 'iterations');
    var key_length = null;
    var prf = 'hmacWithSHA1';

    if (kp.remaining() > 0 && kp.peek_tag() === 0x02) {
      key_length = int_value(kp.read_unsigned(), 'keyLength');
    }

    // ⚠ THE PRF TABLE IS pbes2.js's, NOT A COPY.
    //
    // This module had its own: SHA-256 recognised, and ANYTHING ELSE read as
    // SHA-1. A file written with hmacWithSHA512 derived the wrong key, and
    // the failure said "bad MAC" or produced garbage - which reads as a
    // wrong password. An unknown PRF is now refused by name.
    if (kp.remaining() > 0) {
      var prf_alg = kp.read_sequence();
      var prf_name = OID.name_of(prf_alg.read_oid());

      if (prf_alg.remaining() > 0) {
        prf_alg.read_null();
      }
      prf_alg.expect_end();

      if (prf_name === null || PBES2_PRFS[prf_name] === undefined) {
        fail('unsupported-prf', 'unrecognised PBKDF2 PRF');
      }
      prf = prf_name;
    }
    kp.expect_end();
    kdf.expect_end();

    var enc = p2.read_sequence();
    var cipher_oid = OID.name_of(enc.read_oid());
    var iv = enc.read_octet_string();
    enc.expect_end();
    p2.expect_end();
    alg.expect_end();

    var cipher = cipher_oid === null ? undefined : PBES2_CIPHERS[cipher_oid];

    if (cipher === undefined) {
      fail('unsupported-cipher', 'unrecognised cipher ' + cipher_oid);
    }
    if (iv.length !== cipher.iv) {
      fail('bad-iv-length',
        cipher_oid + ' takes a ' + cipher.iv + '-byte IV, got ' + iv.length);
    }

    // keyLength was read and thrown away, so a file asking for 16 bytes of
    // key for AES-256 was accepted and decrypted with 32.
    if (key_length !== null && key_length !== cipher.key) {
      fail('key-length-mismatch',
        'the KDF asks for ' + key_length + ' bytes but ' + cipher_oid +
        ' takes ' + cipher.key);
    }

    return {
      kdf: 'pbkdf2', prf: prf, salt: salt, iterations: iterations,
      key_length: cipher.key, cipher: cipher_oid, iv: iv,
      data: null
    };
  }

  //   pkcs-12PbeParams ::= SEQUENCE {
  //        salt        OCTET STRING,
  //        iterations  INTEGER }
  var params = alg.read_sequence();
  var pbe_salt = params.read_octet_string();
  var pbe_iterations = int_value(params.read_unsigned(), 'iterations');
  params.expect_end();
  alg.expect_end();

  return {
    kdf: 'pkcs12',
    kdf_note:
      'RFC 7292 appendix B, NOT PBKDF2. The derivation takes an ID byte - ' +
      '1 for the key, 2 for the IV, 3 for the MAC - and a library for ' +
      'PBKDF2 will derive the wrong key.',
    hash: 'sha1',
    salt: pbe_salt,
    iterations: pbe_iterations,
    key_length: scheme.key,
    iv_length: scheme.iv,
    cipher: scheme.cipher,
    scheme: scheme.name,
    id: KDF_ID,
    data: null
  };
}

//   MacData ::= SEQUENCE {
//        mac         DigestInfo,
//        macSalt     OCTET STRING,
//        iterations  INTEGER DEFAULT 1 }
//
// ⚠ THE MAC IS THE ONLY INTEGRITY CHECK A PKCS#12 HAS. A container whose MAC
// is not verified is one whose certificates an attacker may have replaced -
// and since the certificates are usually NOT encrypted, that is the realistic
// attack rather than a theoretical one.
//
// Two schemes, told apart by the DigestInfo's algorithm:
//
//   'pkcs12-kdf'   RFC 7292: the algorithm is a hash, the key comes from
//                  the PKCS#12 KDF (ID 3) over macSalt and iterations
//   'pbmac1'       RFC 9579: the algorithm is id-PBMAC1, whose parameters
//                  carry a PBKDF2 and an HMAC. macSalt and iterations are
//                  IGNORED (RFC 9579 4 c, d) - the PBKDF2 parameters are
//                  the ones that count, and they are what `salt` and
//                  `iterations` report here, so a caller never runs the
//                  KDF over the decoy values.
function read_mac_data(R, r, options) {
  var md = r.read_sequence();
  var digest_info = md.read_sequence();
  var alg = digest_info.read_sequence();
  var hash_oid = alg.read_oid();
  var hash = OID.name_of(hash_oid);
  var pbmac1 = null;

  if (hash === 'pbmac1') {
    if (alg.remaining() === 0) {
      fail('missing-parameters', 'id-PBMAC1 requires PBMAC1-params, ' +
        'RFC 9579 4 a');
    }
    pbmac1 = read_pbmac1_params(alg.capture(), options);
  } else if (alg.remaining() > 0) {
    alg.read_null();
  }
  alg.expect_end();

  var digest = digest_info.read_octet_string();
  digest_info.expect_end();

  var salt = md.read_octet_string();
  var iterations = 1;

  // DEFAULT 1: DER omits a value equal to its default, so an absent field
  // means one iteration rather than none.
  if (md.remaining() > 0) {
    iterations = int_value(md.read_unsigned(), 'MAC iterations');

    // Written out, it is not DER - and the strict pass refuses so that the
    // BER fallback reads it and says `encoding: 'ber'`. RFC 9579's own test
    // vectors are written this way.
    if (iterations === 1 && R === DER) {
      fail('non-der-default', 'MacData iterations 1 is the DEFAULT, and DER ' +
        'omits it');
    }
  }
  md.expect_end();

  if (pbmac1 !== null) {
    if (digest.length !== pbmac1.size) {
      fail('bad-digest-length', 'HMAC-' + pbmac1.hash + ' produces ' +
        pbmac1.size + ' bytes, and the MAC is ' + digest.length);
    }
    return {
      scheme:     'pbmac1',
      hash:       pbmac1.hash,
      digest:     digest,
      kdf:        'pbkdf2',
      prf:        pbmac1.prf,
      salt:       pbmac1.salt,
      iterations: pbmac1.iterations,
      key_length: pbmac1.key_length,
      weak:       pbmac1.weak,
      id:         null
    };
  }

  return {
    scheme:     'pkcs12-kdf',
    hash:       hash === null ? oid_string(hash_oid) : hash,
    digest:     digest,
    salt:       salt,
    iterations: iterations,
    // The caller derives a MAC key with ID byte 3 and HMACs mac_data. Saying
    // which ID is the useful part: 1 and 2 produce a key that is valid and
    // wrong.
    id:         KDF_ID.mac
  };
}

//   PBMAC1-params ::= SEQUENCE {
//      keyDerivationFunc  AlgorithmIdentifier {{PBMAC1-KDFs}},
//      messageAuthScheme  AlgorithmIdentifier {{PBMAC1-MACs}} }
//
// ⚠ keyLength IS REQUIRED HERE AND OPTIONAL EVERYWHERE ELSE. RFC 9579 5:
// "Implementations MUST NOT accept PBKDF2 KDF with PBKDF2-params that omit
// the keyLength field" - in PBES2 the cipher implies the length, and an
// HMAC key has no such anchor. RFC 9579 appendix A.6 is a file built to
// test exactly this.
function read_pbmac1_params(bytes, options) {
  var p = DER.read(bytes, function (r) {
    var seq = r.read_sequence();
    var kdf = F.read_type(seq, 'AlgorithmIdentifier');
    var mac = F.read_type(seq, 'AlgorithmIdentifier');
    seq.expect_end();
    return { kdf: kdf, mac: mac };
  });

  if (OID.name_of(p.kdf.algorithm) !== 'pbkdf2') {
    fail('unsupported-kdf', 'PBMAC1 with ' + OID.describe(p.kdf.algorithm) +
      ' rather than PBKDF2');
  }

  var kdf = read_pbkdf2(p.kdf, options);

  if (kdf.key_length === null) {
    fail('missing-key-length',
      'PBMAC1 must state the PBKDF2 keyLength, RFC 9579 5 - a file without ' +
      'it MUST NOT be accepted');
  }
  // RFC 9579 9: "it is RECOMMENDED to reject" keys shorter than 20 octets.
  if (kdf.key_length < 20) {
    fail('weak-key-length', 'a PBMAC1 key of ' + kdf.key_length +
      ' bytes; RFC 9579 9 recommends refusing anything under 20');
  }

  var mac_name = OID.name_of(p.mac.algorithm);
  var mac = mac_name === null ? undefined : PBES2_PRFS[mac_name];

  if (mac === undefined) {
    fail('unsupported-mac', 'PBMAC1 with ' + OID.describe(p.mac.algorithm) +
      ' as its MAC');
  }

  return {
    hash:       mac.hash,
    size:       mac.size,
    prf:        kdf.prf,
    salt:       kdf.salt,
    iterations: kdf.iterations,
    key_length: kdf.key_length,
    weak:       kdf.weak || mac_name === 'hmacWithSHA1'
  };
}

// ---------------------------------------------------------------------------
// The safes
// ---------------------------------------------------------------------------

function read_authenticated_safe(R, content) {
  return R.read(content, function (r) {
    var seq = r.read_sequence();
    var out = [];

    while (seq.remaining() > 0) {
      out.push(read_content_info(R, seq));
    }

    seq.expect_end();
    return out;
  });
}

// Reads a SafeContents - the plaintext of one safe. For an unencrypted safe
// that is `content` straight from the container; for an encrypted one it is
// what the caller got back from decrypting.
function bags_from_der(input, encoding) {
  var R = encoding === 'ber' ? BER : DER;

  return R.read(to_bytes(input), function (r) {
    var seq = r.read_sequence();
    var out = [];

    while (seq.remaining() > 0) {
      out.push(read_bag(R, seq));
    }

    seq.expect_end();
    return out;
  });
}

//   SafeBag ::= SEQUENCE {
//        bagId          OID,
//        bagValue  [0]  EXPLICIT ANY DEFINED BY bagId,
//        bagAttributes  SET OF PKCS12Attribute OPTIONAL }
function read_bag(R, r) {
  var bag = r.read_sequence();
  var id_oid = bag.read_oid();
  var kind = OID.name_in_table(id_oid, BAG);

  var wrapper = bag.read_explicit(0);
  var out = { kind: kind === null ? oid_string(id_oid) : kind };

  if (kind === 'keyBag') {
    // An unencrypted PKCS#8 PrivateKeyInfo. Returned as bytes for pkcs8.js
    // to parse, rather than parsed here - one PKCS#8 reader, not two.
    out.key = wrapper.capture();

  } else if (kind === 'pkcs8ShroudedKeyBag') {
    // An EncryptedPrivateKeyInfo: MORE ciphertext, one layer further in.
    // The caller decrypts it and hands the result to pkcs8.from_der.
    out.encrypted = wrapper.capture();

  } else if (kind === 'certBag') {
    var cb = wrapper.read_sequence();
    var cert_oid = cb.read_oid();
    var cert_type = OID.name_in_table(cert_oid, CERT_TYPE);

    if (cert_type !== 'x509Certificate') {
      fail('unsupported-cert-type',
        'certificate type ' + oid_string(cert_oid) + ' is not supported');
    }

    var cw = cb.read_explicit(0);
    out.certificate = cw.read_octet_string();
    cw.expect_end();
    cb.expect_end();

  } else {
    // crlBag, secretBag, safeContentsBag and anything unrecognised are kept
    // whole rather than guessed at.
    out.value = wrapper.capture();
  }

  wrapper.expect_end();

  out.friendly_name = null;
  out.local_key_id = null;

  if (bag.remaining() > 0) {
    read_attributes(R, bag, out);
  }

  bag.expect_end();
  return out;
}

function read_attributes(R, bag, out) {
  var set = bag.read_set_of();

  while (set.remaining() > 0) {
    var attr = set.read_sequence();
    var attr_oid = attr.read_oid();
    var name = OID.name_in_table(attr_oid, ATTRIBUTE);
    var values = attr.read_set_of();

    if (name === 'friendlyName') {
      // ⚠ BMPString: UTF-16 BIG ENDIAN. Reading it as UTF-8 gives a string
      // full of null bytes that looks like corruption rather than a wrong
      // decoder, which is why the DER layer has a reader for it.
      out.friendly_name = values.read_bmp_string();
    } else if (name === 'localKeyId') {
      // Ties a key bag to its certificate bag. Without it a container with
      // several keys cannot be sorted out.
      out.local_key_id = hex(values.read_octet_string());
    } else {
      values.capture();
    }

    values.expect_end();
    attr.expect_end();
  }

  set.expect_end();
}

// ---------------------------------------------------------------------------
// The convenience
// ---------------------------------------------------------------------------

// Opens the whole container in one call: verifies the MAC and decrypts every
// safe and key, taking the primitives as arguments. Named `open` rather than
// `read` because elsewhere here `read` is the level-0 cursor (der.read), and
// this does something else entirely.
//
// This function has NO PRIVILEGES the caller does not: it is written entirely
// against the exports above, and a caller who wants the loop visible can
// write it themselves in about twenty lines. It exists because those twenty
// lines are the same every time, not because the library needs to hold them.
//
// The primitives it needs:
//
//   pkcs12_kdf(hash, password, salt, iterations, id, length)
//                             RFC 7292 appendix B. NOT PBKDF2.
//   pbkdf2(prf, password, salt, iterations, length)
//                             PBES2 keys and safes, and a PBMAC1 MAC key
//   decrypt(cipher, key, iv, data)
//   hmac(hash, key, data)
//
// ⚠ verify_mac defaults to TRUE and turning it off is a decision. The MAC is
// the only integrity check a PKCS#12 has, and the certificates inside are
// usually not encrypted - so an unverified container is one whose
// certificates may have been replaced.
function open(input, password, primitives, options) {
  var opts = options || {};
  var pfx = from_der(input, opts);

  if (!primitives || typeof primitives.decrypt !== 'function') {
    fail('missing-primitives',
      'this library performs no cryptography - pass { pkcs12_kdf, pbkdf2, ' +
      'decrypt, hmac } from cryptographic-primitives');
  }

  var mac_verified = null;

  if (pfx.mac !== null && opts.verify_mac !== false) {
    var kdf_name = pfx.mac.scheme === 'pbmac1' ? 'pbkdf2' : 'pkcs12_kdf';

    if (typeof primitives.hmac !== 'function' ||
        typeof primitives[kdf_name] !== 'function') {
      fail('missing-primitives',
        'verifying the MAC needs ' + kdf_name + ' and hmac; pass ' +
        '{ verify_mac: false } only if you have decided to trust the file ' +
        'without its only integrity check');
    }

    // PBMAC1 derives with PBKDF2, the password passed as for PBES2 - which
    // RFC 9579's own test vectors show to be the UTF-8 bytes, whatever its
    // section 6 says about BMPStrings.
    var mac_key = pfx.mac.scheme === 'pbmac1'
      ? primitives.pbkdf2(pfx.mac.prf, password, pfx.mac.salt,
          pfx.mac.iterations, pfx.mac.key_length)
      : primitives.pkcs12_kdf(pfx.mac.hash, password, pfx.mac.salt,
          pfx.mac.iterations, pfx.mac.id,
          OID.checked_digest_size(pfx.mac.hash, fail));

    var computed = to_bytes(
      primitives.hmac(pfx.mac.hash, mac_key, pfx.mac_data));

    mac_verified = bytes_equal(computed, pfx.mac.digest);

    if (!mac_verified) {
      fail('bad-mac',
        'the MAC does not match: the password is wrong, or the container ' +
        'has been altered. Its certificates are usually not encrypted, so ' +
        'this is not a theoretical distinction.');
    }
  }

  var bags = [];
  var i;

  for (i = 0; i < pfx.safes.length; i++) {
    var safe = pfx.safes[i];

    if (safe.type === 'data') {
      bags = bags.concat(bags_from_der(safe.content, pfx.encoding));
      continue;
    }

    var plain = decrypt_safe(safe.encrypted, password, primitives);
    bags = bags.concat(bags_from_der(plain, pfx.encoding));
  }

  // Shrouded key bags are one layer further in.
  for (i = 0; i < bags.length; i++) {
    if (bags[i].encrypted !== undefined) {
      bags[i].key = unwrap_shrouded(bags[i].encrypted, password, primitives,
        pfx.encoding, opts);
    }
  }

  return {
    encoding:     pfx.encoding,
    mac_verified: mac_verified,
    bags:         bags,
    keys:         bags.filter(function (b) { return b.key !== undefined; }),
    certificates: bags.filter(function (b) {
      return b.certificate !== undefined;
    })
  };
}

function decrypt_safe(enc, password, primitives) {
  var key;

  if (enc.kdf === 'pkcs12') {
    key = primitives.pkcs12_kdf(enc.hash, password, enc.salt, enc.iterations,
      enc.id.key, enc.key_length);
    var iv = primitives.pkcs12_kdf(enc.hash, password, enc.salt,
      enc.iterations, enc.id.iv, enc.iv_length);
    return to_bytes(primitives.decrypt(enc.cipher, key, iv, enc.data));
  }

  key = primitives.pbkdf2(enc.prf, password, enc.salt, enc.iterations,
    enc.key_length);
  return to_bytes(primitives.decrypt(enc.cipher, key, enc.iv, enc.data));
}

function unwrap_shrouded(encrypted, password, primitives, encoding, options) {
  var R = encoding === 'ber' ? BER : DER;

  var enc = R.read(encrypted, function (r) {
    var epki = r.read_sequence();
    var alg = read_pbe_algorithm(R, epki);
    alg.data = epki.read_octet_string();
    epki.expect_end();
    return alg;
  });

  // A shrouded key names its own count, separately from the safe it sits
  // in, so it is checked separately.
  check_iterations(enc.iterations, options, fail,
    'the iteration count of a shrouded key');

  return decrypt_safe(enc, password, primitives);
}




export {
  from_der,
  bags_from_der,
  open,
  BAG,
  CONTENT,
  KDF_ID
};
