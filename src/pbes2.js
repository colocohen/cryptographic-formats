// PBES2, RFC 8018 (PKCS #5 v2.1), and the EncryptedPrivateKeyInfo container
// of RFC 5958.
//
// THIS IS THE CASE THE DEPENDENCY DECISION WAS DESIGNED AROUND.
//
// The format contains a cryptographic operation: the key material is
// encrypted, and reading it means deriving a key from a password and
// decrypting. The library does neither. It reports exactly what operation is
// called for, with all its parameters, and hands over the ciphertext:
//
//   var enc   = pkcs8.encrypted_from_der(der);
//   var dk    = flex.pbkdf2(enc.prf, password, enc.salt, enc.iterations,
//                           enc.key_length);
//   var plain = flex.decrypt(enc.cipher, dk, enc.iv, enc.data);
//   var key   = pkcs8.from_der(plain);
//
// The EncryptedPrivateKeyInfo itself is read and written by pkcs8.js
// (encrypted_from_der / encrypted_to_der), beside the plain key - that is
// where somebody holding an encrypted key looks. This module holds the
// PBES2 parts both it and PKCS#12 and CMS use.
//
// Every function here is bytes in, values out. There is no state machine, no
// configure(), and no injected primitives - the nesting belongs to the
// caller's code, where they can see it.
//
// The structures, RFC 8018 appendix A:
//
//   EncryptedPrivateKeyInfo ::= SEQUENCE {
//       encryptionAlgorithm  AlgorithmIdentifier,
//       encryptedData        OCTET STRING }
//
//   PBES2-params ::= SEQUENCE {
//       keyDerivationFunc    AlgorithmIdentifier,
//       encryptionScheme     AlgorithmIdentifier }
//
//   PBKDF2-params ::= SEQUENCE {
//       salt                 OCTET STRING,
//       iterationCount       INTEGER,
//       keyLength            INTEGER OPTIONAL,
//       prf                  AlgorithmIdentifier DEFAULT hmacWithSHA1 }

import * as DER from './der_reader.js';
import * as W from './der_writer.js';
import * as F from './fields.js';

// Imported for its side effect: pkix.js defines AlgorithmIdentifier,
// RDNSequence, Extension and the other structures PKIX shares.
import './pkix.js';
import * as OID from './oid.js';

import { int_value, int_bytes, to_bytes } from './commons/bytes.js';
import { make_fail_here } from './commons/fail.js';
import { check_iterations } from './commons/limits.js';
import { canonical_name } from './algorithm.js';

var fail = make_fail_here('pbes2');


// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------


F.define('EncryptedPrivateKeyInfo', [
  { name: 'algorithm', type: 'AlgorithmIdentifier' },
  { name: 'data',      type: 'octet_string' }
]);

F.define('PBES2Params', [
  { name: 'kdf',    type: 'AlgorithmIdentifier' },
  { name: 'scheme', type: 'AlgorithmIdentifier' }
]);

F.define('PBKDF2Params', [
  // The salt is a CHOICE of OCTET STRING and an AlgorithmIdentifier for an
  // "other source". Only the specified form appears in practice, and the
  // other source is refused rather than guessed at - a salt from a source
  // this library cannot evaluate is a key it cannot read.
  { name: 'salt',       type: 'octet_string' },
  { name: 'iterations', type: 'unsigned' },
  { name: 'key_length', type: 'unsigned', optional: true },
  { name: 'prf',        type: 'AlgorithmIdentifier', optional: true }
]);

// ---------------------------------------------------------------------------
// Algorithm tables
// ---------------------------------------------------------------------------

// The cipher tells the caller three things they need: which algorithm, how
// long a key to derive, and how long an IV to expect. Getting the key length
// wrong produces a derived key that decrypts to noise, and the failure looks
// like a wrong password.
//
// Keyed by the OID-table name, which is what every result here reports;
// algorithm.node_name() gives the spelling node:crypto takes.
var CIPHERS = {
  aes128CBC:    { key: 16, iv: 16 },
  aes192CBC:    { key: 24, iv: 16 },
  aes256CBC:    { key: 32, iv: 16 },
  des_ede3_cbc: { key: 24, iv: 8 }
};

// ⚠ ECB, FOR PKCS#8 ONLY, AND MARKED WEAK (DECISIONS 43).
//
// OpenSSL writes an EncryptedPrivateKeyInfo with AES-ECB when asked to -
// `openssl pkcs8 -topk8 -v2 aes-256-ecb`, or node's
// export({ type: 'pkcs8', cipher: 'aes-256-ecb' }) - and reads it back. ECB
// has no IV and encrypts equal blocks equally, so the key's structure shows
// through; it is still the password that protects the key, and refusing to
// read a key somebody already has helps nobody. So: read, with `weak` set;
// written only with { allow_weak: true }.
//
// Kept out of CIPHERS on purpose. A CMS password recipient (RFC 3211) wraps
// with CBC by definition and PKCS#12 never carries ECB, so the two other
// readers of this module do not accept it - only pkcs8.js asks for it.
//
// The parameters: OpenSSL writes an EMPTY OCTET STRING (the IV it does not
// have), NIST's registration leaves them absent, and some writers put NULL.
// All three are the same statement - no IV - and are read; the empty OCTET
// STRING is what is written, so a key from here compares byte for byte with
// OpenSSL's.
var ECB_CIPHERS = {
  aes128ECB: { key: 16, iv: 0 },
  aes192ECB: { key: 24, iv: 0 },
  aes256ECB: { key: 32, iv: 0 }
};

// ⚠ ALL FIVE RFC 8018 B.1 NAMES. The table had SHA-1 and SHA-256, so a key
// written with `openssl pkcs8 -v2prf hmacWithSHA512` was refused here - and
// pkcs12.js, which kept its own smaller copy of this table, quietly read it
// as SHA-1 and derived the wrong key. One table now, exported, and used by
// both.
var PRFS = {
  hmacWithSHA1:   { hash: 'sha1',   size: 20 },
  hmacWithSHA224: { hash: 'sha224', size: 28 },
  hmacWithSHA256: { hash: 'sha256', size: 32 },
  hmacWithSHA384: { hash: 'sha384', size: 48 },
  hmacWithSHA512: { hash: 'sha512', size: 64 }
};

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------


function read_kdf(alg, options) {
  var name = OID.name_of(alg.algorithm);

  if (name !== 'pbkdf2') {
    fail('unsupported-kdf',
      'PBES2 with ' +
      (name === null ? OID.describe(alg.algorithm) : name) +
      ' rather than PBKDF2');
  }
  if (alg.parameters === undefined) {
    fail('missing-parameters', 'PBKDF2 requires parameters');
  }

  var p = DER.read(alg.parameters, function (r) {
    return F.read_type(r, 'PBKDF2Params');
  });

  // RFC 8018 4.2 requires at least 1000, and modern guidance is far higher.
  // A key stored with a handful of iterations is one whose password can be
  // tried at speed - reported below as `weak` rather than refused, because
  // the key already exists. Too MANY is refused: see commons/limits.js.
  var iterations = check_iterations(int_value(p.iterations, 'iterations'),
    options, fail, 'the PBKDF2 iteration count');

  var prf = 'hmacWithSHA1';

  if (p.prf !== undefined) {
    var prf_name = OID.name_of(p.prf.algorithm);
    if (prf_name === null || PRFS[prf_name] === undefined) {
      fail('unsupported-prf',
        'unrecognised PRF ' + OID.describe(p.prf.algorithm));
    }
    prf = prf_name;
  }

  return {
    salt:       p.salt,
    iterations: iterations,
    key_length: p.key_length === undefined ? null : int_value(p.key_length),
    prf:        prf,
    weak:       is_weak({ iterations: iterations, prf: prf })
  };
}

// `allow_ecb` is pkcs8.js's: see ECB_CIPHERS.
function read_scheme(alg, allow_ecb) {
  var name = OID.name_of(alg.algorithm);

  if (name !== null && ECB_CIPHERS[name] !== undefined) {
    if (allow_ecb !== true) {
      fail('unsupported-cipher', name + ' is read only in a PKCS#8 key; ' +
        'here it would be an ECB key wrap');
    }
    return read_ecb(name, alg.parameters);
  }

  if (name === null || CIPHERS[name] === undefined) {
    fail('unsupported-cipher',
      'unrecognised encryption scheme ' + OID.describe(alg.algorithm));
  }

  var c = CIPHERS[name];

  if (alg.parameters === undefined) {
    fail('missing-iv', name + ' requires an IV in its parameters');
  }

  var iv = DER.read(alg.parameters, function (r) {
    return r.read_octet_string();
  });

  if (iv.length !== c.iv) {
    fail('bad-iv-length',
      name + ' takes a ' + c.iv + '-byte IV, got ' + iv.length);
  }

  return {
    cipher:     name,
    key_length: c.key,
    iv:         iv,
    weak:       false
  };
}

function read_ecb(name, parameters) {
  if (parameters !== undefined) {
    var none = DER.read(parameters, function (r) {
      var tag = r.peek_tag();
      if (tag === 0x05) {
        r.read_null();
        return true;
      }
      return r.read_octet_string().length === 0;
    });
    if (!none) {
      fail('bad-iv-length', name + ' takes no IV, but its parameters carry one');
    }
  }
  return {
    cipher:     name,
    key_length: ECB_CIPHERS[name].key,
    iv:         null,
    weak:       true
  };
}

// Whether the parameters describe a key whose password can be attacked
// cheaply. Reported rather than refused, because refusing would make an old
// key unreadable - but a caller about to trust it should be able to ask.
function is_weak(p) {
  return p.iterations < 1000 || canonical_name(p.prf) === 'hmacWithSHA1';
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------


// The PBES2 AlgorithmIdentifier alone - what pkcs8.encrypted_to_der puts in
// front of the
// ciphertext, and what a PKCS#12 encrypted safe carries in its
// EncryptedContentInfo. One writer for both, so a key written here and a
// safe written by pkcs12_build name their parameters identically.
//
// parts: { prf, salt, iterations, cipher, iv, key_length? }
//
// `allow_ecb` is pkcs8.js's, and with it an ECB cipher is written when
// parts.allow_weak is true - see ECB_CIPHERS.
function scheme_to_der(parts, allow_ecb) {
  if (!parts || typeof parts !== 'object') {
    fail('bad-input', 'the PBES2 parameters are required');
  }

  var c = cipher_entry(parts.cipher, allow_ecb === true);

  if (c.ecb && parts.allow_weak !== true) {
    fail('weak-cipher', c.oid_name + ' encrypts equal blocks equally and ' +
      'takes no IV; aes256CBC does neither. Pass { allow_weak: true } to ' +
      'write it anyway');
  }

  // keyLength is written only when it is not implied by the cipher, matching
  // what OpenSSL emits - so a key written here and one written there compare
  // byte for byte. A length that disagrees with the cipher is refused.
  if (parts.key_length !== undefined && parts.key_length !== null &&
      parts.key_length !== c.entry.key) {
    fail('key-length-mismatch',
      parts.cipher + ' takes a ' + c.entry.key + '-byte key');
  }

  return W.sequence([
    W.oid(OID.by_name('pbes2')),
    W.sequence([
      pbkdf2_to_der(parts),
      c.ecb ? W.sequence([W.oid(OID.by_name(c.oid_name)),
                          W.octet_string(new Uint8Array(0))])
            : cipher_to_der(parts.cipher, parts.iv)
    ])
  ]);
}

// The PBKDF2 AlgorithmIdentifier: { prf, salt, iterations }. Shared by
// PBES2, by CMS password recipients (RFC 3211), whose
// keyDerivationAlgorithm is this same structure, and by PBMAC1 (RFC 9579).
//
// `key_length` is written only when given. PBES2 and pwri leave it out -
// the cipher implies it, and OpenSSL omits it - but PBMAC1 MUST carry it
// (RFC 9579 5), because an HMAC key has no length of its own to imply.
function pbkdf2_to_der(parts, key_length) {
  if (!parts.salt || parts.salt.length === 0) {
    fail('bad-salt', 'a salt is required');
  }
  if (!parts.iterations || parts.iterations < 1000) {
    // Refused on WRITE where it is only reported on read. An old key with a
    // low count already exists and refusing to read it helps nobody; writing
    // a new one that way is a choice, and this library does not make it.
    fail('weak-iterations',
      'writing a key with fewer than 1000 iterations is refused; RFC 8018 ' +
      'section 4.2 sets that as the minimum and current guidance is far ' +
      'higher');
  }
  check_iterations(parts.iterations, undefined, fail,
    'the PBKDF2 iteration count');

  var prf_name = parts.prf === undefined ? 'hmacWithSHA1'
    : canonical_name(parts.prf);

  if (PRFS[prf_name] === undefined) {
    fail('unsupported-prf', 'cannot write PRF ' + parts.prf);
  }

  var kdf_params = [
    W.octet_string(to_bytes(parts.salt)),
    W.unsigned(int_bytes(parts.iterations))
  ];

  if (key_length !== undefined) {
    kdf_params.push(W.unsigned(int_bytes(key_length)));
  }

  // The PRF is written unless it is the DEFAULT. DER omits a value equal to
  // its default, so writing hmacWithSHA1 explicitly would be non-canonical.
  if (prf_name !== 'hmacWithSHA1') {
    kdf_params.push(W.sequence([
      W.oid(OID.by_name(prf_name)),
      W.null()
    ]));
  }

  return W.sequence([W.oid(OID.by_name('pbkdf2')), W.sequence(kdf_params)]);
}

// A CBC cipher AlgorithmIdentifier with its IV - 'aes256CBC' (or
// 'aes-256-cbc') and 16 bytes.
function cipher_to_der(cipher, iv) {
  var c = cipher_entry(cipher);

  if (!iv || iv.length !== c.entry.iv) {
    fail('bad-iv-length', cipher + ' takes a ' + c.entry.iv + '-byte IV');
  }

  return W.sequence([W.oid(OID.by_name(c.oid_name)),
                     W.octet_string(to_bytes(iv))]);
}

function cipher_entry(cipher, allow_ecb) {
  var name = canonical_name(cipher);

  if (allow_ecb === true && ECB_CIPHERS[name] !== undefined) {
    return { oid_name: name, entry: ECB_CIPHERS[name], ecb: true };
  }
  if (CIPHERS[name] === undefined) {
    fail('unsupported-cipher', 'cannot write ' + cipher + '; PBES2 here is ' +
      Object.keys(CIPHERS).join(', '));
  }
  return { oid_name: name, entry: CIPHERS[name] };
}

// ---------------------------------------------------------------------------



export {
  scheme_to_der,
  pbkdf2_to_der,
  cipher_to_der,
  read_kdf as read_pbkdf2,
  read_scheme as read_cipher,
  is_weak,
  CIPHERS,
  ECB_CIPHERS,
  PRFS
};
