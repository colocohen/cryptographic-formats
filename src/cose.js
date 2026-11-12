// COSE, RFC 9052 (formerly RFC 8152), and COSE keys, RFC 9053.
//
// This is the item with no real competition in JavaScript. What exists -
// cose-to-jwk, parse-cosekey - was written for one WebAuthn use case, handles
// only ECDSA and RSA, and is barely maintained. Nothing does COSE_Sign1, or
// the full key type range, or Sig_structure.
//
// Three things, and the third is the one that breaks interoperability:
//
//   COSE_Key         a key as a CBOR map with integer labels
//   COSE_Sign1       the signed container
//   Sig_structure    THE BYTES ACTUALLY SIGNED
//
// Sig_structure is format work - it is an array assembled from the context
// string, the protected header and the payload - but an error in it produces
// signatures that verify nowhere else, and the failure looks like a bad key
// rather than a bad encoding. RFC 9052 section 4.4 defines it.
//
// This module builds Sig_structure and hands the bytes over. It does not
// sign, verify, or hash - see DECISIONS 0.1.

import * as CBOR from './cbor_reader.js';
import * as W from './cbor_writer.js';

import { to_bytes } from './commons/bytes.js';
import { make_fail_here } from './commons/fail.js';
import { encode_utf8 } from './commons/encode_text.js';

var fail = make_fail_here('cose');


// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

// ⚠ COSE HAS TWO LABEL SPACES AND THEY OVERLAP WITH DIFFERENT MEANINGS.
//
//   label   in a HEADER (RFC 9052 table 2)   in a KEY (table 3)
//   -----   ------------------------------   ------------------
//     1     alg                              kty
//     2     crit                             kid
//     3     content type                     alg
//     4     kid                              key_ops
//     5     IV                               base IV
//
// So label 1 in a protected header is the algorithm, and label 1 in a
// COSE_Key is the key type. Reading a header with the key table returns the
// algorithm as if it were a key type, or - as happened while this module was
// being written - returns null for an algorithm that is plainly there.
//
// Two tables, named for which space they belong to, and neither is used for
// the other.

// ⚠ A SWEEP AGAINST THE IANA REGISTRY FOUND SIX OF TEN.
//
// The missing ones are not obscure. `counter signature` is how a COSE
// message carries a second signature - a timestamp, a notary - and a
// message that has one and is read by something that does not see it is a
// message whose second claim is invisible.
//
// x5bag and x5u are the other two ways RFC 9360 carries certificates, and a
// reader that knows only x5chain will find nothing in a message that used
// either.
var HEADER_LABEL = {
  // RFC 9052 table 2.
  alg:          1,
  crit:         2,
  content_type: 3,
  kid:          4,
  iv:           5,
  partial_iv:   6,
  // Deprecated by RFC 9338 in favour of label 11, and still what older
  // messages carry - so it is read, and the newer one is read too.
  counter_signature: 7,

  // RFC 9338 section 3.1.
  counter_signature_0: 11,

  // RFC 9360 table 1. The four ways a COSE message carries certificates.
  x5bag:        32,
  x5chain:      33,
  x5t:          34,
  x5u:          35
};

// RFC 9052 table 3 (common key parameters) and RFC 9053 tables.
var KEY_LABEL = {
  kty:     1,
  kid:     2,
  alg:     3,
  key_ops: 4,
  base_iv: 5,
  // OKP and EC2 share these label numbers with different meanings, which is
  // exactly why kty has to be read first.
  crv:    -1,
  x:      -2,
  y:      -3,      // EC2 only
  d:      -4
};

var KTY = {
  OKP:       1,
  EC2:       2,
  RSA:       3,
  Symmetric: 4
};

// RFC 9053 table 18 and RFC 8152 table 22.
var CRV = {
  1: { name: 'P-256',    oid: 'secp256r1', kty: 2, size: 32 },
  2: { name: 'P-384',    oid: 'secp384r1', kty: 2, size: 48 },
  3: { name: 'P-521',    oid: 'secp521r1', kty: 2, size: 66 },
  4: { name: 'X25519',   oid: 'X25519',    kty: 1, size: 32 },
  5: { name: 'X448',     oid: 'X448',      kty: 1, size: 56 },
  6: { name: 'Ed25519',  oid: 'Ed25519',   kty: 1, size: 32 },
  7: { name: 'Ed448',    oid: 'Ed448',     kty: 1, size: 57 },
  8: { name: 'secp256k1', oid: 'secp256k1', kty: 2, size: 32 }
};

// RFC 9053 table 1 and table 2. Negative because COSE reserves positive
// values for the standard registry's later entries.
// ⚠ EVERY ALGORITHM CARRIES ITS KIND, WHICH ELEVEN SIGNATURE ENTRIES DID
//    NOT NEED AND THE REST DO.
//
// The table held only the signature algorithms, so a message using A256GCM
// or HMAC-256 reported `alg: null` - and a caller checking `alg === 'ES256'`
// would treat an encrypted message as an unsigned one rather than as
// something else entirely.
//
// `kind` is what makes that impossible: a caller reads it before deciding
// what the message is, and a signature check on a `mac` algorithm is a
// mistake the table can now name.
var ALG = {
  // --- signature, RFC 9053 tables 1 and 2 --------------------------------
  '-7':   { name: 'ES256',  kind: 'signature', crv: 1 },
  '-35':  { name: 'ES384',  kind: 'signature', crv: 2 },
  '-36':  { name: 'ES512',  kind: 'signature', crv: 3 },
  '-8':   { name: 'EdDSA',  kind: 'signature', crv: null },
  '-47':  { name: 'ES256K', kind: 'signature', crv: 8 },
  '-257': { name: 'RS256',  kind: 'signature', crv: null },
  '-258': { name: 'RS384',  kind: 'signature', crv: null },
  '-259': { name: 'RS512',  kind: 'signature', crv: null },
  '-37':  { name: 'PS256',  kind: 'signature', crv: null },
  '-38':  { name: 'PS384',  kind: 'signature', crv: null },
  '-39':  { name: 'PS512',  kind: 'signature', crv: null },

  // --- content encryption, RFC 9053 table 5 and 6 ------------------------
  //
  // The key and nonce sizes are stated because a caller has to derive or
  // supply both, and an AES-GCM nonce is 12 bytes where an AES-CCM one
  // depends on the variant - which is the sort of thing a table should
  // answer rather than a document.
  '1':  { name: 'A128GCM', kind: 'encryption', key: 16, nonce: 12, tag: 16 },
  '2':  { name: 'A192GCM', kind: 'encryption', key: 24, nonce: 12, tag: 16 },
  '3':  { name: 'A256GCM', kind: 'encryption', key: 32, nonce: 12, tag: 16 },

  '10': { name: 'AES-CCM-16-64-128',  kind: 'encryption',
          key: 16, nonce: 13, tag: 8 },
  '11': { name: 'AES-CCM-16-64-256',  kind: 'encryption',
          key: 32, nonce: 13, tag: 8 },
  '12': { name: 'AES-CCM-64-64-128',  kind: 'encryption',
          key: 16, nonce: 7,  tag: 8 },
  '13': { name: 'AES-CCM-64-64-256',  kind: 'encryption',
          key: 32, nonce: 7,  tag: 8 },
  '30': { name: 'AES-CCM-16-128-128', kind: 'encryption',
          key: 16, nonce: 13, tag: 16 },
  '31': { name: 'AES-CCM-16-128-256', kind: 'encryption',
          key: 32, nonce: 13, tag: 16 },
  '32': { name: 'AES-CCM-64-128-128', kind: 'encryption',
          key: 16, nonce: 7,  tag: 16 },
  '33': { name: 'AES-CCM-64-128-256', kind: 'encryption',
          key: 32, nonce: 7,  tag: 16 },

  '24': { name: 'ChaCha20/Poly1305', kind: 'encryption',
          key: 32, nonce: 12, tag: 16 },

  // --- MAC, RFC 9053 tables 7 and 8 --------------------------------------
  //
  // ⚠ HMAC 256/64 IS A TRUNCATED TAG, and the two numbers are not the same
  // thing: the first is the hash and the second is how many BITS of it are
  // kept. A caller comparing a 32-byte tag against a message that carries 8
  // is comparing the wrong length.
  '4':  { name: 'HMAC 256/64',  kind: 'mac', hash: 'sha256', tag: 8 },
  '5':  { name: 'HMAC 256/256', kind: 'mac', hash: 'sha256', tag: 32 },
  '6':  { name: 'HMAC 384/384', kind: 'mac', hash: 'sha384', tag: 48 },
  '7':  { name: 'HMAC 512/512', kind: 'mac', hash: 'sha512', tag: 64 },

  '14': { name: 'AES-MAC 128/64',  kind: 'mac', key: 16, tag: 8 },
  '15': { name: 'AES-MAC 256/64',  kind: 'mac', key: 32, tag: 8 },
  '25': { name: 'AES-MAC 128/128', kind: 'mac', key: 16, tag: 16 },
  '26': { name: 'AES-MAC 256/128', kind: 'mac', key: 32, tag: 16 },

  // --- key wrap and derivation, RFC 9053 tables 9 to 15 ------------------
  '-3': { name: 'A128KW', kind: 'key-wrap', key: 16 },
  '-4': { name: 'A192KW', kind: 'key-wrap', key: 24 },
  '-5': { name: 'A256KW', kind: 'key-wrap', key: 32 },

  // ⚠ `direct` means the recipient already holds the content key. A message
  // using it carries no wrapped key, and a reader that expected one would
  // look for something that is correctly absent.
  '-6': { name: 'direct', kind: 'direct' },

  '-25': { name: 'ECDH-ES + HKDF-256', kind: 'key-agreement' },
  '-26': { name: 'ECDH-ES + HKDF-512', kind: 'key-agreement' },
  '-27': { name: 'ECDH-SS + HKDF-256', kind: 'key-agreement' },
  '-28': { name: 'ECDH-SS + HKDF-512', kind: 'key-agreement' },
  '-29': { name: 'ECDH-ES + A128KW',   kind: 'key-agreement' },
  '-30': { name: 'ECDH-ES + A192KW',   kind: 'key-agreement' },
  '-31': { name: 'ECDH-ES + A256KW',   kind: 'key-agreement' },
  '-32': { name: 'ECDH-SS + A128KW',   kind: 'key-agreement' },
  '-33': { name: 'ECDH-SS + A192KW',   kind: 'key-agreement' },
  '-34': { name: 'ECDH-SS + A256KW',   kind: 'key-agreement' },

  '-10': { name: 'direct+HKDF-SHA-256', kind: 'key-derivation' },
  '-11': { name: 'direct+HKDF-SHA-512', kind: 'key-derivation' },
  '-12': { name: 'direct+HKDF-AES-128', kind: 'key-derivation' },
  '-13': { name: 'direct+HKDF-AES-256', kind: 'key-derivation' },

  // --- hash, RFC 9054 -----------------------------------------------------
  '-14': { name: 'SHA-1',     kind: 'hash', size: 20 },
  '-16': { name: 'SHA-256',   kind: 'hash', size: 32 },
  '-43': { name: 'SHA-384',   kind: 'hash', size: 48 },
  '-44': { name: 'SHA-512',   kind: 'hash', size: 64 },
  '-15': { name: 'SHA-256/64', kind: 'hash', size: 8 }
};

// Message type tags, RFC 9052 section 2.
var TAG_SIGN1   = 18;
var TAG_SIGN    = 98;
var TAG_ENCRYPT0 = 16;
var TAG_MAC0    = 17;
var TAG_ENCRYPT = 96;
var TAG_MAC     = 97;

// How deep COSE_recipient may nest. RFC 9052 allows a recipient to have
// recipients (a key wrapped to a key wrapped to a key), and two layers is
// the deepest anything in practice writes; eight leaves room and stops a
// crafted message from recursing the stack away.
var MAX_RECIPIENT_DEPTH = 8;

// ---------------------------------------------------------------------------
// COSE_Key
// ---------------------------------------------------------------------------

// Returns the same shape every other source of a key produces, so a key from
// a WebAuthn attestation and a key from a PEM file compare directly.
function key_from_cbor(input) {
  var pairs = input instanceof Uint8Array || Array.isArray(input) === false
    ? CBOR.read(to_bytes(input), function (r) { return r.read_map(0); })
    : input;

  var m = index(pairs);
  var kty = m[KEY_LABEL.kty];

  if (kty === undefined) {
    fail('missing-kty', 'a COSE_Key must have label 1 (kty)');
  }
  if (typeof kty !== 'number') {
    fail('bad-kty', 'kty must be an integer, got ' + typeof kty);
  }

  if (kty === KTY.EC2) { return ec2_key(m); }
  if (kty === KTY.OKP) { return okp_key(m); }
  if (kty === KTY.RSA) {
    fail('unsupported-kty',
      'RSA COSE keys are not read by this module yet');
  }
  if (kty === KTY.Symmetric) {
    fail('symmetric-key',
      'kty Symmetric is a secret, not a key this module returns as a point');
  }

  fail('unknown-kty', 'unrecognised kty ' + kty);
}

function ec2_key(m) {
  var crv_id = m[KEY_LABEL.crv];

  if (crv_id === undefined) {
    fail('missing-crv', 'an EC2 COSE_Key must have label -1 (crv)');
  }

  var curve = CRV[crv_id];
  if (curve === undefined) {
    fail('unknown-curve', 'unrecognised crv ' + crv_id);
  }

  // The label numbers are shared between key types, so a curve belonging to
  // OKP under kty EC2 is a map whose two halves describe different keys.
  if (curve.kty !== KTY.EC2) {
    fail('kty-crv-mismatch',
      'crv ' + crv_id + ' (' + curve.name + ') belongs to kty OKP, not EC2');
  }

  var x = coordinate(m, KEY_LABEL.x, curve.size, 'x');
  var y = coordinate(m, KEY_LABEL.y, curve.size, 'y');

  check_alg(m, crv_id);

  var point = new Uint8Array(1 + curve.size * 2);
  point[0] = 0x04;
  point.set(x, 1);
  point.set(y, 1 + curve.size);

  var out = {
    algorithm:  'ecPublicKey',
    curve:      curve.oid,
    cose_curve: crv_id,
    point:      point,
    scalar:     null,
    kid:        m[KEY_LABEL.kid] || null,
    alg:        alg_name(m[KEY_LABEL.alg]),
    private:    false
  };

  if (m[KEY_LABEL.d] !== undefined) {
    out.scalar = coordinate(m, KEY_LABEL.d, curve.size, 'd');
    out.private = true;
  }

  return out;
}

function okp_key(m) {
  var crv_id = m[KEY_LABEL.crv];

  if (crv_id === undefined) {
    fail('missing-crv', 'an OKP COSE_Key must have label -1 (crv)');
  }

  var curve = CRV[crv_id];
  if (curve === undefined) {
    fail('unknown-curve', 'unrecognised crv ' + crv_id);
  }
  if (curve.kty !== KTY.OKP) {
    fail('kty-crv-mismatch',
      'crv ' + crv_id + ' (' + curve.name + ') belongs to kty EC2, not OKP');
  }

  // Label -3 is y for EC2 and unassigned for OKP. A key carrying it was
  // written as if it were EC2, and something upstream has the wrong idea of
  // what this key is.
  if (m[KEY_LABEL.y] !== undefined) {
    fail('unexpected-member',
      'an OKP COSE_Key has no label -3; only EC2 keys do');
  }

  check_alg(m, crv_id);

  var out = {
    algorithm:  curve.oid,
    curve:      null,
    cose_curve: crv_id,
    point:      coordinate(m, KEY_LABEL.x, curve.size, 'x'),
    scalar:     null,
    kid:        m[KEY_LABEL.kid] || null,
    alg:        alg_name(m[KEY_LABEL.alg]),
    private:    false
  };

  if (m[KEY_LABEL.d] !== undefined) {
    out.scalar = coordinate(m, KEY_LABEL.d, curve.size, 'd');
    out.private = true;
  }

  return out;
}

function check_alg(m, crv_id) {
  var alg = m[KEY_LABEL.alg];

  if (alg === undefined) {
    return;
  }
  if (typeof alg !== 'number') {
    fail('bad-alg', 'alg must be an integer');
  }

  var entry = ALG[String(alg)];
  if (entry === undefined) {
    fail('unknown-alg', 'unrecognised alg ' + alg);
  }

  // ES256 is P-256 and nothing else. A key declaring both ES256 and P-384 is
  // a map contradicting itself, and the digest size is not the whole story.
  if (entry.crv !== null && entry.crv !== crv_id) {
    fail('alg-crv-mismatch',
      'alg ' + entry.name + ' requires crv ' + entry.crv +
      ', but this key says ' + crv_id);
  }

  // EdDSA needs a signing curve; X25519 and X448 are for key agreement and
  // cannot sign whatever the caller does afterwards.
  if (entry.name === 'EdDSA' && crv_id !== 6 && crv_id !== 7) {
    fail('alg-crv-mismatch',
      'alg EdDSA needs Ed25519 or Ed448, not crv ' + crv_id);
  }
}

function alg_name(alg) {
  if (alg === undefined || alg === null) {
    return null;
  }
  var entry = ALG[String(alg)];
  return entry === undefined ? alg : entry.name;
}

// RFC 9053 section 7.1.1: coordinates are the full field length, left-padded.
// A short x is not the same point written compactly.
function coordinate(m, label, size, name) {
  var v = m[label];

  if (v === undefined) {
    fail('missing-member', 'this key type requires label ' + label +
      ' (' + name + ')');
  }
  if (!(v instanceof Uint8Array)) {
    fail('bad-member', name + ' must be a byte string');
  }
  if (v.length !== size) {
    fail('bad-coordinate-length',
      name + ' is ' + v.length + ' bytes; this curve requires ' + size);
  }
  return v;
}

// ---------------------------------------------------------------------------
// Writing a COSE_Key
// ---------------------------------------------------------------------------

var OID_TO_CRV = {
  secp256r1: 1, secp384r1: 2, secp521r1: 3, secp256k1: 8,
  X25519: 4, X448: 5, Ed25519: 6, Ed448: 7
};

function key_to_cbor(key) {
  if (!key || typeof key.algorithm !== 'string') {
    fail('bad-key', 'expected a key object with an algorithm');
  }

  var pairs = [];

  if (key.algorithm === 'ecPublicKey') {
    var crv_id = OID_TO_CRV[key.curve];
    if (crv_id === undefined) {
      fail('no-cose-curve',
        'curve ' + key.curve + ' has no registered COSE identifier');
    }

    var size = CRV[crv_id].size;
    if (!key.point || key.point.length !== 1 + size * 2) {
      fail('bad-point',
        'expected an uncompressed point of ' + (1 + size * 2) + ' bytes');
    }
    if (key.point[0] !== 0x04) {
      fail('bad-point',
        'a COSE_Key carries x and y separately, so the point must be ' +
        'uncompressed; decompress it with cryptographic-primitives first');
    }

    pairs.push([W.int(KEY_LABEL.kty), W.int(KTY.EC2)]);
    pairs.push([W.int(KEY_LABEL.crv), W.int(crv_id)]);
    pairs.push([W.int(KEY_LABEL.x),
      W.bytes(key.point.subarray(1, 1 + size))]);
    pairs.push([W.int(KEY_LABEL.y),
      W.bytes(key.point.subarray(1 + size))]);

    if (key.scalar) {
      pairs.push([W.int(KEY_LABEL.d), W.bytes(key.scalar)]);
    }
  } else if (OID_TO_CRV[key.algorithm] !== undefined) {
    var okp_crv = OID_TO_CRV[key.algorithm];

    pairs.push([W.int(KEY_LABEL.kty), W.int(KTY.OKP)]);
    pairs.push([W.int(KEY_LABEL.crv), W.int(okp_crv)]);
    pairs.push([W.int(KEY_LABEL.x), W.bytes(key.point)]);

    if (key.scalar) {
      pairs.push([W.int(KEY_LABEL.d), W.bytes(key.scalar)]);
    }
  } else {
    fail('unsupported-algorithm',
      'cannot write algorithm ' + key.algorithm + ' as a COSE_Key');
  }

  if (key.kid) {
    // kid is a byte string in COSE (RFC 9052 7.1); text is its UTF-8.
    pairs.push([W.int(KEY_LABEL.kid), W.bytes(typeof key.kid === 'string'
      ? encode_utf8(key.kid, fail) : key.kid)]);
  }

  // The writer sorts, so the caller cannot produce an unsorted map even by
  // pushing these in a different order.
  return W.to_bytes(W.map(pairs));
}

// ---------------------------------------------------------------------------
// COSE_Sign1
// ---------------------------------------------------------------------------

//   COSE_Sign1 = [
//       protected   : bstr,        an encoded map, or a zero-length bstr
//       unprotected : header_map,
//       payload     : bstr / nil,  nil when detached
//       signature   : bstr
//   ]
//
// The protected header is returned BOTH as its bytes and as its parsed map.
// The bytes are what Sig_structure needs, and they must be the ones that
// arrived: re-encoding the map would change the signature input for any
// message that deviates from deterministic form, and the signature would then
// fail to verify for reasons that look like a bad key.
function sign1_decode(input, options) {
  var bytes = to_bytes(input);

  return CBOR.read(bytes, function (r) {
    var tagged = null;

    if (r.peek_type() === CBOR.TAG) {
      tagged = r.read_tag();
      if (tagged !== TAG_SIGN1) {
        fail('wrong-tag',
          'expected tag ' + TAG_SIGN1 + ' for COSE_Sign1, got ' + tagged);
      }
    }

    var n = r.read_array_header();
    if (n !== 4) {
      fail('bad-sign1',
        'COSE_Sign1 is a four-element array, got ' + n);
    }

    var protected_bytes = r.read_bytes();
    var unprotected = r.read_map(0);
    check_headers(decode_protected(protected_bytes), unprotected, options);

    var payload = null;
    if (r.peek_type() === CBOR.SIMPLE) {
      // nil means the payload is detached and supplied out of band.
      var v = r.read_value(0);
      if (v !== null) {
        fail('bad-sign1', 'payload must be a byte string or nil');
      }
    } else {
      payload = r.read_bytes();
    }

    var signature = r.read_bytes();

    return {
      tagged:            tagged !== null,
      protected_bytes:   protected_bytes,
      protected:         decode_protected(protected_bytes),
      unprotected:       unprotected,
      payload:           payload,
      signature:         signature,
      alg:               protected_alg(protected_bytes)
    };
  });
}

// RFC 9052 section 3: an empty protected header is a ZERO-LENGTH byte string,
// not an encoded empty map. The two are different byte strings and only one
// is correct, so an encoded empty map here is refused rather than normalised.
function decode_protected(bytes) {
  if (bytes.length === 0) {
    return [];
  }

  var pairs = CBOR.read(bytes, function (r) { return r.read_map(0); });

  if (pairs.length === 0) {
    fail('non-canonical-protected',
      'an empty protected header must be a zero-length byte string, not an ' +
      'encoded empty map');
  }

  return pairs;
}

function protected_alg(bytes) {
  if (bytes.length === 0) {
    return null;
  }
  // HEADER_LABEL, not KEY_LABEL. In a header the algorithm is label 1; in a
  // key it is label 3, and label 1 is the key type.
  var m = index(decode_protected(bytes));
  return alg_name(m[HEADER_LABEL.alg]);
}

// ---------------------------------------------------------------------------
// Sig_structure
// ---------------------------------------------------------------------------

//   Sig_structure = [
//       context      : "Signature1",
//       body_protected : bstr,
//       external_aad : bstr,
//       payload      : bstr
//   ]
//
// RFC 9052 section 4.4. These are the bytes the signature is computed over,
// and getting them wrong produces signatures that verify nowhere else - a
// failure that looks like a bad key rather than a bad encoding.
//
// The library builds the structure and returns the bytes. Hashing them and
// signing is the caller's step with cryptographic-primitives.
function sig_structure_sign1(protected_bytes, payload, external_aad) {
  var aad = external_aad === undefined || external_aad === null
    ? new Uint8Array(0)
    : to_bytes(external_aad);

  return W.to_bytes(W.array([
    W.text('Signature1'),
    W.bytes(to_bytes(protected_bytes)),
    W.bytes(aad),
    W.bytes(to_bytes(payload))
  ]));
}

// The multi-signer form uses the context "Signature" and carries the signer's
// own protected header as well as the body's.
function sig_structure_sign(body_protected, signer_protected, payload,
                            external_aad) {
  var aad = external_aad === undefined || external_aad === null
    ? new Uint8Array(0)
    : to_bytes(external_aad);

  return W.to_bytes(W.array([
    W.text('Signature'),
    W.bytes(to_bytes(body_protected)),
    W.bytes(to_bytes(signer_protected)),
    W.bytes(aad),
    W.bytes(to_bytes(payload))
  ]));
}

// The signing input for a message already decoded. Takes the payload
// separately so a detached signature works: the message carries nil and the
// caller supplies the bytes.
function sign1_signing_input(message, payload, external_aad) {
  var body = payload === undefined || payload === null
    ? message.payload
    : payload;

  if (body === null || body === undefined) {
    fail('detached-payload',
      'this message has a detached payload; supply it to build the signing ' +
      'input');
  }

  return sig_structure_sign1(message.protected_bytes, body, external_aad);
}

// ---------------------------------------------------------------------------
// Assembling a COSE_Sign1
// ---------------------------------------------------------------------------

// Takes a signature the caller produced over sig_structure_sign1 and puts the
// message together. The signature crosses the boundary in the form the
// specification names - for ECDSA that is raw r||s, not DER - so the length
// is checked here.

function signature_size(alg) {
  if (alg === 'ES256' || alg === 'ES256K') { return 64; }
  if (alg === 'ES384') { return 96; }
  if (alg === 'ES512') { return 132; }
  if (alg === 'EdDSA') { return null; }   // 64 for Ed25519, 114 for Ed448
  return null;
}

// Builds a protected header from label/value pairs. Provided so a caller does
// not reach for the CBOR writer directly and produce an unsorted map.
// ---------------------------------------------------------------------------
// The header rules every structure shares - RFC 9052 section 3
// ---------------------------------------------------------------------------

// The labels whose MEANING this module implements, and so may appear in
// crit. RFC 9052 3.1: a recipient that does not understand a critical
// label MUST reject the message.
var UNDERSTOOD = [1, 2, 3, 4, 5, 6];

// ⚠ TWO RULES sign1_decode did not check, now checked for every structure:
//
//   disjoint   "A header parameter MUST NOT occur in both the protected and
//              unprotected header" (RFC 9052 3). A kid in both is two
//              answers, and the unprotected one is anybody's.
//   crit       must be in the PROTECTED header, a non-empty array, every
//              label in it present in the protected header, and every one
//              understood - by this module or by the caller, through
//              options.understood.
function check_headers(protected_pairs, unprotected_pairs, options) {
  var seen = {};
  var i;

  function key(label) {
    return (typeof label) + ':' + String(label);
  }

  for (i = 0; i < protected_pairs.length; i++) {
    seen[key(protected_pairs[i][0])] = true;
  }
  for (i = 0; i < unprotected_pairs.length; i++) {
    if (seen[key(unprotected_pairs[i][0])]) {
      fail('header-not-disjoint',
        'label ' + unprotected_pairs[i][0] + ' is in both the protected and ' +
        'the unprotected header');
    }
    if (unprotected_pairs[i][0] === HEADER_LABEL.crit) {
      fail('crit-unprotected', 'crit must be in the protected header');
    }
  }

  var p = index(protected_pairs);
  var u = index(unprotected_pairs);

  if (p[HEADER_LABEL.iv] !== undefined || u[HEADER_LABEL.iv] !== undefined) {
    if (p[HEADER_LABEL.partial_iv] !== undefined ||
        u[HEADER_LABEL.partial_iv] !== undefined) {
      fail('iv-and-partial-iv',
        'IV and Partial IV MUST NOT both be present (RFC 9052 3.1)');
    }
  }

  var crit = p[HEADER_LABEL.crit];

  if (crit === undefined) {
    return;
  }

  var understood = UNDERSTOOD.concat(
    options && Array.isArray(options.understood) ? options.understood : []);

  if (!Array.isArray(crit) || crit.length === 0) {
    fail('bad-crit', 'crit is a non-empty array of labels');
  }

  for (i = 0; i < crit.length; i++) {
    if (!seen[key(crit[i])]) {
      fail('bad-crit', 'crit names label ' + crit[i] + ', which is not in ' +
        'the protected header');
    }
    if (understood.indexOf(crit[i]) === -1) {
      fail('crit-not-understood',
        'crit says label ' + crit[i] + ' must be understood, and nothing ' +
        'here implements it. If your code does, pass options.understood');
    }
  }
}

// The common start of every COSE message: [protected, unprotected, ...].
// Reads the tag if there is one (it must be the expected one), the array
// header (it must have `size` members), and the two headers.
function read_head(r, tag, size, what) {
  var tagged = null;

  if (r.peek_type() === CBOR.TAG) {
    tagged = r.read_tag();
    if (tagged !== tag) {
      fail('wrong-tag',
        'expected tag ' + tag + ' for ' + what + ', got ' + tagged);
    }
  }

  var n = r.read_array_header();
  if (n !== size) {
    fail('bad-structure', what + ' is a ' + size + '-element array, got ' + n);
  }

  var protected_bytes = r.read_bytes();
  var unprotected = r.read_map(0);

  return { tagged: tagged !== null, protected_bytes: protected_bytes,
           protected: decode_protected(protected_bytes),
           unprotected: unprotected };
}

// A byte string, or nil for a detached payload.
function read_payload(r, what) {
  if (r.peek_type() === CBOR.SIMPLE) {
    if (r.read_value(0) !== null) {
      fail('bad-structure', what + ' payload must be a byte string or nil');
    }
    return null;
  }
  return r.read_bytes();
}

function aad_bytes(external_aad) {
  return external_aad === undefined || external_aad === null
    ? new Uint8Array(0)
    : to_bytes(external_aad);
}

function payload_of(message, payload) {
  var body = payload === undefined || payload === null
    ? message.payload : payload;
  if (body === null || body === undefined) {
    fail('detached-payload',
      'this message has a detached payload; supply it');
  }
  return to_bytes(body);
}

function alg_of(head) {
  var a = index(head.protected)[HEADER_LABEL.alg];
  if (a === undefined) {
    a = index(head.unprotected)[HEADER_LABEL.alg];
  }
  return a === undefined ? null : a;
}

// ---------------------------------------------------------------------------
// COSE_Sign - several signers over one payload, RFC 9052 4.1
// ---------------------------------------------------------------------------

//   COSE_Sign = [ protected, unprotected, payload, signatures: [+ [
//                 protected, unprotected, signature ]] ]
//
// Like a general JWS: several claims about one document, returned as a list
// because which signer to trust is the caller's decision.
function sign_decode(input, options) {
  return CBOR.read(to_bytes(input), function (r) {
    var head = read_head(r, TAG_SIGN, 4, 'COSE_Sign');
    check_headers(head.protected, head.unprotected, options);
    var payload = read_payload(r, 'COSE_Sign');
    var n = r.read_array_header();

    if (n === 0) {
      fail('bad-structure', 'COSE_Sign needs at least one signature');
    }

    var signatures = [];
    var i;

    for (i = 0; i < n; i++) {
      var k = r.read_array_header();
      if (k !== 3) {
        fail('bad-structure', 'a COSE_Signature is a 3-element array');
      }
      var sp = r.read_bytes();
      var su = r.read_map(0);
      var sig = r.read_bytes();
      var sprot = decode_protected(sp);
      check_headers(sprot, su, options);
      var sa = alg_of({ protected: sprot, unprotected: su });

      signatures.push({ protected_bytes: sp, protected: sprot,
                        unprotected: su, signature: sig,
                        alg: sa === null ? null : alg_name(sa) });
    }

    return { tagged: head.tagged, protected_bytes: head.protected_bytes,
             protected: head.protected, unprotected: head.unprotected,
             payload: payload, signatures: signatures };
  });
}

// The Sig_structure for signer `i`: "Signature", body protected, THAT
// signer's protected, external AAD, payload.
function sign_signing_input(message, i, payload, external_aad) {
  var s = message.signatures[i];
  if (s === undefined) {
    fail('bad-index', 'there is no signature ' + i);
  }
  return sig_structure_sign(message.protected_bytes, s.protected_bytes,
    payload_of(message, payload), external_aad);
}


function check_signature_length(alg, signature) {
  if (!(signature instanceof Uint8Array)) {
    fail('bad-signature', 'a signature byte string is required');
  }
  if (alg === undefined || alg === null) {
    return;
  }
  var expected = signature_size(alg);
  if (expected !== null && signature.length !== expected) {
    fail('bad-signature-length',
      alg + ' signatures are ' + expected + ' bytes (raw r||s); got ' +
      signature.length +
      (signature[0] === 0x30 ? ' - this looks like DER, which COSE does not use'
                             : ''));
  }
}

// ---------------------------------------------------------------------------
// COSE_Mac0 - RFC 9052 6.2
// ---------------------------------------------------------------------------

//   COSE_Mac0 = [ protected, unprotected, payload, tag ]
//
// The tag length is fixed by the algorithm - HMAC 256/64 is EIGHT bytes, a
// truncation, and a verifier comparing a full 32-byte HMAC against it
// never matches.
function mac0_decode(input, options) {
  return CBOR.read(to_bytes(input), function (r) {
    var head = read_head(r, TAG_MAC0, 4, 'COSE_Mac0');
    check_headers(head.protected, head.unprotected, options);
    var payload = read_payload(r, 'COSE_Mac0');
    var tag = r.read_bytes();

    return mac_body(head, payload, tag);
  });
}

// What COSE_Mac0 and COSE_Mac share: the tag, checked against the
// algorithm that made it.
function mac_body(head, payload, tag) {
  var a = alg_of(head);
  var spec = a === null ? undefined : ALG[String(a)];

  if (spec !== undefined && spec.kind !== 'mac') {
    fail('wrong-algorithm-kind', spec.name + ' is not a MAC algorithm');
  }
  if (spec !== undefined && tag.length !== spec.tag) {
    fail('bad-tag-length', spec.name + ' produces a ' + spec.tag +
      '-byte tag, got ' + tag.length);
  }

  return { tagged: head.tagged, protected_bytes: head.protected_bytes,
           protected: head.protected, unprotected: head.unprotected,
           payload: payload, tag: tag,
           alg: a === null ? null : alg_name(a),
           hash: spec === undefined ? null : spec.hash || null,
           key_length: spec === undefined ? null : spec.key || null,
           tag_length: spec === undefined ? null : spec.tag };
}

//   MAC_structure = [ "MAC0", protected, external_aad, payload ]
//
// What the MAC is computed over. For HMAC 256/64, compute HMAC-SHA-256 over
// these bytes and keep the FIRST 8.
function mac0_input(message, payload, external_aad) {
  return mac_structure('MAC0', message, payload, external_aad);
}

function mac_structure(context, message, payload, external_aad) {
  return W.to_bytes(W.array([
    W.text(context),
    W.bytes(to_bytes(message.protected_bytes)),
    W.bytes(aad_bytes(external_aad)),
    W.bytes(payload_of(message, payload))
  ]));
}


// ---------------------------------------------------------------------------
// COSE_Encrypt0 - RFC 9052 5.2
// ---------------------------------------------------------------------------

//   COSE_Encrypt0 = [ protected, unprotected, ciphertext ]
//
// The ciphertext includes the AEAD tag at its end, as RFC 9053 specifies.
// The IV is header label 5 - or a Partial IV, label 6, to be combined with
// a base IV from the key, which is context this module cannot see and so
// reports rather than resolves.
function encrypt0_decode(input, options) {
  return CBOR.read(to_bytes(input), function (r) {
    var head = read_head(r, TAG_ENCRYPT0, 3, 'COSE_Encrypt0');
    check_headers(head.protected, head.unprotected, options);
    var ciphertext = read_payload(r, 'COSE_Encrypt0');

    return encrypted_body(head, ciphertext);
  });
}

// What COSE_Encrypt0 and COSE_Encrypt share: the content layer - its
// cipher, nonce and ciphertext. nil is a detached ciphertext.
function encrypted_body(head, ciphertext) {
  var a = alg_of(head);
  var spec = a === null ? undefined : ALG[String(a)];
  var all = index(head.protected.concat(head.unprotected));
  var iv = all[HEADER_LABEL.iv] === undefined ? null : all[HEADER_LABEL.iv];
  var partial = all[HEADER_LABEL.partial_iv] === undefined
    ? null : all[HEADER_LABEL.partial_iv];

  if (spec !== undefined && spec.kind !== 'encryption') {
    fail('wrong-algorithm-kind', spec.name + ' is not a content cipher');
  }
  if (spec !== undefined && iv !== null && iv.length !== spec.nonce) {
    fail('bad-iv-length', spec.name + ' takes a ' + spec.nonce +
      '-byte nonce, got ' + iv.length);
  }
  if (spec !== undefined && ciphertext !== null &&
      ciphertext.length < spec.tag) {
    fail('bad-ciphertext', 'the ciphertext is shorter than the ' +
      spec.name + ' tag');
  }

  return { tagged: head.tagged, protected_bytes: head.protected_bytes,
           protected: head.protected, unprotected: head.unprotected,
           ciphertext: ciphertext, iv: iv, partial_iv: partial,
           alg: a === null ? null : alg_name(a),
           key_length: spec === undefined ? null : spec.key,
           tag_length: spec === undefined ? null : spec.tag };
}

//   Enc_structure = [ "Encrypt0", protected, external_aad ]
//
// The AAD for the AEAD. Not the protected header alone, and not empty when
// the protected header is - the array is always there.
function encrypt0_aad(message, external_aad) {
  return enc_structure('Encrypt0', message.protected_bytes, external_aad);
}

function enc_structure(context, protected_bytes, external_aad) {
  return W.to_bytes(W.array([
    W.text(context),
    W.bytes(to_bytes(protected_bytes || new Uint8Array(0))),
    W.bytes(aad_bytes(external_aad))
  ]));
}



// ---------------------------------------------------------------------------
// COSE_Encrypt and COSE_Mac - with recipients, RFC 9052 5.1 and 6.1
// ---------------------------------------------------------------------------
//
//   COSE_Encrypt   = [ protected, unprotected, ciphertext / nil,
//                      recipients: [+ COSE_recipient] ]
//   COSE_Mac       = [ protected, unprotected, payload / nil, tag,
//                      recipients: [+ COSE_recipient] ]
//   COSE_recipient = [ protected, unprotected, ciphertext / nil,
//                      ? recipients: [+ COSE_recipient] ]
//
// The content key is the same for every recipient and each recipient holds
// its own route to it - the CMS EnvelopedData shape in CBOR. Which recipient
// is the caller's is their decision (by kid, usually); this reports them
// all and opens none.
//
// ⚠ TWO DIFFERENT CONTEXT STRINGS FOR THE CONTENT. COSE_Encrypt's AAD is
// Enc_structure with "Encrypt", not "Encrypt0"; COSE_Mac's input is
// MAC_structure with "MAC", not "MAC0". A message decrypts with neither
// of the other two, and the failure looks like a wrong key.

function encrypt_decode(input, options) {
  return CBOR.read(to_bytes(input), function (r) {
    var head = read_head(r, TAG_ENCRYPT, 4, 'COSE_Encrypt');
    check_headers(head.protected, head.unprotected, options);
    var body = encrypted_body(head, read_payload(r, 'COSE_Encrypt'));
    body.recipients = read_recipients(r, options, 1);
    return body;
  });
}

// Enc_structure ["Encrypt", protected, external_aad] - the AEAD's AAD.
function encrypt_aad(message, external_aad) {
  return enc_structure('Encrypt', message.protected_bytes, external_aad);
}


function mac_decode(input, options) {
  return CBOR.read(to_bytes(input), function (r) {
    var head = read_head(r, TAG_MAC, 5, 'COSE_Mac');
    check_headers(head.protected, head.unprotected, options);
    var payload = read_payload(r, 'COSE_Mac');
    var body = mac_body(head, payload, r.read_bytes());
    body.recipients = read_recipients(r, options, 1);
    return body;
  });
}

// MAC_structure ["MAC", protected, external_aad, payload].
function mac_input(message, payload, external_aad) {
  return mac_structure('MAC', message, payload, external_aad);
}


// --- recipients ---------------------------------------------------------

function read_recipients(r, options, depth) {
  if (depth > MAX_RECIPIENT_DEPTH) {
    fail('too-deep', 'recipients nest more than ' + MAX_RECIPIENT_DEPTH +
      ' deep');
  }

  var n = r.read_array_header();

  if (n === 0) {
    fail('bad-structure', 'recipients is a non-empty array - RFC 9052 [+ ]');
  }

  var out = [];
  var i;
  for (i = 0; i < n; i++) {
    out.push(read_recipient(r, options, depth));
  }
  return out;
}

// Each recipient, with the algorithm's rules for its fields checked - the
// ones whose violation makes a message that opens in one implementation and
// not another:
//
//   direct    protected empty (RFC 9053 6.1.1) and ciphertext empty: the
//             recipient already holds the content key, so nothing is wrapped
//   A*KW      protected empty (RFC 9053 6.2.1) - AES-KW takes no AAD, so a
//             protected header there would be authenticated by nothing -
//             and the ciphertext a wrapped key: whole 8-byte blocks, at
//             least 24 bytes (a 16-byte key plus the integrity block)
function read_recipient(r, options, depth) {
  var size = r.read_array_header();

  if (size !== 3 && size !== 4) {
    fail('bad-structure', 'a COSE_recipient is a 3- or 4-element array, ' +
      'got ' + size);
  }

  var pb = r.read_bytes();
  var unprotected = r.read_map(0);
  var prot = decode_protected(pb);
  check_headers(prot, unprotected, options);
  var ciphertext = read_payload(r, 'COSE_recipient');
  var head = { protected: prot, unprotected: unprotected };
  var a = alg_of(head);

  if (a === null) {
    fail('missing-alg', 'a recipient names how it holds the key - alg is ' +
      'required');
  }

  var spec = ALG[String(a)];
  var kind = spec === undefined ? null : spec.kind;

  if (kind === 'encryption' || kind === 'mac' || kind === 'signature' ||
      kind === 'hash') {
    fail('wrong-algorithm-kind', spec.name + ' is not a recipient algorithm');
  }

  if (kind === 'direct' || kind === 'key-wrap') {
    if (pb.length !== 0) {
      fail('protected-not-empty', spec.name + ' recipients have an empty ' +
        'protected header, RFC 9053 ' + (kind === 'direct' ? '6.1.1' : '6.2.1'));
    }
  }

  if (kind === 'direct' && (ciphertext === null || ciphertext.length !== 0)) {
    fail('bad-ciphertext', 'a direct recipient carries no wrapped key - ' +
      'its ciphertext is the empty byte string');
  }

  if (kind === 'key-wrap' && (ciphertext === null ||
      ciphertext.length < 24 || ciphertext.length % 8 !== 0)) {
    fail('bad-ciphertext', spec.name + ' wraps to whole 8-byte blocks, at ' +
      'least 24 bytes');
  }

  var all = index(prot.concat(unprotected));
  var out = {
    protected_bytes: pb, protected: prot, unprotected: unprotected,
    ciphertext: ciphertext,
    alg: alg_name(a),
    kind: kind,
    kid: all[HEADER_LABEL.kid] === undefined ? null : all[HEADER_LABEL.kid],
    recipients: null
  };

  if (size === 4) {
    out.recipients = read_recipients(r, options, depth + 1);
  }

  return out;
}

// The Enc_structure for a recipient layer whose algorithm is an AEAD -
// context "Enc_Recipient" under COSE_Encrypt, "Mac_Recipient" under
// COSE_Mac, "Rec_Recipient" under another recipient. AES-KW, direct and
// ECDH-ES with AES-KW take no AAD and need none of these.
var RECIPIENT_CONTEXTS = ['Enc_Recipient', 'Mac_Recipient', 'Rec_Recipient'];

function recipient_aad(recipient, context, external_aad) {
  if (RECIPIENT_CONTEXTS.indexOf(context) === -1) {
    fail('bad-context', 'the context is one of ' +
      RECIPIENT_CONTEXTS.join(', '));
  }
  return enc_structure(context, recipient.protected_bytes, external_aad);
}

function write_recipients(list, depth) {
  if (!Array.isArray(list) || list.length === 0) {
    fail('bad-input', 'at least one recipient is required');
  }
  if (depth > MAX_RECIPIENT_DEPTH) {
    fail('too-deep', 'recipients nest more than ' + MAX_RECIPIENT_DEPTH +
      ' deep');
  }
  return W.array(list.map(function (rc) {
    var pb = rc.protected !== undefined ? protected_header(rc.protected)
      : to_bytes(rc.protected_bytes || new Uint8Array(0));
    var fields = [
      W.bytes(pb),
      header_map(rc.unprotected),
      rc.ciphertext === null || rc.ciphertext === undefined
        ? W.null() : W.bytes(to_bytes(rc.ciphertext))
    ];
    if (rc.recipients !== undefined && rc.recipients !== null) {
      fields.push(write_recipients(rc.recipients, depth + 1));
    }
    return W.array(fields);
  }));
}


// ---------------------------------------------------------------------------
// Writing - prepare / assemble, as every builder in this library
// ---------------------------------------------------------------------------
//
// <thing>_prepare(parts) returns { bytes, ... }: the bytes the cryptography
// applies to - the Sig_structure to sign, the MAC_structure to MAC, or, for
// encryption, the Enc_structure to use as the AEAD's AAD. The caller runs
// the operation and <thing>_assemble(prepared, result) writes the message.
//
//   var p   = cose.sign1_prepare({ protected: [[1, -8]], payload });
//   var msg = cose.sign1_assemble(p, ed25519_sign(key, p.bytes));
//
// parts, for every message:
//   protected        header label/value pairs - [[1, -7], [4, kid]] - or
//   protected_bytes  the protected header already encoded
//   unprotected      label/value pairs
//   external_aad     bytes bound in but not carried (default empty)
//   tagged           false to write it without its CBOR tag
// and, where the message has one, `payload` (with `detached: true` to
// leave it out of the message - it is still what is signed or MACed) and
// `recipients` [{ protected, unprotected, ciphertext, recipients }].
//
// The header rules the readers check (disjoint buckets, crit) are checked
// here too, so a message this writes is one this module reads.

function writer_head(parts, what) {
  if (!parts || typeof parts !== 'object') {
    fail('bad-input', what + '_prepare takes an object');
  }
  if (parts.protected !== undefined && parts.protected_bytes !== undefined) {
    fail('bad-input', 'give protected (label/value pairs) or ' +
      'protected_bytes, not both');
  }

  var pb = parts.protected_bytes !== undefined
    ? to_bytes(parts.protected_bytes)
    : protected_header(parts.protected || []);
  var unprotected = parts.unprotected || [];
  var prot = decode_protected(pb);

  check_headers(prot, unprotected, parts);

  var a = alg_of({ protected: prot, unprotected: unprotected });

  return {
    protected_bytes: pb,
    unprotected:     unprotected,
    alg:             a === null ? null : alg_name(a),
    alg_id:          a,
    external_aad:    aad_bytes(parts.external_aad),
    tagged:          parts.tagged !== false
  };
}

function writer_payload(parts, what) {
  if (parts.payload === undefined || parts.payload === null) {
    fail('bad-input', what + ' needs the payload - with detached: true it ' +
      'is left out of the message, but it is still what is covered');
  }
  return to_bytes(parts.payload);
}

function body_payload(p) {
  return p.detached ? W.null() : W.bytes(p.payload);
}

function tagged(p, tag, body) {
  return W.to_bytes(p.tagged ? W.tag(tag, body) : body);
}

// --- COSE_Sign1 -----------------------------------------------------------

function sign1_prepare(parts) {
  var p = writer_head(parts, 'sign1');
  p.payload = writer_payload(parts, 'sign1_prepare');
  p.detached = parts.detached === true;
  p.bytes = sig_structure_sign1(p.protected_bytes, p.payload, p.external_aad);
  return p;
}

// ECDSA in COSE is the fixed-width r||s pair, like JOSE and unlike DER - the
// length check catches the confusion where it happens.
function sign1_assemble(p, signature) {
  check_signature_length(p.alg, signature);
  return tagged(p, TAG_SIGN1, W.array([W.bytes(p.protected_bytes),
    header_map(p.unprotected), body_payload(p), W.bytes(signature)]));
}

// --- COSE_Sign: several signers -------------------------------------------

// parts.signers: [{ protected, unprotected }] - one per signer. Returns
// { signers: [{ bytes, ... }] }: each signer signs its own Sig_structure.
function sign_prepare(parts) {
  var p = writer_head(parts, 'sign');
  p.payload = writer_payload(parts, 'sign_prepare');
  p.detached = parts.detached === true;

  if (!Array.isArray(parts.signers) || parts.signers.length === 0) {
    fail('bad-input', 'COSE_Sign needs at least one signer');
  }

  p.signers = parts.signers.map(function (sp) {
    var h = writer_head(sp, 'sign');
    h.bytes = sig_structure_sign(p.protected_bytes, h.protected_bytes,
      p.payload, p.external_aad);
    return h;
  });
  return p;
}

// signatures: one per signer, in the order sign_prepare returned them.
function sign_assemble(p, signatures) {
  if (!Array.isArray(signatures) || signatures.length !== p.signers.length) {
    fail('bad-input', 'one signature per signer, in order - ' +
      p.signers.length + ' expected');
  }

  var sigs = p.signers.map(function (s, i) {
    check_signature_length(s.alg, signatures[i]);
    return W.array([W.bytes(s.protected_bytes), header_map(s.unprotected),
                    W.bytes(signatures[i])]);
  });

  return tagged(p, TAG_SIGN, W.array([W.bytes(p.protected_bytes),
    header_map(p.unprotected), body_payload(p), W.array(sigs)]));
}

// --- COSE_Mac0 and COSE_Mac -----------------------------------------------

function mac0_prepare(parts) {
  return mac0_prepare_as(parts, 'mac0', 'MAC0');
}

function mac0_assemble(p, tag) {
  check_tag_length(p, tag);
  return tagged(p, TAG_MAC0, W.array([W.bytes(p.protected_bytes),
    header_map(p.unprotected), body_payload(p), W.bytes(tag)]));
}

function mac_prepare(parts) {
  var p = mac0_prepare_as(parts, 'mac', 'MAC');
  p.recipients = parts.recipients;
  write_recipients(p.recipients, 1);      // checked now, written at assemble
  return p;
}

function mac_assemble(p, tag) {
  check_tag_length(p, tag);
  return tagged(p, TAG_MAC, W.array([W.bytes(p.protected_bytes),
    header_map(p.unprotected), body_payload(p), W.bytes(tag),
    write_recipients(p.recipients, 1)]));
}

function mac0_prepare_as(parts, what, context) {
  var p = writer_head(parts, what);
  p.payload = writer_payload(parts, what + '_prepare');
  p.detached = parts.detached === true;
  p.bytes = mac_structure(context, p, p.payload, p.external_aad);
  return p;
}

// HMAC 256/64 keeps 8 bytes of 32. A full-length tag for it is the commonest
// way to write a COSE_Mac0 that verifies nowhere.
function check_tag_length(p, tag) {
  if (!(tag instanceof Uint8Array)) {
    fail('bad-input', 'the MAC tag is bytes');
  }
  var spec = p.alg_id === null ? undefined : ALG[String(p.alg_id)];
  if (spec !== undefined && spec.kind === 'mac' && tag.length !== spec.tag) {
    fail('bad-tag-length', spec.name + ' produces a ' + spec.tag +
      '-byte tag, got ' + tag.length + ' - truncate the MAC');
  }
}

// --- COSE_Encrypt0 and COSE_Encrypt ---------------------------------------

// `bytes` is the AAD - the Enc_structure. Encrypt with it, and pass the
// ciphertext with the AEAD tag on the end, as RFC 9053 carries it.
function encrypt0_prepare(parts) {
  var p = writer_head(parts, 'encrypt0');
  p.bytes = enc_structure('Encrypt0', p.protected_bytes, p.external_aad);
  return p;
}

function encrypt0_assemble(p, ciphertext) {
  return tagged(p, TAG_ENCRYPT0, W.array([W.bytes(p.protected_bytes),
    header_map(p.unprotected), ciphertext_value(ciphertext)]));
}

function encrypt_prepare(parts) {
  var p = writer_head(parts, 'encrypt');
  p.bytes = enc_structure('Encrypt', p.protected_bytes, p.external_aad);
  p.recipients = parts.recipients;
  write_recipients(p.recipients, 1);
  return p;
}

function encrypt_assemble(p, ciphertext) {
  return tagged(p, TAG_ENCRYPT, W.array([W.bytes(p.protected_bytes),
    header_map(p.unprotected), ciphertext_value(ciphertext),
    write_recipients(p.recipients, 1)]));
}

// null is a detached ciphertext, carried elsewhere.
function ciphertext_value(ciphertext) {
  if (ciphertext === null) {
    return W.null();
  }
  if (ciphertext === undefined) {
    fail('bad-input', 'the ciphertext is required (null if detached)');
  }
  return W.bytes(to_bytes(ciphertext));
}

// ⚠ THE UNPROTECTED HEADER, ENCODED - not passed to the map writer raw.
//
// cbor_writer.map takes ENCODED keys and values. Every encoder here handed
// it the caller's pairs as they were - [[4, <kid bytes>]], the very shape
// the decoders return - and the bytes came out wrong without a word: the
// IV of an Encrypt0 written as the integer 0. Encoded the way
// protected_header encodes, so a header read can be written back.
function header_map(pairs) {
  var list = pairs || [];
  var encoded = [];
  var i;

  for (i = 0; i < list.length; i++) {
    encoded.push([W.encode_value(list[i][0], 0),
                  W.encode_value(list[i][1], 0)]);
  }
  return W.map(encoded);
}

function protected_header(pairs) {
  if (pairs.length === 0) {
    // The empty header is a zero-length byte string, not an encoded empty
    // map. Returning the encoded map here would produce a message this
    // module's own reader refuses.
    return new Uint8Array(0);
  }

  var encoded = [];
  var i;
  for (i = 0; i < pairs.length; i++) {
    encoded.push([
      W.encode_value(pairs[i][0], 0),
      W.encode_value(pairs[i][1], 0)
    ]);
  }
  return W.to_bytes(W.map(encoded));
}

// ---------------------------------------------------------------------------

// Turns [key, value] pairs into a lookup. Keys that are not integers are
// skipped rather than stringified, because "1" and 1 are different labels and
// collapsing them would let a private label answer for a registered one.
function index(pairs) {
  var out = {};
  var i;
  for (i = 0; i < pairs.length; i++) {
    if (typeof pairs[i][0] === 'number') {
      out[pairs[i][0]] = pairs[i][1];
    }
  }
  return out;
}


export {
  sign1_decode,
  sign1_signing_input,
  sign1_prepare,
  sign1_assemble,
  sign_decode,
  sign_signing_input,
  sign_prepare,
  sign_assemble,
  mac0_decode,
  mac0_input,
  mac0_prepare,
  mac0_assemble,
  mac_decode,
  mac_input,
  mac_prepare,
  mac_assemble,
  encrypt0_decode,
  encrypt0_aad,
  encrypt0_prepare,
  encrypt0_assemble,
  encrypt_decode,
  encrypt_aad,
  encrypt_prepare,
  encrypt_assemble,
  recipient_aad,
  key_from_cbor,
  key_to_cbor,
  protected_header,
  HEADER_LABEL,
  KEY_LABEL,
  KTY,
  CRV,
  ALG,
  TAG_SIGN1,
  TAG_SIGN,
  TAG_ENCRYPT0,
  TAG_MAC0,
  TAG_ENCRYPT,
  TAG_MAC
};
