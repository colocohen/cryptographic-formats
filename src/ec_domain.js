// EC domain and point handling, shared by every module that reads a key.
//
// ⚠ WHY THIS EXISTS: EXTRACTING THE DUPLICATE FOUND A DISAGREEMENT.
//
// spki.js and pkcs8.js each had their own `curve_from_parameters`, identical
// but for whitespace. Harmless on its own - but when Wycheproof found that
// SPKI accepted an EMPTY public point and a 57-byte X448 key, the fix went
// into spki.js and PKCS#8 kept none of it.
//
// So the two modules disagreed about what an EC key is: an SPKI with a
// 40-byte P-256 point was refused, and the SAME point inside a PKCS#8 was
// accepted. Nothing reported the difference, because each module had its own
// copy and each copy was internally consistent.
//
// That is the whole argument for extraction in one example: duplicated code
// does not stay duplicated, it DRIFTS, and the drift is invisible from
// inside either copy.
//
// SAFE TO SHARE: these are checks, not encoders. A mistake makes every module
// refuse the same good key or accept the same bad one - loud either way, and
// not a reader and a writer agreeing on something wrong. See
// src/commons/README.md.

import * as DER from './der_reader.js';
import * as OID from './oid.js';

// ---------------------------------------------------------------------------
// Curve sizes
// ---------------------------------------------------------------------------

// The field size in bytes, for checking that a point is the right LENGTH for
// the curve its wrapper names.
//
// Length is FORMAT work and belongs here: it follows from the curve
// identifier, which is the field these modules exist to preserve. Whether the
// point is ON the curve does not - that is cryptographic-primitives's decode_point, and two
// point decoders that disagree about which encodings are acceptable is the
// same class of bug as an encoder checked only against its own decoder.
var CURVE_SIZE = {
  secp192r1: 24, secp224r1: 28, secp256r1: 32, secp384r1: 48,
  secp521r1: 66, secp256k1: 32,
  brainpoolP256r1: 32, brainpoolP256t1: 32,
  brainpoolP320r1: 40, brainpoolP320t1: 40,
  brainpoolP384r1: 48, brainpoolP384t1: 48,
  brainpoolP512r1: 64, brainpoolP512t1: 64
};

// The fixed key sizes of the RFC 8410 algorithms, which have no parameters at
// all. An X448 key of 57 bytes is not an X448 key.
var OKP_SIZE = {
  Ed25519: 32, Ed448: 57, X25519: 32, X448: 56
};

// ---------------------------------------------------------------------------

// The parameters of an ecPublicKey are a named curve OID.
//
// ⚠ EXPLICIT DOMAIN PARAMETERS ARE REFUSED, here and everywhere else in this
// library. A curve that arrives with its own equation cannot be checked
// against a known-good definition, so accepting one means trusting whatever
// the file says the curve is - and a curve chosen by an attacker is a curve
// whose discrete log they already know.
function curve_from_parameters(params, fail) {
  var r = DER.reader(params);
  var oid_bytes;

  try {
    oid_bytes = r.read_oid();
    r.expect_end();
  } catch (e) {
    fail('explicit-curve-parameters',
      'EC parameters are not a named curve; explicit domain parameters are ' +
      'refused because the domain cannot be checked against a known curve');
  }

  var name = OID.name_of(oid_bytes);

  if (name === null) {
    fail('unknown-curve',
      'unrecognised named curve ' + OID.describe(oid_bytes));
  }

  return name;
}

// A SEC 1 point is one prefix byte plus one or two field elements.
//
// Found missing by Wycheproof: an SPKI with an EMPTY BIT STRING parsed
// cleanly and returned a zero-length "point". No curve has one.
function check_point_length(curve, point, fail) {
  var size = CURVE_SIZE[curve];

  if (size === undefined) {
    return;
  }

  if (point.length === 0) {
    fail('bad-point-length', 'the public key point is empty');
  }

  var prefix = point[0];

  if (prefix === 0x04) {
    if (point.length !== 1 + size * 2) {
      fail('bad-point-length',
        'an uncompressed ' + curve + ' point is ' + (1 + size * 2) +
        ' bytes, got ' + point.length);
    }
    return;
  }

  if (prefix === 0x02 || prefix === 0x03) {
    if (point.length !== 1 + size) {
      fail('bad-point-length',
        'a compressed ' + curve + ' point is ' + (1 + size) + ' bytes, got ' +
        point.length);
    }
    return;
  }

  // 0x00 is the point at infinity in SEC 1, and it is not a public key.
  fail('bad-point-prefix',
    'a SEC 1 point begins 0x02, 0x03 or 0x04, got 0x' +
    prefix.toString(16));
}

// The private scalar is the field size exactly, left-padded - RFC 5915
// section 3 for SEC1 and RFC 5208 for PKCS#8.
//
// A short scalar is the commonest real malformation: a producer that stripped
// leading zeros, which is right for an INTEGER and wrong for this OCTET
// STRING.
function check_scalar_length(curve, scalar, fail) {
  var size = CURVE_SIZE[curve];

  if (size === undefined) {
    return;
  }

  if (scalar.length !== size) {
    fail('bad-scalar-length',
      'a ' + curve + ' private scalar is ' + size + ' bytes, got ' +
      scalar.length +
      (scalar.length < size
        ? ' - a producer that stripped leading zeros, which is right for an ' +
          'INTEGER and wrong for this OCTET STRING'
        : ''));
  }
}

function check_okp_length(algorithm, key, fail, what) {
  var size = OKP_SIZE[algorithm];

  if (size === undefined) {
    return;
  }

  if (key.length !== size) {
    fail('bad-key-length',
      algorithm + ' ' + (what || 'keys') + ' are ' + size + ' bytes, got ' +
      key.length);
  }
}

// ---------------------------------------------------------------------------
// Key algorithms and their parameter rules
// ---------------------------------------------------------------------------

// ⚠ ONE TABLE FOR WHAT EACH KEY ALGORITHM'S PARAMETERS MUST BE.
//
// spki.js and pkcs8.js each had a copy: the FAMILY table, the "unknown /
// not a key algorithm" refusals, and a cascade of parameter checks - in
// pkcs8 as a function, in spki inline - and jscpd found five clones between
// them. They are the same rules, from the same RFCs, for the same
// AlgorithmIdentifier; two copies is how the EC point-length disagreement
// this file was created for happened in the first place.
//
//   curve      ecPublicKey: a named curve OID (RFC 5480)
//   null       rsaEncryption: present and NULL (RFC 4055 - absent is a
//              second encoding of the same key)
//   absent     the RFC 8410 algorithms: no parameters at all, not NULL
//   required   DSA: p, q and g, read and handed over - there is no registry
//              to check them against
// ⚠ THE POST-QUANTUM PARAMETER SETS, BY SIZE.
//
// Each OID names one parameter set, and each set fixes every length: the
// public key, the private key in each form, the signature or ciphertext. A
// length is the one thing about these keys a format reader CAN check
// without doing the mathematics - and a key of the wrong length for its OID
// is a key from another parameter set, or a truncated one.
//
// FIPS 204 table 2 (ML-DSA), FIPS 203 table 3 (ML-KEM), FIPS 205 table 2
// (SLH-DSA, where n is 16, 24 or 32: public 2n, private 4n). RFC 9881,
// RFC 9935 and RFC 9909 restate them, and their examples have these sizes.
//
//   seed       ML-DSA's xi (32) / ML-KEM's d || z (64) - the RECOMMENDED form
//   expanded   the expanded private key
//   private    SLH-DSA's, which has one form
var PQ_KEYS = {
  mlDsa44:  { family: 'ml-dsa', public: 1312, seed: 32, expanded: 2560, signature: 2420 },
  mlDsa65:  { family: 'ml-dsa', public: 1952, seed: 32, expanded: 4032, signature: 3309 },
  mlDsa87:  { family: 'ml-dsa', public: 2592, seed: 32, expanded: 4896, signature: 4627 },
  mlKem512:  { family: 'ml-kem', public: 800,  seed: 64, expanded: 1632, ciphertext: 768 },
  mlKem768:  { family: 'ml-kem', public: 1184, seed: 64, expanded: 2400, ciphertext: 1088 },
  mlKem1024: { family: 'ml-kem', public: 1568, seed: 64, expanded: 3168, ciphertext: 1568 }
};

(function () {
  var sets = { '128s': [16, 7856], '128f': [16, 17088], '192s': [24, 16224],
               '192f': [24, 35664], '256s': [32, 29792], '256f': [32, 49856] };
  var k;
  for (k in sets) {
    if (Object.prototype.hasOwnProperty.call(sets, k)) {
      var n = sets[k][0];
      PQ_KEYS['slhDsaSha2_' + k] = { family: 'slh-dsa', public: 2 * n,
        private: 4 * n, signature: sets[k][1] };
      PQ_KEYS['slhDsaShake_' + k] = { family: 'slh-dsa', public: 2 * n,
        private: 4 * n, signature: sets[k][1] };
    }
  }
}());

var KEY_PARAMS = {
  ecPublicKey:   'curve',
  rsaEncryption: 'null',
  Ed25519:       'absent',
  Ed448:         'absent',
  X25519:        'absent',
  X448:          'absent',
  dsa:           'required',
  // ⚠ RSA-PSS KEYS (RFC 4055 3.1): an RSA key restricted to PSS - what
  // `openssl genpkey -algorithm RSA-PSS` makes. Parameters ABSENT allow any
  // PSS signature; present, they are RSASSA-PSS-params, the limits a
  // signature by this key must keep to. Never NULL. This table did not have
  // it, so every certificate with such a key failed to read, where node and
  // OpenSSL accept it (reported from lemon).
  rsassaPss:     'pss'
};

(function () {
  var k;
  for (k in PQ_KEYS) {
    if (Object.prototype.hasOwnProperty.call(PQ_KEYS, k)) {
      KEY_PARAMS[k] = 'absent';      // RFC 9881 2, 9909 3, 9935 3: MUST be absent
    }
  }
}());

// The raw public key's length for an algorithm whose SPKI holds one - the
// OKP curves and the post-quantum sets - or undefined.
function raw_public_size(name) {
  if (OKP_SIZE[name] !== undefined) { return OKP_SIZE[name]; }
  return PQ_KEYS[name] === undefined ? undefined : PQ_KEYS[name].public;
}

// The algorithm's name, refusing what is unknown and what is known but not
// a key algorithm. `role` says which kind of key the caller was reading.
function identify_key_algorithm(alg_bytes, fail, role) {
  var name = OID.name_of(alg_bytes);

  if (name === null) {
    fail('unknown-algorithm',
      'unrecognised key algorithm ' + OID.describe(alg_bytes));
  }
  if (KEY_PARAMS[name] === undefined) {
    fail('unsupported-algorithm',
      name + ' is a known identifier but not a ' + role + ' algorithm');
  }
  return name;
}

// Applies the algorithm's parameter rule. Returns the curve name for
// ecPublicKey and null for everything else.
function read_key_parameters(name, params, fail) {
  var rule = KEY_PARAMS[name];

  if (rule === 'curve') {
    if (params === undefined) {
      fail('missing-parameters', name + ' requires a named curve in parameters');
    }
    return curve_from_parameters(params, fail);
  }

  if (rule === 'null') {
    if (params === undefined) {
      fail('missing-parameters',
        name + ' requires parameters to be present and NULL');
    }
    if (!(params.length === 2 && params[0] === 0x05 && params[1] === 0x00)) {
      fail('bad-parameters', name + ' requires parameters to be NULL');
    }
    return null;
  }

  if (rule === 'required') {
    if (params === undefined) {
      fail('missing-parameters', name + ' requires domain parameters');
    }
    return null;
  }

  // Absent, or a SEQUENCE - which spki.js reads as RSASSA-PSS-params.
  if (rule === 'pss') {
    if (params !== undefined && params[0] !== 0x30) {
      fail('bad-parameters', 'RSA-PSS key parameters are absent or ' +
        'RSASSA-PSS-params (RFC 4055 3.1); NULL is neither');
    }
    return null;
  }

  // RFC 8410: absent, not NULL. A NULL here is a second encoding of the key.
  if (params !== undefined) {
    fail('unexpected-parameters', name + ' must not carry parameters');
  }
  return null;
}

// Whether a curve name is one this library knows the size of - which is the
// list of curves it supports.
function is_curve(name) {
  return Object.prototype.hasOwnProperty.call(CURVE_SIZE, name);
}

export {
  is_curve,
  PQ_KEYS,
  raw_public_size,
  KEY_PARAMS,
  identify_key_algorithm,
  read_key_parameters,
  curve_from_parameters,
  check_point_length,
  check_scalar_length,
  check_okp_length,
  CURVE_SIZE,
  OKP_SIZE
};
