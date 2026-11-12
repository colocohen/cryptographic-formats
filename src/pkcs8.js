// PKCS#8 PrivateKeyInfo, RFC 5208 and RFC 5958.
//
//   PrivateKeyInfo ::= SEQUENCE {
//     version                   INTEGER,
//     privateKeyAlgorithm       AlgorithmIdentifier,
//     privateKey                OCTET STRING,
//     attributes           [0]  IMPLICIT Attributes OPTIONAL }
//
// The nesting is the point and it is where implementations cut corners. The
// OCTET STRING holds ANOTHER complete DER structure - a SEC1 ECPrivateKey for
// EC keys, a PKCS#1 RSAPrivateKey for RSA, a bare OCTET STRING for the
// Edwards and Montgomery curves.
//
// Wycheproof has cases that omit the inner OCTET STRING entirely and must be
// refused on structure. cryptographic-primitives's test harness marks those `acceptable`
// because it SCANS for a value of the right length rather than validating
// shape - it finds 32 bytes that look like a scalar and stops asking. That
// shortcut is exactly what this module must not take: every layer is parsed,
// and a scalar is only a scalar if the structure around it says so.

import * as DER from './der_reader.js';
import * as W from './der_writer.js';
import * as F from './fields.js';

// Imported for its side effect: pkix.js defines AlgorithmIdentifier,
// RDNSequence, Extension and the other structures PKIX shares.
import './pkix.js';
import * as OID from './oid.js';
import * as PBES2 from './pbes2.js';
import { key_algorithm_to_der } from './spki.js';
import { identify_key_algorithm, read_key_parameters, is_curve,
  curve_from_parameters, check_point_length, check_scalar_length,
  check_okp_length, CURVE_SIZE, OKP_SIZE, PQ_KEYS } from './ec_domain.js';

import { read_pss_params } from './algorithm.js';
import { to_bytes, int_value, bit_length, bytes_equal } from './commons/bytes.js';
import { make_fail_here } from './commons/fail.js';

var fail = make_fail_here('pkcs8');


// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------


F.define('PrivateKeyInfo', [
  { name: 'version',    type: 'unsigned' },
  { name: 'algorithm',  type: 'AlgorithmIdentifier' },
  { name: 'privateKey', type: 'octet_string' },
  // [0] IMPLICIT Attributes - present in RFC 5958, rarely used, captured
  // whole rather than interpreted.
  { name: 'attributes', tag: 0xA0, mode: 'implicit', type: 'octet_string',
    optional: true },
  // [1] IMPLICIT publicKey, the RFC 5958 OneAsymmetricKey addition. Ed25519
  // keys written by newer OpenSSL carry it.
  { name: 'publicKey',  tag: 0x81, mode: 'implicit', type: 'bit_string',
    optional: true }
]);

// SEC1 ECPrivateKey, RFC 5915. Appears BOTH as the inner structure of a
// PKCS#8 EC key AND on its own behind `-----BEGIN EC PRIVATE KEY-----`.
//
//   ECPrivateKey ::= SEQUENCE {
//     version        INTEGER { ecPrivkeyVer1(1) },
//     privateKey     OCTET STRING,
//     parameters [0] ECParameters OPTIONAL,
//     publicKey  [1] BIT STRING OPTIONAL }
F.define('ECPrivateKey', [
  { name: 'version',    type: 'unsigned' },
  { name: 'privateKey', type: 'octet_string' },
  { name: 'parameters', tag: 0xA0, mode: 'explicit', type: 'oid',
    optional: true },
  { name: 'publicKey',  tag: 0xA1, mode: 'explicit', type: 'bit_string',
    optional: true }
]);

// PKCS#1 RSAPrivateKey, RFC 8017 appendix A.1.2. Also appears both nested and
// bare, behind `-----BEGIN RSA PRIVATE KEY-----`.
F.define('RSAPrivateKey', [
  { name: 'version', type: 'unsigned' },
  { name: 'n',       type: 'unsigned' },
  { name: 'e',       type: 'unsigned' },
  { name: 'd',       type: 'unsigned' },
  { name: 'p',       type: 'unsigned' },
  { name: 'q',       type: 'unsigned' },
  { name: 'dp',      type: 'unsigned' },
  { name: 'dq',      type: 'unsigned' },
  { name: 'qinv',    type: 'unsigned' }
  // otherPrimeInfos, for multi-prime keys, is refused rather than parsed:
  // version must be 0, and version 1 is what signals its presence.
]);

// ---------------------------------------------------------------------------
// Algorithm families
// ---------------------------------------------------------------------------

// What the privateKey OCTET STRING holds, per algorithm. The PARAMETER rules
// are ec_domain's KEY_PARAMS, shared with spki.js - one table for what an
// AlgorithmIdentifier may carry, where there were two.
var FAMILY = {
  ecPublicKey:   { params: 'curve',  inner: 'sec1' },
  rsaEncryption: { params: 'null',   inner: 'pkcs1' },
  // An RSA key restricted to PSS: the same RSAPrivateKey inside, the
  // parameters as ec_domain's KEY_PARAMS rule for it.
  rsassaPss:     { params: 'pss',    inner: 'pkcs1' },
  Ed25519:       { params: 'absent', inner: 'raw', size: 32 },
  Ed448:         { params: 'absent', inner: 'raw', size: 57 },
  X25519:        { params: 'absent', inner: 'raw', size: 32 },
  X448:          { params: 'absent', inner: 'raw', size: 56 },

  // ⚠ DSA WAS MISSING FROM THIS TABLE ENTIRELY, so `openssl pkcs8 -topk8`
  // output for a DSA key reported `unsupported-algorithm`.
  //
  // The shape is unlike anything else here: the privateKey OCTET STRING
  // holds a bare INTEGER - the scalar x - and the domain lives in the
  // parameters. Every other family is a curve point or an RSA structure,
  // which is how it fell through.
  //
  // Found by testing against files openssl produces rather than against the
  // fixture set, which had no DSA key because nothing generated one.
  dsa:           { params: 'required', inner: 'integer' }
};
// The post-quantum families, from the size table ec_domain shares with spki.
//
//   pq-choice  ML-DSA and ML-KEM: a CHOICE of seed [0], expandedKey, or
//              both (RFC 9881 6, RFC 9935 6) - DER-encoded INSIDE the
//              privateKey OCTET STRING, as every other family's inner
//              structure is.
//   bare       SLH-DSA: the 4n private bytes ARE the OCTET STRING's
//              content (RFC 9909 6) - no inner wrapping at all, unlike
//              Ed25519's OCTET STRING inside an OCTET STRING.
(function () {
  var k;
  for (k in PQ_KEYS) {
    if (Object.prototype.hasOwnProperty.call(PQ_KEYS, k)) {
      FAMILY[k] = PQ_KEYS[k].family === 'slh-dsa'
        ? { params: 'absent', inner: 'bare', size: PQ_KEYS[k].private }
        : { params: 'absent', inner: 'pq-choice', pq: PQ_KEYS[k] };
    }
  }
}());




// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

function from_der(input) {
  var parsed = DER.read(input, function (r) {
    return F.read_type(r, 'PrivateKeyInfo');
  });

  // RFC 5208 fixes version at 0; RFC 5958 adds 1 to signal that a public key
  // is present. Anything else is a structure this parser has not been written
  // against.
  var version = int_value(parsed.version);
  if (version !== 0 && version !== 1) {
    fail('bad-version', 'PrivateKeyInfo version must be 0 or 1, got ' + version);
  }
  if (version === 1 && parsed.publicKey === undefined) {
    fail('bad-version',
      'version 1 signals an included public key, but none is present');
  }

  var alg_name = identify_key_algorithm(parsed.algorithm.algorithm, fail,
    'private key');
  var params = parsed.algorithm.parameters;
  var family = FAMILY[alg_name];

  var curve = read_key_parameters(alg_name, params, fail);

  var out = {
    algorithm: alg_name,
    curve:     curve,
    scalar:    null,
    point:     null,
    der:       to_bytes(input)
  };

  // The inner structure. This is the layer the harness helper skipped.
  if (family.inner === 'raw') {
    read_raw_scalar(out, family, parsed.privateKey);
  } else if (family.inner === 'bare') {
    read_bare(out, family, parsed.privateKey);
  } else if (family.inner === 'pq-choice') {
    read_pq_choice(out, family.pq, parsed.privateKey);
  } else if (family.inner === 'sec1') {
    read_sec1(out, curve, parsed.privateKey);
  } else if (family.inner === 'pkcs1') {
    read_pkcs1(out, parsed.privateKey);
  } else if (family.inner === 'integer') {
    read_dsa(out, parsed.privateKey, params);
  }

  // An RSA-PSS key's limits, as spki.js returns them - and the parameter
  // bytes, so to_der writes the same restrictions back.
  if (alg_name === 'rsassaPss') {
    out.parameters = params === undefined ? null : params;
    out.pss = params === undefined ? null : read_pss_params(params);
  }

  // An outer public key, when RFC 5958 supplied one.
  if (parsed.publicKey !== undefined) {
    if (parsed.publicKey.unused !== 0) {
      fail('bad-key-bit-string',
        'public key BIT STRING has ' + parsed.publicKey.unused +
        ' unused bits');
    }
    out.point = parsed.publicKey.bytes;
  }

  return out;
}



// ---------------------------------------------------------------------------
// Inner structures
// ---------------------------------------------------------------------------

// Ed25519 and friends: the OCTET STRING holds ANOTHER OCTET STRING wrapping
// the scalar. RFC 8410 section 7 is explicit about this and it is the case
// Wycheproof attacks - a key whose inner wrapper is missing has 32 bytes at
// the right offset and passes any parser that scans by length.
// SLH-DSA: the private key is the OCTET STRING's content, 4n bytes.
function read_bare(out, family, inner) {
  if (inner.length !== family.size) {
    fail('bad-scalar-length',
      out.algorithm + ' private keys are ' + family.size + ' bytes, got ' +
      inner.length);
  }
  out.scalar = inner;
}

// ⚠ ML-DSA AND ML-KEM: THREE FORMS, AND THE TAG SAYS WHICH.
//
//   seed         [0] IMPLICIT OCTET STRING - 0x80, primitive
//   expandedKey  OCTET STRING              - 0x04
//   both         SEQUENCE { seed, expandedKey }
//
// RFC 9881 and RFC 9935 RECOMMEND the seed: the expanded key and the public
// key follow from it by KeyGen. `both` carries a seed and an expanded key
// that MUST agree - and whether they do is a key generation away, which is
// cryptography. So `both` is read and reported, and private_format says the
// caller has a consistency check to make (RFC 9881 8, RFC 9935 8; their
// appendices C.4 hold keys that fail it).
function read_pq_choice(out, pq, inner) {
  var parsed = DER.read(inner, function (r) {
    var tag = r.peek_tag();

    if (tag === 0x80) {
      return { format: 'seed', seed: r.read_implicit(0, 0x04).bytes,
               expanded: null };
    }
    if (tag === 0x04) {
      return { format: 'expanded', seed: null, expanded: r.read_octet_string() };
    }
    if (tag === 0x30) {
      var both = r.read_sequence();
      var seed = both.read_octet_string();
      var expanded = both.read_octet_string();
      both.expect_end();
      return { format: 'both', seed: seed, expanded: expanded };
    }
    fail('bad-private-key',
      out.algorithm + ' private keys are seed [0], expandedKey or both; ' +
      'got tag 0x' + (tag === null ? 'end' : tag.toString(16)));
  });

  if (parsed.seed !== null && parsed.seed.length !== pq.seed) {
    fail('bad-seed-length', out.algorithm + ' seeds are ' + pq.seed +
      ' bytes, got ' + parsed.seed.length);
  }
  if (parsed.expanded !== null && parsed.expanded.length !== pq.expanded) {
    fail('bad-expanded-length', out.algorithm + ' expanded keys are ' +
      pq.expanded + ' bytes, got ' + parsed.expanded.length);
  }

  // ⚠ ML-KEM: WHAT CAN BE CHECKED WITHOUT CRYPTOGRAPHY, IS.
  //
  // FIPS 203's expanded key is dk_pke || ek || H(ek) || z, and the seed is
  // d || z. So the public key sits at a fixed offset inside the expanded
  // key, and z appears in both forms: a `both` whose two z values differ is
  // inconsistent by plain byte comparison - RFC 9935 C.4.1's fourth
  // example. Everything else (H(ek), the pairwise check) needs SHA3 and
  // KeyGen, and stays the caller's - `unchecked` says so.
  if (pq.family === 'ml-kem' && parsed.expanded !== null) {
    var dk_pke = pq.public - 32;          // 384k; ek is 384k + 32
    out.point = parsed.expanded.subarray(dk_pke, dk_pke + pq.public);

    if (parsed.seed !== null &&
        !bytes_equal(parsed.seed.subarray(32), parsed.expanded.subarray(pq.expanded - 32))) {
      fail('inconsistent-private-key',
        out.algorithm + ': the seed\'s z and the expanded key\'s z differ ' +
        '- the two forms are not the same key (RFC 9935 8)');
    }
  }

  out.private_format = parsed.format;
  out.seed = parsed.seed;
  out.expanded_key = parsed.expanded;
  if (parsed.format !== 'seed') {
    out.unchecked = 'the expanded key was not checked against ' +
      (parsed.seed !== null ? 'the seed' : 'its public key') + ': that is ' +
      'key generation (FIPS ' + (pq.family === 'ml-kem' ? '203' : '204') +
      '), which this library does not do. RFC ' +
      (pq.family === 'ml-kem' ? '9935' : '9881') + ' says to run it and ' +
      'compare before using the key.';
  }
  // The shared shape's `scalar`: the private key as stored - the seed when
  // there is one, since everything else derives from it.
  out.scalar = parsed.seed !== null ? parsed.seed : parsed.expanded;
}

function read_raw_scalar(out, family, inner) {
  var scalar = DER.read(inner, function (r) {
    return r.read_octet_string();
  });

  if (scalar.length !== family.size) {
    fail('bad-scalar-length',
      out.algorithm + ' scalar must be ' + family.size + ' bytes, got ' +
      scalar.length);
  }

  out.scalar = scalar;
}

// RFC 5915 ECPrivateKey, version 1 - inside a PKCS#8 or on its own.
function read_ec_private_key(bytes) {
  var ec = DER.read(bytes, function (r) {
    return F.read_type(r, 'ECPrivateKey');
  });

  var version = int_value(ec.version);
  if (version !== 1) {
    fail('bad-version', 'ECPrivateKey version must be 1, got ' + version);
  }
  return ec;
}

function read_sec1(out, curve, inner) {
  var ec = read_ec_private_key(inner);

  var size = CURVE_SIZE[curve];

  // RFC 5915: the scalar is the field length, zero-padded on the left. A
  // shorter one is a different encoding of the same key; a longer one is not
  // a scalar for this curve at all.
  if (ec.privateKey.length !== size) {
    fail('bad-scalar-length',
      curve + ' scalar must be ' + size + ' bytes, got ' +
      ec.privateKey.length);
  }

  // When the inner structure names a curve too, the two must agree. A PKCS#8
  // wrapper claiming P-256 around a SEC1 body claiming P-384 is a key with no
  // single answer to which curve it is on.
  if (ec.parameters !== undefined) {
    var inner_curve = OID.name_of(ec.parameters);
    if (inner_curve !== curve) {
      fail('curve-mismatch',
        'PKCS#8 says ' + curve + ' but the inner ECPrivateKey says ' +
        (inner_curve === null ? OID.describe(ec.parameters) : inner_curve));
    }
  }

  out.scalar = ec.privateKey;

  if (ec.publicKey !== undefined) {
    if (ec.publicKey.unused !== 0) {
      fail('bad-key-bit-string', 'inner public key has unused bits');
    }
    // ⚠ THE CHECK PKCS#8 DID NOT HAVE.
    //
    // Wycheproof found SPKI accepting an empty point and a 57-byte X448 key,
    // the fix went into spki.js, and this module kept none of it - so a
    // 40-byte P-256 point was refused inside an SPKI and accepted inside a
    // PKCS#8. Extracting the shared helper is what exposed it.
    check_point_length(out.curve, ec.publicKey.bytes, fail);
    out.point = ec.publicKey.bytes;
  }
}

// ⚠ A DSA PRIVATE KEY IS A BARE INTEGER.
//
//   Dss-Parms ::= SEQUENCE { p INTEGER, q INTEGER, g INTEGER }
//   the privateKey OCTET STRING holds  INTEGER  -- x
//
// Nothing else in this library has that shape: every other family is a curve
// point or an RSA structure, which is why a DSA PKCS#8 fell through the
// dispatch entirely and reported `unrecognised-der`.
//
// Read and never written, the same position DSA gets everywhere else here.
function read_dsa(out, inner, params) {
  out.scalar = DER.read(inner, function (r) {
    return r.read_unsigned();
  });

  if (params === undefined) {
    return;
  }

  var domain = DER.read(params, function (r) {
    var seq = r.read_sequence();
    var p = seq.read_unsigned();
    var q = seq.read_unsigned();
    var g = seq.read_unsigned();
    seq.expect_end();
    return { p: p, q: q, g: g };
  });

  out.domain = domain;
  // The bit length of p, which is the one judgement available from the
  // bytes - the same figure params.js reports for a DH group.
  out.bits = bit_length(domain.p);

  // ⚠ q is the subgroup order, and its size is what actually decides the
  // security level: a 2048-bit p with a 160-bit q is a 160-bit group.
  out.subgroup_bits = bit_length(domain.q);
}


function read_pkcs1(out, inner) {
  var rsa = DER.read(inner, function (r) {
    return F.read_type(r, 'RSAPrivateKey');
  });

  var version = int_value(rsa.version);
  if (version !== 0) {
    // Version 1 means otherPrimeInfos follows, which this parser does not
    // read. Refusing is honest; parsing the first eight fields and ignoring
    // the rest would return a key that is not the key in the file.
    fail('multi-prime-rsa',
      'RSAPrivateKey version ' + version + ' carries otherPrimeInfos, ' +
      'which is not supported');
  }

  out.rsa = {
    n: rsa.n, e: rsa.e, d: rsa.d,
    p: rsa.p, q: rsa.q,
    dp: rsa.dp, dq: rsa.dq, qinv: rsa.qinv
  };
  out.scalar = rsa.d;
}

// ---------------------------------------------------------------------------
// Bare formats - NOT PKCS#8
// ---------------------------------------------------------------------------

// PKCS#8 wraps an algorithm identifier around an inner key; SEC1 and PKCS#1
// ARE the inner key, on its own. A file saying `BEGIN EC PRIVATE KEY` will
// not parse as PKCS#8 and vice versa, and any library reading keys from disk
// has to handle both.
//
// OpenSSL 3.x makes this worse rather than better: `openssl rsa -outform der`
// writes PKCS#8, and only `-traditional` produces PKCS#1. A generator that
// forgets the flag produces two byte-identical fixtures.

function sec1_from_der(input) {
  var ec = read_ec_private_key(input);

  // A bare SEC1 key has nothing above it to name the curve, so its own
  // parameters field is the only source. Without it the scalar cannot be
  // interpreted - its length alone does not identify a curve, since P-256,
  // secp256k1 and brainpoolP256r1 all use 32 bytes.
  if (ec.parameters === undefined) {
    fail('missing-curve',
      'a bare ECPrivateKey must name its curve; scalar length cannot ' +
      'distinguish secp256r1 from secp256k1 or brainpoolP256r1');
  }

  var curve = OID.name_of(ec.parameters);
  if (curve === null || !is_curve(curve)) {
    fail('unknown-curve', 'unrecognised curve ' + OID.describe(ec.parameters));
  }

  var size = CURVE_SIZE[curve];
  if (ec.privateKey.length !== size) {
    fail('bad-scalar-length',
      curve + ' scalar must be ' + size + ' bytes, got ' +
      ec.privateKey.length);
  }

  var out = {
    format:    'sec1',
    algorithm: 'ecPublicKey',
    curve:     curve,
    scalar:    ec.privateKey,
    point:     null,
    der:       to_bytes(input)
  };

  if (ec.publicKey !== undefined) {
    if (ec.publicKey.unused !== 0) {
      fail('bad-key-bit-string', 'public key BIT STRING has unused bits');
    }
    check_point_length(out.curve, ec.publicKey.bytes, fail);
    out.point = ec.publicKey.bytes;
  }

  return out;
}

function pkcs1_from_der(input) {
  var rsa = DER.read(input, function (r) {
    return F.read_type(r, 'RSAPrivateKey');
  });

  var version = int_value(rsa.version);
  if (version !== 0) {
    fail('multi-prime-rsa',
      'RSAPrivateKey version ' + version + ' carries otherPrimeInfos, ' +
      'which is not supported');
  }

  return {
    format:    'pkcs1',
    algorithm: 'rsaEncryption',
    curve:     null,
    scalar:    rsa.d,
    rsa: {
      n: rsa.n, e: rsa.e, d: rsa.d,
      p: rsa.p, q: rsa.q,
      dp: rsa.dp, dq: rsa.dq, qinv: rsa.qinv
    },
    der: to_bytes(input)
  };
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

function to_der(key) {
  if (!key || typeof key.algorithm !== 'string') {
    fail('bad-key', 'expected a key object with an algorithm');
  }

  var family = FAMILY[key.algorithm];
  if (family === undefined) {
    fail('unsupported-algorithm', 'cannot encode algorithm ' + key.algorithm);
  }

  var alg = key_algorithm_to_der(key, fail);
  var inner;

  if (family.params === 'curve') {
    inner = encode_sec1(key);
  } else if (family.inner === 'pkcs1') {
    // rsaEncryption and rsassaPss: the same RSAPrivateKey inside.
    inner = encode_pkcs1(key);
  } else if (family.inner === 'pq-choice') {
    inner = encode_pq_choice(key, family.pq);
  } else if (family.inner === 'bare') {
    if (!key.scalar || key.scalar.length !== family.size) {
      fail('bad-scalar-length',
        key.algorithm + ' private keys are ' + family.size + ' bytes');
    }
    // The bytes themselves are the OCTET STRING's content - no inner TLV.
    return W.to_bytes(W.sequence([W.integer([0x00]), alg,
      W.octet_string(key.scalar)]));
  } else {
    if (!key.scalar || key.scalar.length !== family.size) {
      fail('bad-scalar-length',
        key.algorithm + ' scalar must be ' + family.size + ' bytes');
    }
    inner = W.octet_string(key.scalar);
  }

  return W.to_bytes(W.sequence([
    W.integer([0x00]),
    alg,
    W.octet_string(inner)
  ]));
}

// The CHOICE from what the key holds: seed and expanded_key -> both; one of
// them -> that one. A `scalar` alone is taken as the seed if it is a seed's
// length, as from_der reports it. The writer does not check that a seed and
// an expanded key agree - that is KeyGen, and this library does no
// cryptography; RFC 9881 RECOMMENDS writing the seed alone.
function encode_pq_choice(key, pq) {
  var seed = key.seed || null;
  var expanded = key.expanded_key || null;

  if (seed === null && expanded === null && key.scalar) {
    if (key.scalar.length === pq.seed) { seed = key.scalar; }
    else if (key.scalar.length === pq.expanded) { expanded = key.scalar; }
  }
  if (seed !== null && seed.length !== pq.seed) {
    fail('bad-seed-length', key.algorithm + ' seeds are ' + pq.seed + ' bytes');
  }
  if (expanded !== null && expanded.length !== pq.expanded) {
    fail('bad-expanded-length', key.algorithm + ' expanded keys are ' +
      pq.expanded + ' bytes');
  }
  if (seed !== null && expanded !== null) {
    return W.sequence([W.octet_string(seed), W.octet_string(expanded)]);
  }
  if (seed !== null) {
    return W.implicit(0, W.octet_string(seed));
  }
  if (expanded !== null) {
    return W.octet_string(expanded);
  }
  fail('bad-key', key.algorithm + ' needs seed or expanded_key');
}

function encode_sec1(key) {
  var size = CURVE_SIZE[key.curve];

  if (!key.scalar || key.scalar.length !== size) {
    fail('bad-scalar-length',
      key.curve + ' scalar must be ' + size + ' bytes, got ' +
      (key.scalar ? key.scalar.length : 0));
  }

  var parts = [
    W.integer([0x01]),
    W.octet_string(key.scalar)
  ];

  // OpenSSL omits the inner curve inside a PKCS#8 wrapper - the outer
  // algorithm identifier already carries it, and repeating it creates two
  // places for the curve to disagree. Matching that keeps re-encoding
  // byte-identical.
  if (key.point) {
    parts.push(W.explicit(1, W.bit_string(key.point, 0)));
  }

  return W.sequence(parts);
}

function encode_pkcs1(key) {
  if (!key.rsa) {
    fail('bad-key', 'an RSA private key needs its components');
  }
  var k = key.rsa;
  return W.sequence([
    W.integer([0x00]),
    W.unsigned(k.n), W.unsigned(k.e), W.unsigned(k.d),
    W.unsigned(k.p), W.unsigned(k.q),
    W.unsigned(k.dp), W.unsigned(k.dq), W.unsigned(k.qinv)
  ]);
}

// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// Encrypted keys - PBES2
// ---------------------------------------------------------------------------

// An EncryptedPrivateKeyInfo (RFC 5958) - a key nobody can read without a
// password. What comes back is therefore not the key but what the caller
// needs to decrypt it: the PBES2 parameters, and the ciphertext as `data`.
// Decrypting gives a PrivateKeyInfo, which from_der reads:
//
//   var enc = pkcs8.encrypted_from_der(der);
//   var dk  = pbkdf2(node_name(enc.prf), password, enc.salt, enc.iterations,
//                    enc.key_length);
//   var key = pkcs8.from_der(cbc_decrypt(node_name(enc.cipher), dk, enc.iv,
//                                        enc.data));
//
// `options.max_iterations` raises the ceiling on the iteration count - see
// commons/limits.js. The count is the caller's cost and the file's choice.
function encrypted_from_der(input, options) {
  var outer = DER.read(input, function (r) {
    return F.read_type(r, 'EncryptedPrivateKeyInfo');
  });

  var scheme_name = OID.name_of(outer.algorithm.algorithm);

  if (scheme_name !== 'pbes2') {
    // PBES1 and the PKCS#12 schemes use different identifiers and different
    // derivations. Naming what was found is more useful than "unsupported",
    // because the caller may have reached for the wrong reader.
    fail('not-pbes2',
      'this key uses ' +
      (scheme_name === null
        ? OID.describe(outer.algorithm.algorithm)
        : scheme_name) +
      ', not PBES2');
  }

  if (outer.algorithm.parameters === undefined) {
    fail('missing-parameters', 'PBES2 requires parameters');
  }

  var p = DER.read(outer.algorithm.parameters, function (r) {
    return F.read_type(r, 'PBES2Params');
  });

  var kdf = PBES2.read_pbkdf2(p.kdf, options);
  var enc = PBES2.read_cipher(p.scheme);

  // RFC 8018 A.4: keyLength is OPTIONAL, and when absent the length comes
  // from the encryption scheme. A caller who defaulted to the PRF's output
  // length instead would derive 20 or 32 bytes where AES-192 wants 24, and
  // the result would look like a wrong password.
  var key_length = kdf.key_length === null ? enc.key_length : kdf.key_length;

  if (kdf.key_length !== null && kdf.key_length !== enc.key_length) {
    fail('key-length-mismatch',
      'the KDF asks for ' + kdf.key_length + ' bytes but ' + enc.cipher +
      ' takes ' + enc.key_length);
  }

  return {
    kdf:        'pbkdf2',
    prf:        kdf.prf,
    salt:       kdf.salt,
    iterations: kdf.iterations,
    key_length: key_length,
    cipher:     enc.cipher,
    iv:         enc.iv,
    data:       outer.data,
    // read_kdf computed this and params() dropped it - the weakness check
    // ran and its answer went nowhere.
    weak:       kdf.weak
  };
}

// The other direction: ciphertext the caller produced, wrapped as an
// EncryptedPrivateKeyInfo with the PBES2 parameters that produced it. The library does not
// encrypt, so the caller derives the key, encrypts, and passes the result
// with the parameters that were used - which is also what makes the
// parameters honest: they describe what actually happened.
function encrypted_to_der(parts) {
  if (!parts || !(parts.data instanceof Uint8Array)) {
    fail('bad-input', 'ciphertext is required');
  }

  return W.to_bytes(W.sequence([
    PBES2.scheme_to_der(parts),
    W.octet_string(parts.data)
  ]));
}

export {
  encrypted_from_der,
  encrypted_to_der,
  from_der,
  to_der,
  sec1_from_der,
  pkcs1_from_der,
  CURVE_SIZE
};
