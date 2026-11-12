// JSON Web Key, RFC 7517 and RFC 7518.
//
// Probably the most-parsed key format on the web today: every OAuth and
// OpenID Connect deployment serves a /.well-known/jwks.json, which puts it
// ahead of PEM for anything new.
//
// Parsing a JWK is not enough. The structure carries several claims about
// itself that can disagree, and checking them is format work of exactly the
// kind brainpool demands in DER:
//
//   crv must match kty            an OKP with crv P-256 is nonsense
//   alg must match crv            ES256 is P-256 and nothing else
//   x and y are the field length  a short x is a different point
//   EC without y                  not a point
//   use and key_ops must agree    a key that is "for signing" and also for
//                                 encryption has no single answer
//
// None of that is policy - it is whether the document says one thing or two.
// Deciding whether to TRUST a key is the caller's, and this module does not
// do it.
//
// Everything is base64url: no padding, no whitespace, strict alphabet. RFC
// 7515 appendix C is explicit, and a decoder that accepts padding accepts two
// encodings of one key.

import * as B from './base.js';
import * as JSON_ from './json.js';

import { make_fail_here } from './commons/fail.js';
import { strip_leading_zeros } from './commons/bytes.js';
import { encode_utf8 } from './commons/encode_text.js';

var fail = make_fail_here('jwk');


// ---------------------------------------------------------------------------
// base64url
// ---------------------------------------------------------------------------

// Delegated to base.js. One codec, used by everything that needs it.
//
// The wrapper adds the member NAME to the error, which is what a caller
// actually needs: "x has padding, which base64url omits" points at the field
// to fix, where "bad base64url" leaves them reading the whole document.
//
// RFC 7515 appendix C omits padding, and base.js refuses it for base64url -
// so accepting it here would need an explicit relaxation, and there is none.

function b64url_decode(text, what) {
  if (typeof text !== 'string') {
    fail('bad-base64url', what + ' must be a string');
  }

  try {
    return B.decode('base64url', text);
  } catch (e) {
    var detail = e.message.replace(/^cryptographic-formats: base(64url)?: /, '');
    fail(e.code === 'non-canonical'
      ? 'non-canonical-base64url'
      : 'bad-base64url',
      what + ': ' + detail);
  }
}

function b64url_encode(bytes) {
  return B.encode('base64url', bytes);
}

// ---------------------------------------------------------------------------
// Curve and algorithm tables
// ---------------------------------------------------------------------------

// JWK curve names are not the OID names. "P-256" is secp256r1; keeping the
// mapping explicit means the two vocabularies never get confused for one
// another. RFC 7518 section 6.2.1.1 and RFC 8037.
var EC_CURVES = {
  'P-256':      { oid: 'secp256r1', size: 32 },
  'P-384':      { oid: 'secp384r1', size: 48 },
  'P-521':      { oid: 'secp521r1', size: 66 },
  'secp256k1':  { oid: 'secp256k1', size: 32 }
};

var OKP_CURVES = {
  Ed25519: { oid: 'Ed25519', size: 32 },
  Ed448:   { oid: 'Ed448',   size: 57 },
  X25519:  { oid: 'X25519',  size: 32 },
  X448:    { oid: 'X448',    size: 56 }
};

// Which curve each algorithm identifier requires. RFC 7518 section 3.1 ties
// ES256 to P-256 specifically - the digest size is not the whole story, and a
// key declaring ES256 with crv P-384 is a document contradicting itself.
var ALG_CURVE = {
  ES256:  'P-256',
  ES384:  'P-384',
  ES512:  'P-521',
  ES256K: 'secp256k1',
  EdDSA:  null            // valid for any OKP signing curve
};

var OKP_SIGN   = { Ed25519: true, Ed448: true };
var OKP_DERIVE = { X25519: true, X448: true };

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

// Returns the same shape every other source of a key produces:
//
//   { algorithm, curve, point, scalar, ... }
//
// `curve` is the OID name, not the JWK name, so a key read from a JWK and a
// key read from SPKI compare equal without the caller translating.
function to_key(input) {
  var jwk = typeof input === 'string' || input instanceof Uint8Array
    ? JSON_.parse(input)
    : input;

  if (!jwk || typeof jwk !== 'object') {
    fail('bad-jwk', 'expected a JWK object');
  }

  var kty = JSON_.member(jwk, 'kty');

  if (typeof kty !== 'string') {
    fail('missing-kty', 'a JWK must have a string kty');
  }

  if (kty === 'EC')  { return ec_key(jwk); }
  if (kty === 'OKP') { return okp_key(jwk); }
  if (kty === 'RSA') { return rsa_key(jwk); }
  if (kty === 'oct') {
    fail('symmetric-key',
      'kty "oct" is a symmetric secret, not a key this module returns as a ' +
      'point; read the k member yourself if that is what you want');
  }

  fail('unknown-kty', 'unrecognised kty "' + kty + '"');
}

function ec_key(jwk) {
  var crv = JSON_.member(jwk, 'crv');

  if (typeof crv !== 'string') {
    fail('missing-crv', 'an EC JWK must have a string crv');
  }

  var curve = EC_CURVES[crv];
  if (curve === undefined) {
    // An OKP curve name under kty EC is the specific confusion worth naming,
    // because the two key types look similar and the error is otherwise just
    // "unknown curve".
    if (Object.prototype.hasOwnProperty.call(OKP_CURVES, crv)) {
      fail('kty-crv-mismatch',
        'crv "' + crv + '" belongs to kty OKP, not EC');
    }
    fail('unknown-curve', 'unrecognised EC curve "' + crv + '"');
  }

  check_alg(jwk, crv);
  check_use(jwk);

  var x = required_coordinate(jwk, 'x', curve.size);
  var y = required_coordinate(jwk, 'y', curve.size);

  var point = new Uint8Array(1 + curve.size * 2);
  point[0] = 0x04;
  point.set(x, 1);
  point.set(y, 1 + curve.size);

  var out = {
    algorithm: 'ecPublicKey',
    curve:     curve.oid,
    jwk_curve: crv,
    point:     point,
    scalar:    null,
    private:   false
  };

  with_members(out, jwk, string_member(jwk, 'alg'));

  if (JSON_.has(jwk, 'd')) {
    out.scalar = coordinate(jwk, 'd', curve.size);
    out.private = true;
  }

  return out;
}

function okp_key(jwk) {
  var crv = JSON_.member(jwk, 'crv');

  if (typeof crv !== 'string') {
    fail('missing-crv', 'an OKP JWK must have a string crv');
  }

  var curve = OKP_CURVES[crv];
  if (curve === undefined) {
    if (Object.prototype.hasOwnProperty.call(EC_CURVES, crv)) {
      fail('kty-crv-mismatch',
        'crv "' + crv + '" belongs to kty EC, not OKP');
    }
    fail('unknown-curve', 'unrecognised OKP curve "' + crv + '"');
  }

  // An OKP key carries x only. A y member means the document was written as
  // if it were an EC key, and something upstream has the wrong idea of what
  // this key is.
  if (JSON_.has(jwk, 'y')) {
    fail('unexpected-member',
      'an OKP JWK has no y; only EC keys do');
  }

  var alg = string_member(jwk, 'alg');

  if (alg === 'EdDSA' && !OKP_SIGN[crv]) {
    // X25519 and X448 are key agreement curves. A key declaring EdDSA on one
    // of them cannot sign, whatever the caller does with it.
    fail('alg-crv-mismatch',
      'alg EdDSA needs a signing curve; ' + crv + ' is for key agreement');
  }
  if (alg !== null && alg !== 'EdDSA' && OKP_DERIVE[crv] === undefined) {
    fail('alg-crv-mismatch',
      'alg "' + alg + '" is not defined for OKP curve ' + crv);
  }

  check_use(jwk);

  var out = {
    algorithm: curve.oid,
    curve:     null,
    jwk_curve: crv,
    point:     required_coordinate(jwk, 'x', curve.size),
    scalar:    null,
    private:   false
  };

  with_members(out, jwk, alg);

  if (JSON_.has(jwk, 'd')) {
    out.scalar = coordinate(jwk, 'd', curve.size);
    out.private = true;
  }

  return out;
}

function rsa_key(jwk) {
  if (JSON_.has(jwk, 'crv')) {
    fail('unexpected-member', 'an RSA JWK has no crv');
  }

  check_use(jwk);

  var n = coordinate_any(jwk, 'n');
  var e = coordinate_any(jwk, 'e');

  // RFC 7518 section 6.3.1.1: the modulus is written with no leading zero
  // octet, unlike DER, where a leading zero is required for the sign bit.
  // Carrying one over from a DER parser gives a modulus one byte longer than
  // it should be and a thumbprint that matches nothing.
  if (n.length > 0 && n[0] === 0x00) {
    fail('non-canonical-parameter',
      'n has a leading zero octet; JWK integers are unsigned big-endian ' +
      'with no padding');
  }
  if (e.length > 0 && e[0] === 0x00) {
    fail('non-canonical-parameter', 'e has a leading zero octet');
  }

  var out = {
    algorithm: 'rsaEncryption',
    curve:     null,
    jwk_curve: null,
    point:     null,
    scalar:    null,
    rsa:       { n: n, e: e },
    private:   false
  };

  with_members(out, jwk, string_member(jwk, 'alg'));

  if (JSON_.has(jwk, 'd')) {
    out.rsa.d = coordinate_any(jwk, 'd');
    out.scalar = out.rsa.d;
    out.private = true;

    // RFC 7518 section 6.3.2: if any CRT member is present they must ALL be.
    // A key with p but no q is one no consumer can use, and the failure would
    // surface far from here.
    var crt = ['p', 'q', 'dp', 'dq', 'qi'];
    var present = 0;
    var i;
    for (i = 0; i < crt.length; i++) {
      if (JSON_.has(jwk, crt[i])) { present += 1; }
    }
    if (present > 0 && present < crt.length) {
      fail('incomplete-crt',
        'an RSA private JWK with any of p, q, dp, dq, qi must have all five');
    }
    if (present === crt.length) {
      out.rsa.p  = coordinate_any(jwk, 'p');
      out.rsa.q  = coordinate_any(jwk, 'q');
      out.rsa.dp = coordinate_any(jwk, 'dp');
      out.rsa.dq = coordinate_any(jwk, 'dq');
      out.rsa.qi = coordinate_any(jwk, 'qi');
    }
  }

  return out;
}

// ---------------------------------------------------------------------------
// Consistency checks
// ---------------------------------------------------------------------------

function check_alg(jwk, crv) {
  var alg = JSON_.member(jwk, 'alg');

  if (alg === undefined || alg === null) {
    return;
  }
  if (typeof alg !== 'string') {
    fail('bad-alg', 'alg must be a string');
  }
  if (!Object.prototype.hasOwnProperty.call(ALG_CURVE, alg)) {
    // Not every alg is an EC alg; RS256 on an EC key is a contradiction too.
    fail('alg-crv-mismatch',
      'alg "' + alg + '" is not an EC signing algorithm');
  }

  var required = ALG_CURVE[alg];
  if (required !== null && required !== crv) {
    fail('alg-crv-mismatch',
      'alg ' + alg + ' requires crv ' + required + ', but this key says ' +
      crv);
  }
}

function check_use(jwk) {
  var use = JSON_.member(jwk, 'use');
  var ops = JSON_.member(jwk, 'key_ops');

  if (use !== undefined && use !== null && typeof use !== 'string') {
    fail('bad-use', 'use must be a string');
  }
  if (use === 'sig' || use === 'enc' || use === undefined || use === null) {
    // fine
  } else {
    fail('bad-use', 'use must be "sig" or "enc", got "' + use + '"');
  }

  if (ops === undefined || ops === null) {
    return;
  }
  if (!Array.isArray(ops)) {
    fail('bad-key-ops', 'key_ops must be an array');
  }

  var seen = {};
  var i;
  for (i = 0; i < ops.length; i++) {
    if (typeof ops[i] !== 'string') {
      fail('bad-key-ops', 'key_ops entries must be strings');
    }
    // RFC 7517 section 4.3: duplicates are not allowed. Two entries saying
    // the same thing is the array-shaped version of a duplicate member.
    if (Object.prototype.hasOwnProperty.call(seen, ops[i])) {
      fail('bad-key-ops', 'key_ops contains "' + ops[i] + '" twice');
    }
    seen[ops[i]] = true;
  }

  // RFC 7517 section 4.3: when both appear their meanings must not conflict.
  // A key that is "for signatures" and also permits encryption has no single
  // answer to what it is for.
  if (use === 'sig') {
    if (seen.encrypt || seen.decrypt || seen.wrapKey || seen.unwrapKey) {
      fail('use-key-ops-conflict',
        'use is "sig" but key_ops permits an encryption operation');
    }
  }
  if (use === 'enc') {
    if (seen.sign || seen.verify) {
      fail('use-key-ops-conflict',
        'use is "enc" but key_ops permits a signature operation');
    }
  }
}

function required_coordinate(jwk, name, size) {
  if (!JSON_.has(jwk, name)) {
    fail('missing-member', 'this key type requires a ' + name + ' member');
  }
  return coordinate(jwk, name, size);
}

// RFC 7518 section 6.2.1.2: coordinates are left-padded to the full field
// length. A short x is not the same point written compactly - it is a
// different value, and the padding is what makes two keys comparable.
function coordinate(jwk, name, size) {
  var bytes = b64url_decode(JSON_.member(jwk, name), name);

  if (bytes.length !== size) {
    fail('bad-coordinate-length',
      name + ' is ' + bytes.length + ' bytes; this curve requires ' + size +
      ', zero-padded on the left');
  }
  return bytes;
}

function coordinate_any(jwk, name) {
  if (!JSON_.has(jwk, name)) {
    fail('missing-member', 'this key type requires a ' + name + ' member');
  }
  return b64url_decode(JSON_.member(jwk, name), name);
}

// The members every key type reports the same way. Three copies, one per
// key type, before - which is how a fourth member gets added to two of them.
function with_members(out, jwk, alg) {
  out.kid = string_member(jwk, 'kid');
  out.use = string_member(jwk, 'use');
  out.alg = alg;
  out.key_ops = JSON_.member(jwk, 'key_ops') || null;
  return out;
}

function string_member(jwk, name) {
  var v = JSON_.member(jwk, name);
  if (v === undefined || v === null) {
    return null;
  }
  if (typeof v !== 'string') {
    fail('bad-member', name + ' must be a string');
  }
  return v;
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

var OID_TO_JWK = {
  secp256r1: 'P-256',
  secp384r1: 'P-384',
  secp521r1: 'P-521',
  secp256k1: 'secp256k1'
};

// ⚠ `from_key` MEANS "FROM A KEY", AND READS BACKWARDS TO EVERY OTHER
//    from_* IN THE LIBRARY.
//
//   spki.from_der(bytes)   consumes DER      -> a key
//   jwk.from_key(key)      consumes a key    -> a JWK
//
// Both mean "from X", so the naming is exactly consistent - and the eye
// reads the first as "produce the thing this module is about" and the second
// as the same, which puts the direction the wrong way round.
//
// Kept because the alternative is worse: `to_jwk` and `from_jwk` inside a
// module CALLED jwk reads as though the module converts to and from itself,
// and every caller writes `jwk.to_jwk(key)`.
//
// The pairing is from_key/to_key and it is symmetric: from_key(to_key(j))
// returns j, and to_key(from_key(k)) returns k.
function from_key(key) {
  if (!key || typeof key.algorithm !== 'string') {
    fail('bad-key', 'expected a key object with an algorithm');
  }

  if (key.algorithm === 'ecPublicKey') {
    return ec_to_jwk(key);
  }
  if (Object.prototype.hasOwnProperty.call(OKP_CURVES, key.algorithm)) {
    return okp_to_jwk(key);
  }
  if (key.algorithm === 'rsaEncryption') {
    return rsa_to_jwk(key);
  }

  fail('unsupported-algorithm',
    'cannot write algorithm ' + key.algorithm + ' as a JWK');
}

function ec_to_jwk(key) {
  var crv = OID_TO_JWK[key.curve];

  if (crv === undefined) {
    // brainpool has no registered JWK curve name. Inventing one would produce
    // a document nothing else can read, and silently substituting P-256
    // because the sizes match would produce a key on the wrong curve.
    fail('no-jwk-curve',
      'curve ' + key.curve + ' has no registered JWK name; JOSE defines ' +
      'P-256, P-384, P-521 and secp256k1 only');
  }

  var size = EC_CURVES[crv].size;

  if (!key.point || key.point.length !== 1 + size * 2) {
    fail('bad-point',
      'expected an uncompressed point of ' + (1 + size * 2) + ' bytes');
  }
  if (key.point[0] !== 0x04) {
    fail('bad-point',
      'JWK carries x and y separately, so the point must be uncompressed; ' +
      'decompress it with cryptographic-primitives first');
  }

  var out = {
    kty: 'EC',
    crv: crv,
    x: b64url_encode(key.point.subarray(1, 1 + size)),
    y: b64url_encode(key.point.subarray(1 + size))
  };

  if (key.scalar) {
    out.d = b64url_encode(key.scalar);
  }
  if (key.kid) { out.kid = key.kid; }

  return out;
}

function okp_to_jwk(key) {
  var out = {
    kty: 'OKP',
    crv: key.algorithm,
    x: b64url_encode(key.point)
  };

  if (key.scalar) { out.d = b64url_encode(key.scalar); }
  if (key.kid)    { out.kid = key.kid; }

  return out;
}

function rsa_to_jwk(key) {
  if (!key.rsa || !key.rsa.n || !key.rsa.e) {
    fail('bad-key', 'an RSA key needs n and e');
  }

  // Strip the DER sign octet. Leaving it produces a modulus one byte longer
  // than the spec allows and a thumbprint that matches nothing.
  var out = {
    kty: 'RSA',
    n: b64url_encode(strip_leading_zeros(key.rsa.n)),
    e: b64url_encode(strip_leading_zeros(key.rsa.e))
  };

  if (key.rsa.d) { out.d = b64url_encode(strip_leading_zeros(key.rsa.d)); }
  if (key.kid)   { out.kid = key.kid; }

  return out;
}


// ---------------------------------------------------------------------------
// Key sets
// ---------------------------------------------------------------------------

// A JWKS is what /.well-known/jwks.json serves. Selecting by kid is format
// work; two members sharing a kid is a malformed set rather than a policy
// question, because the selection has no single answer.
function set_from_json(input) {
  var doc = typeof input === 'string' || input instanceof Uint8Array
    ? JSON_.parse(input)
    : input;

  var keys = JSON_.member(doc, 'keys');

  if (!Array.isArray(keys)) {
    fail('bad-jwks', 'a JWK Set must have a keys array');
  }

  var out = [];
  var seen = {};
  var i;

  for (i = 0; i < keys.length; i++) {
    var kid = JSON_.member(keys[i], 'kid');

    if (typeof kid === 'string') {
      if (Object.prototype.hasOwnProperty.call(seen, kid)) {
        fail('duplicate-kid',
          'two keys share kid "' + kid + '"; selection by kid has no single ' +
          'answer in this set');
      }
      seen[kid] = true;
    }

    out.push(keys[i]);
  }

  return out;
}

// Returns the raw JWK for a kid, or null. Parsing it is a separate step so
// that one bad key in a set does not make the whole set unreadable - a JWKS
// often carries algorithms a given consumer does not support.
function set_find(input, kid) {
  var keys = set_from_json(input);
  var i;

  for (i = 0; i < keys.length; i++) {
    if (JSON_.member(keys[i], 'kid') === kid) {
      return keys[i];
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Thumbprint - RFC 7638
// ---------------------------------------------------------------------------

// The members a thumbprint covers, by kty: RFC 7638 3.2 for EC, RSA and oct,
// RFC 8037 2 for OKP.
var THUMBPRINT_MEMBERS = {
  EC:  ['crv', 'kty', 'x', 'y'],
  RSA: ['e', 'kty', 'n'],
  oct: ['k', 'kty'],
  OKP: ['crv', 'kty', 'x']
};

// ⚠ WHAT A JWK THUMBPRINT IS THE HASH OF - the caller hashes it (SHA-256
// for ACME's key authorization, RFC 8555 8.1) and base64url-encodes the
// digest. RFC 7638 3: the REQUIRED members only, in lexicographic order, no
// whitespace, as UTF-8. Anything else - kid, alg, use, d - is left out, so
// a public key and its private JWK have the same thumbprint.
//
// Takes a JWK object or its JSON text.
function thumbprint_input(jwk) {
  var j = typeof jwk === 'string' ? JSON_.parse(jwk) : jwk;

  if (!j || typeof j !== 'object' || Array.isArray(j)) {
    fail('bad-jwk', 'a JWK is a JSON object');
  }

  var kty = JSON_.member(j, 'kty');
  var names = Object.prototype.hasOwnProperty.call(THUMBPRINT_MEMBERS, kty)
    ? THUMBPRINT_MEMBERS[kty] : null;

  if (names === null) {
    fail('unsupported-kty', 'no thumbprint members are defined for kty ' +
      JSON.stringify(kty) + ' (EC, RSA, oct, OKP)');
  }

  var parts = names.map(function (n) {
    var v = JSON_.member(j, n);
    if (typeof v !== 'string') {
      fail('missing-member', 'a ' + kty + ' thumbprint needs "' + n + '" as a string');
    }
    return JSON.stringify(n) + ':' + JSON.stringify(v);
  });

  return new Uint8Array(encode_utf8('{' + parts.join(',') + '}', fail));
}

export {
  thumbprint_input,
  to_key,
  from_key,
  set_from_json,
  set_find,
  EC_CURVES,
  OKP_CURVES
};
