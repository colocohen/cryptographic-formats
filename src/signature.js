// Signature encodings.
//
// ⚠ ONE ALGORITHM NEEDS A CONVERSION AND THE OTHERS DO NOT, AND SAYING SO IS
//    HALF THE POINT OF THIS MODULE.
//
//   ECDSA    r||s in JOSE, COSE, WebAuthn and SSH
//            SEQUENCE { r, s } in X.509, CMS, TSP, OCSP, CRL, CMP, CRMF,
//            attribute certificates and SCTs
//            -> NINE modules on one side, four on the other. Every WebAuthn
//               assertion checked against a certificate crosses it.
//
//   EdDSA    64 bytes, raw, EVERYWHERE - including inside X.509. There is
//            nothing to convert, and a caller who writes a converter for it
//            has written the identity function.
//
//   RSA      a fixed-width big-endian integer, key-sized, which goes into a
//            BIT STRING unchanged. PKCS#1 v1.5 and PSS both produce that.
//            Again nothing to convert.
//
// So `describe` answers the question before a caller reaches for a function
// that should not exist.
//
// ⚠ AND THIS IS WHERE cryptographic-primitives BROKE.
//
// `sig_to_der` wrote a short-form length of 135 for a P-521 signature, which
// is not DER at all - and it went unnoticed because the decoder was equally
// wrong in the other direction. Four things have to be right at once here,
// and each of them looks fine on its own:
//
//   1. TWO OPPOSITE PADDING RULES. Raw left-pads to a fixed width; DER
//      STRIPS leading zeros and adds one back only when the top bit is set,
//      to keep the INTEGER positive.
//   2. THE WIDTH COMES FROM THE CURVE, not from the input. An r of 31 bytes
//      is ordinary, and taking the width from it gives a 62-byte raw
//      signature that verifies nowhere.
//   3. P-521 IS 66 BYTES, not 64. That is the number sig_to_der got wrong.
//   4. THE UNSIGNED WRITER, not the integer one. W.integer on bytes with the
//      top bit set writes a NEGATIVE integer - one byte shorter, and it
//      looks right.

import * as DER from './der_reader.js';
import * as W from './der_writer.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, hex, strip_leading_zeros } from './commons/bytes.js';
import { CURVE_SIZE } from './ec_domain.js';

var fail = make_fail_here('signature');

// ---------------------------------------------------------------------------
// What needs converting
// ---------------------------------------------------------------------------

// ⚠ ANSWERED BEFORE A CALLER REACHES FOR A FUNCTION THAT SHOULD NOT EXIST.
//
// Somebody holding an Ed25519 signature and a certificate will look for a
// converter, because ECDSA needed one. This says there is nothing to do.
var ALGORITHMS = {
  ecdsa: {
    converts: true,
    raw:  'r||s, each left-padded to the curve size',
    der:  'SEQUENCE { r INTEGER, s INTEGER }',
    note: 'the two encodings differ, and every format in this library uses ' +
          'one or the other'
  },
  eddsa: {
    converts: false,
    raw:  '64 bytes for Ed25519, 114 for Ed448',
    der:  'the same 64 or 114 bytes',
    note: 'RFC 8032 signatures are raw everywhere, INCLUDING inside X.509 - ' +
          'there is nothing to convert'
  },
  rsa: {
    converts: false,
    raw:  'a fixed-width big-endian integer, the size of the modulus',
    der:  'the same bytes, in a BIT STRING',
    note: 'PKCS#1 v1.5 and PSS both produce a fixed-width byte string that ' +
          'goes into a BIT STRING unchanged'
  },
  dsa: {
    converts: true,
    raw:  'r||s, each the size of the subgroup order q',
    der:  'SEQUENCE { r INTEGER, s INTEGER }',
    // ⚠ DSA's raw width comes from q, NOT from p - a 2048-bit key with a
    // 256-bit q has 32-byte halves, and taking the width from p would give
    // 256 and pad every signature into nonsense.
    note: 'the same shape as ECDSA, but the width comes from the SUBGROUP ' +
          'order q rather than from the key size'
  }
};

// Whether an algorithm needs a conversion at all.
function describe(algorithm) {
  var spec = ALGORITHMS[normalise(algorithm)];

  if (spec === undefined) {
    fail('unknown-algorithm',
      'no encoding rule for "' + algorithm + '". The families are ecdsa, ' +
      'eddsa, rsa and dsa.');
  }

  return spec;
}

// `ES256`, `ecdsaWithSHA256`, `ecdsa` and `EC` all mean the same family here.
function normalise(name) {
  var s = String(name).toLowerCase();

  if (/^es\d|ecdsa|^ec$/.test(s)) { return 'ecdsa'; }
  if (/eddsa|ed25519|ed448/.test(s)) { return 'eddsa'; }
  if (/^rs\d|^ps\d|rsa/.test(s)) { return 'rsa'; }
  if (/^dsa|dsawith/.test(s)) { return 'dsa'; }

  return s;
}

// ---------------------------------------------------------------------------
// The width
// ---------------------------------------------------------------------------

// ⚠ THE WIDTH COMES FROM THE CURVE AND NOWHERE ELSE.
//
// Not from the signature, whose halves vary; not from the key, whose
// encoding differs. An r of 31 bytes is ordinary - one signature in 256 has
// one - and taking the width from it produces a 62-byte raw signature that
// verifies nowhere and looks almost right.
function width_for(options) {
  if (options.size !== undefined && options.size !== null) {
    if (typeof options.size !== 'number' || options.size < 1) {
      fail('bad-size', 'size must be a positive number of bytes');
    }
    return options.size;
  }

  if (options.curve === undefined || options.curve === null) {
    fail('no-curve',
      'raw_to_der and der_to_raw need { curve } - the width of each half ' +
      'comes from the curve and cannot be worked out from the signature. ' +
      'For DSA, pass { size } instead: the width is the size of q.');
  }

  var size = CURVE_SIZE[options.curve];

  if (size === undefined) {
    fail('unknown-curve',
      'no size for curve "' + options.curve + '". Pass { size } if you ' +
      'know it.');
  }

  return size;
}

// ---------------------------------------------------------------------------
// DER to raw
// ---------------------------------------------------------------------------

// Converts SEQUENCE { r, s } to the fixed-width r||s that JOSE, COSE,
// WebAuthn and SSH use.
//
//   signature.der_to_raw({ der: bytes, curve: 'secp256r1' })
function der_to_raw(options) {
  check_options(options, 'der_to_raw', 'der');

  var size = width_for(options);
  var pair = parse_der({ der: options.der });

  if (pair.r.length > size || pair.s.length > size) {
    fail('value-too-large',
      'a half is ' + Math.max(pair.r.length, pair.s.length) +
      ' bytes and the curve size is ' + size +
      '. Either the curve is wrong or this is not a signature for it.');
  }

  // ⚠ LEFT-PAD. The raw form is fixed-width, so a 31-byte r gets a leading
  // zero - the opposite of what DER does, which strips them.
  var out = new Uint8Array(size * 2);
  out.set(pair.r, size - pair.r.length);
  out.set(pair.s, size * 2 - pair.s.length);

  return out;
}

// ---------------------------------------------------------------------------
// Raw to DER
// ---------------------------------------------------------------------------

//   signature.raw_to_der({ raw: bytes, curve: 'secp256r1' })
function raw_to_der(options) {
  check_options(options, 'raw_to_der', 'raw');

  var raw = to_bytes(options.raw);
  var size = width_for(options);

  if (raw.length !== size * 2) {
    fail('bad-length',
      'a raw ' + (options.curve || 'signature') + ' is ' + (size * 2) +
      ' bytes, got ' + raw.length +
      (raw.length === 64 && size === 66
        ? '. P-521 halves are 66 bytes, not 64 - that is the mistake ' +
          'sig_to_der made.'
        : ''));
  }

  return pair_der(raw.subarray(0, size), raw.subarray(size));
}

// ⚠ SEQUENCE { INTEGER r, INTEGER s }, WRITTEN DIRECTLY.
//
// Both halves are UNSIGNED: leading zeros stripped, and a zero put back
// when the top bit is set - W.integer would write a negative number one
// byte short, and it looks correct. This went through the general writer
// (W.sequence of W.unsigned, arrays and concatenation) and cost 3.8us for
// 70 bytes - a third of node's whole ECDSA signature, on every TLS
// handshake lemon-tls makes (DECISIONS 41). The bytes are the same: the
// test compares them with W's for every width.
function pair_der(r, s) {
  var a = strip_leading_zeros(to_bytes(r));
  var b = strip_leading_zeros(to_bytes(s));
  var pa = a.length === 0 || (a[0] & 0x80) !== 0 ? 1 : 0;
  var pb = b.length === 0 || (b[0] & 0x80) !== 0 ? 1 : 0;
  var la = a.length + pa;
  var lb = b.length + pb;
  var ha = W.encode_length(la);
  var hb = W.encode_length(lb);
  var inner = 2 + ha.length - 1 + la + 2 + hb.length - 1 + lb;
  var hs = W.encode_length(inner);
  var out = new Uint8Array(1 + hs.length + inner);
  var i = 0;
  var k;
  out[i++] = 0x30;
  for (k = 0; k < hs.length; k++) { out[i++] = hs[k]; }
  out[i++] = 0x02;
  for (k = 0; k < ha.length; k++) { out[i++] = ha[k]; }
  if (pa) { out[i++] = 0; }
  out.set(a, i); i += a.length;
  out[i++] = 0x02;
  for (k = 0; k < hb.length; k++) { out[i++] = hb[k]; }
  if (pb) { out[i++] = 0; }
  out.set(b, i);
  return out;
}

// ---------------------------------------------------------------------------
// The pair
// ---------------------------------------------------------------------------

// The two halves, as they appear - stripped, which is how DER carries them.
//
//   signature.parse_der({ der: bytes })
function parse_der(options) {
  check_options(options, 'parse_der', 'der');

  var bytes = to_bytes(options.der);

  return DER.read(bytes, function (reader) {
    var seq = reader.read_sequence();
    var r = seq.read_unsigned();
    var s = seq.read_unsigned();
    seq.expect_end();

    if (r.length === 0 || s.length === 0) {
      fail('empty-half', 'a signature half has no content octets');
    }

    return { r: r, s: s };
  });
}

// The reverse, for a caller who has the halves already.
//
//   signature.from_pair({ r: bytes, s: bytes })
function from_pair(options) {
  if (options === null || typeof options !== 'object') {
    fail('bad-options', 'from_pair takes { r, s }');
  }
  if (options.r === undefined || options.s === undefined) {
    fail('bad-options', 'from_pair needs both r and s');
  }

  return pair_der(options.r, options.s);
}

// ---------------------------------------------------------------------------


// ⚠ ONE OBJECT ARGUMENT, AND A POSITIONAL CALL IS REFUSED RATHER THAN
//    MISREAD.
//
// `der_to_raw(bytes, 'secp256r1')` would read `bytes.der` as undefined and
// fail somewhere further in with a message about the wrong thing. Catching
// the shape here says what to write instead.
function check_options(options, name, field) {
  if (options instanceof Uint8Array ||
      (typeof Buffer !== 'undefined' && Buffer.isBuffer(options)) ||
      Array.isArray(options)) {
    fail('positional-call',
      name + ' takes one object: ' + name + '({ ' + field +
      ': bytes, curve: "secp256r1" })');
  }

  if (options === null || typeof options !== 'object') {
    fail('bad-options',
      name + ' takes one object: ' + name + '({ ' + field +
      ': bytes, curve: "secp256r1" })');
  }

  if (options[field] === undefined || options[field] === null) {
    fail('missing-' + field,
      name + ' needs { ' + field + ': bytes }');
  }
}

export {
  der_to_raw,
  raw_to_der,
  parse_der,
  from_pair,
  describe,
  ALGORITHMS
};
