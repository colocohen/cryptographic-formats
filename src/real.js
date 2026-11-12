// ASN.1 REAL, X.690 section 8.5 and DER's restrictions in 11.3.
//
// The most complicated type in the universal class, and the one most often
// left out - which is why it has its own file rather than adding a hundred
// lines to der_reader and der_writer each.
//
// ⚠ THE READER AND THE WRITER ARE BOTH HERE, WHICH LOOKS LIKE IT BREAKS THE
// RULE. It does not, and the reason is worth stating.
//
// The rule in commons/README.md is that a helper may not be SHARED between a
// reader and its writer, because one bug then appears in both directions and
// cancels on a round trip. These two functions share NOTHING: they are in one
// file because REAL's three encoding forms are one subject, and the file is
// arranged so that is visible - no common helper, no common table, and a
// test that asserts the encoder's output against byte strings from X.690
// rather than against the decoder.
//
// THREE FORMS, and DER permits one of them:
//
//   binary        first octet has bit 8 set. mantissa x base^exponent
//   decimal       first octet is 0x00-0x03. ISO 6093 text
//   special       first octet is 0x40-0x43. infinity, NaN, minus zero
//
// X.690 11.3.1: DER requires the BINARY form for any non-zero value, with
// base 2, and the mantissa ODD or the whole value zero. That last rule is
// what makes the encoding unique - without it, 2 x 2^1 and 1 x 2^2 are two
// encodings of 4.

import * as T from './tags.js';
import { make_fail } from './commons/fail.js';
import { make_fail_here } from './commons/fail.js';
import { to_array } from './commons/bytes.js';

var fail_read = make_fail('der');
var fail_write = make_fail_here('der');

// Special values, X.690 8.5.9.
var PLUS_INFINITY  = 0x40;
var MINUS_INFINITY = 0x41;
var NOT_A_NUMBER   = 0x42;
var MINUS_ZERO     = 0x43;

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

// Takes the content octets of a REAL and returns a JavaScript number.
//
// Zero is the EMPTY content - X.690 8.5.2 - which is the one case where a
// value has no octets at all, and a decoder that treats an empty value as an
// error rejects zero.
function decode(bytes, pos, strict) {
  if (bytes.length === 0) {
    return 0;
  }

  var first = bytes[0];

  // --- special values ----------------------------------------------------
  if ((first & 0xC0) === 0x40) {
    if (bytes.length !== 1) {
      fail_read(pos, 'bad-real',
        'a special REAL value has exactly one content octet');
    }
    if (first === PLUS_INFINITY)  { return Infinity; }
    if (first === MINUS_INFINITY) { return -Infinity; }
    if (first === NOT_A_NUMBER)   { return NaN; }
    if (first === MINUS_ZERO)     { return -0; }

    fail_read(pos, 'bad-real',
      'unrecognised special REAL value 0x' + first.toString(16));
  }

  // --- decimal form ------------------------------------------------------
  if ((first & 0x80) === 0) {
    if (strict) {
      // X.690 11.3.1: DER uses the binary form. The decimal form is ISO 6093
      // text, and the same number has many spellings in it - "1.5", "1.5E0",
      // "0.15E1" - so a signature over a decimal REAL covers one of them.
      fail_read(pos, 'decimal-real',
        'the decimal REAL form is BER; DER requires the binary form');
    }
    return decode_decimal(bytes, pos);
  }

  // --- binary form -------------------------------------------------------
  return decode_binary(bytes, pos, strict);
}

// X.690 8.5.7. The first octet packs sign, base, scale factor and how the
// exponent is carried.
function decode_binary(bytes, pos, strict) {
  var first = bytes[0];
  var sign = (first & 0x40) ? -1 : 1;

  var base_bits = (first >> 4) & 0x03;
  var base;

  if (base_bits === 0)      { base = 2; }
  else if (base_bits === 1) { base = 8; }
  else if (base_bits === 2) { base = 16; }
  else {
    fail_read(pos, 'bad-real', 'base bits 11 are reserved');
  }

  if (strict && base !== 2) {
    // X.690 11.3.1: DER fixes the base at 2. Bases 8 and 16 are the same
    // value written with a different exponent, which is a second encoding.
    fail_read(pos, 'non-canonical-real',
      'DER requires base 2, this REAL uses base ' + base);
  }

  var scale = (first >> 2) & 0x03;

  if (strict && scale !== 0) {
    // The scale factor multiplies the mantissa by 2^scale, which duplicates
    // what the exponent already does.
    fail_read(pos, 'non-canonical-real',
      'DER requires a scale factor of 0, this REAL has ' + scale);
  }

  var exp_format = first & 0x03;
  var exp_len;
  var at = 1;

  if (exp_format === 0)      { exp_len = 1; }
  else if (exp_format === 1) { exp_len = 2; }
  else if (exp_format === 2) { exp_len = 3; }
  else {
    // Format 3: the next octet holds the exponent length.
    if (bytes.length < 2) {
      fail_read(pos, 'bad-real', 'REAL is truncated before its exponent');
    }
    exp_len = bytes[1];
    at = 2;

    if (exp_len < 4) {
      // A long-form exponent that would have fitted in a short form is a
      // second encoding.
      fail_read(pos, 'non-canonical-real',
        'an exponent of ' + exp_len + ' octets must use the short form');
    }
  }

  if (at + exp_len > bytes.length) {
    fail_read(pos, 'bad-real', 'REAL exponent runs past the content');
  }

  // The exponent is two's complement.
  var exponent = 0;
  var i;

  for (i = 0; i < exp_len; i++) {
    exponent = (exponent * 256) + bytes[at + i];
  }
  if (bytes[at] & 0x80) {
    exponent -= Math.pow(256, exp_len);
  }

  if (exp_len > 1) {
    // A leading 0x00 or 0xFF that the sign does not require is padding.
    var lead = bytes[at];
    var next = bytes[at + 1];
    if ((lead === 0x00 && (next & 0x80) === 0) ||
        (lead === 0xFF && (next & 0x80) !== 0)) {
      fail_read(pos, 'non-canonical-real',
        'the REAL exponent has a superfluous leading octet');
    }
  }

  at += exp_len;

  if (at >= bytes.length) {
    fail_read(pos, 'bad-real', 'REAL has no mantissa');
  }

  var mantissa = 0;
  for (i = at; i < bytes.length; i++) {
    mantissa = (mantissa * 256) + bytes[i];
  }

  if (mantissa === 0) {
    // Zero is the empty encoding, so a mantissa of zero in the binary form
    // is a second way of writing it.
    fail_read(pos, 'non-canonical-real',
      'zero is encoded with no content octets, not with a zero mantissa');
  }

  if (strict && (mantissa % 2) === 0) {
    // ⚠ THE RULE THAT MAKES THE ENCODING UNIQUE. X.690 11.3.1: the mantissa
    // must be odd. Without it, 2 x 2^1 and 1 x 2^2 are two encodings of 4,
    // and the value is malleable in a signed structure.
    fail_read(pos, 'non-canonical-real',
      'DER requires an odd mantissa; this one is even, so the same value ' +
      'has another encoding with the exponent shifted');
  }

  return sign * mantissa * Math.pow(base, exponent) *
    Math.pow(2, scale);
}

// ISO 6093, three number forms distinguished by the first octet. Read only
// under BER - see the refusal above.
function decode_decimal(bytes, pos) {
  var form = bytes[0] & 0x3F;

  if (form < 1 || form > 3) {
    fail_read(pos, 'bad-real',
      'unrecognised decimal REAL form ' + form);
  }

  var s = '';
  var i;

  for (i = 1; i < bytes.length; i++) {
    s += String.fromCharCode(bytes[i]);
  }

  // ISO 6093 uses a comma or a full stop for the decimal mark.
  var value = Number(s.replace(/,/g, '.').replace(/^\s+|\s+$/g, ''));

  if (!isFinite(value) && !/^[-+]?(inf|nan)/i.test(s)) {
    fail_read(pos, 'bad-real', 'malformed decimal REAL "' + s + '"');
  }

  return value;
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

// Emits the ONE form DER permits. Nothing here is shared with the decoder
// above: the special-value constants are read from the same names, which are
// declarations rather than logic, and every rule is applied again.
function encode(value) {
  if (typeof value !== 'number') {
    fail_write('bad-real', 'expected a number');
  }

  if (isNaN(value)) {
    return [NOT_A_NUMBER];
  }
  if (value === Infinity) {
    return [PLUS_INFINITY];
  }
  if (value === -Infinity) {
    return [MINUS_INFINITY];
  }

  // Object.is distinguishes -0 from 0, which === does not - and X.690 gives
  // them different encodings.
  if (Object.is(value, -0)) {
    return [MINUS_ZERO];
  }
  if (value === 0) {
    // X.690 8.5.2: zero has NO content octets.
    return [];
  }

  var sign = value < 0 ? 1 : 0;

  // The mantissa and exponent are taken from the IEEE-754 bits rather than
  // found by multiplying and dividing.
  //
  // The loop version worked for ordinary values and failed on large ones -
  // 6.02e23 has an exact 53-bit mantissa and an exponent of 26, and reaching
  // it by repeated halving overflows the safe integer range on the way. The
  // bits already hold exactly what the encoding needs.
  var view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, Math.abs(value));

  var high = view.getUint32(0);
  var low = view.getUint32(4);
  var biased = (high >>> 20) & 0x7FF;

  // 52 fraction bits, plus the implicit leading 1 for a normal number.
  var frac_high = high & 0xFFFFF;
  var mantissa = frac_high * 0x100000000 + low;
  var exponent;

  if (biased === 0) {
    // Subnormal: no implicit leading bit, and the exponent is fixed.
    exponent = -1074;
  } else {
    mantissa += 0x10000000000000;      // the implicit 1, at bit 52
    exponent = biased - 1075;          // 1023 bias, minus the 52 fraction bits
  }

  // ⚠ The rule that makes the encoding unique: halve until the mantissa is
  // ODD. Without it, 2 x 2^1 and 1 x 2^2 are two encodings of 4.
  while (mantissa > 0 && (mantissa % 2) === 0) {
    mantissa /= 2;
    exponent += 1;
  }

  var mantissa_bytes = unsigned_bytes(mantissa);
  var exponent_bytes = twos_complement_bytes(exponent);

  var first = 0x80 | (sign << 6);
  var out;

  if (exponent_bytes.length === 1) {
    out = [first];
  } else if (exponent_bytes.length === 2) {
    out = [first | 0x01];
  } else if (exponent_bytes.length === 3) {
    out = [first | 0x02];
  } else {
    out = [first | 0x03, exponent_bytes.length];
  }

  return out.concat(exponent_bytes).concat(mantissa_bytes);
}

function unsigned_bytes(n) {
  var out = [];
  var v = n;

  while (v > 0) {
    out.unshift(v % 256);
    v = Math.floor(v / 256);
  }
  return out.length === 0 ? [0] : out;
}

// Two's complement, in the fewest octets that hold the value with its sign.
function twos_complement_bytes(n) {
  if (n >= -128 && n <= 127) {
    return [n & 0xFF];
  }
  if (n >= -32768 && n <= 32767) {
    return [(n >> 8) & 0xFF, n & 0xFF];
  }
  if (n >= -8388608 && n <= 8388607) {
    return [(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF];
  }
  return [(n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF];
}

export {
  decode,
  encode,
  PLUS_INFINITY,
  MINUS_INFINITY,
  NOT_A_NUMBER,
  MINUS_ZERO
};
