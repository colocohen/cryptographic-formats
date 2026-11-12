// CBOR writer, emitting only the deterministic form of RFC 8949 section
// 4.2.1.
//
// As with der_writer, this file shares NOTHING with cbor_reader beyond the
// major-type constants, which are duplicated here rather than imported so
// that even they cannot become a shared mistake. A shared head-encoding
// helper would put one bug in both directions, where it cancels itself out on
// a round trip and leaves a green test over an encoder that is wrong.
//
// There is no non-deterministic mode. A flag for it would be switched on
// somewhere, and COSE signs these bytes.


import { to_bytes, to_array, append } from './commons/bytes.js';
import { encode_utf8 } from './commons/encode_text.js';
import { make_fail_here } from './commons/fail.js';

var fail = make_fail_here('cbor');


var UNSIGNED = 0;
var NEGATIVE = 1;
var BYTES    = 2;
var TEXT     = 3;
var ARRAY    = 4;
var MAP      = 5;
var TAG      = 6;
var SIMPLE   = 7;

// ---------------------------------------------------------------------------
// Head
// ---------------------------------------------------------------------------

// The initial byte and its argument, always in the shortest form that holds
// the value. Written out rather than shared with the reader: this is the
// single place the shortest-form rule is applied on output, and the reader
// has its own.
function head(major, value) {
  if (value < 0 || !isFinite(value)) {
    fail('bad-argument', 'argument must be a non-negative finite number');
  }
  if (value > Number.MAX_SAFE_INTEGER) {
    fail('value-too-large',
      'argument exceeds the exactly representable range');
  }

  var m = major << 5;

  if (value < 24) {
    return [m | value];
  }
  if (value < 0x100) {
    return [m | 24, value];
  }
  if (value < 0x10000) {
    return [m | 25, (value >> 8) & 0xFF, value & 0xFF];
  }
  if (value < 0x100000000) {
    return [m | 26,
      (value >>> 24) & 0xFF, (value >>> 16) & 0xFF,
      (value >>> 8) & 0xFF, value & 0xFF];
  }

  var high = Math.floor(value / 0x100000000);
  var low  = value % 0x100000000;
  return [m | 27,
    (high >>> 24) & 0xFF, (high >>> 16) & 0xFF,
    (high >>> 8) & 0xFF, high & 0xFF,
    (low >>> 24) & 0xFF, (low >>> 16) & 0xFF,
    (low >>> 8) & 0xFF, low & 0xFF];
}

// ---------------------------------------------------------------------------
// Scalars
// ---------------------------------------------------------------------------

function unsigned(n) {
  if (n < 0) {
    fail('bad-argument', 'unsigned cannot hold ' + n);
  }
  return head(UNSIGNED, n);
}

// Major type 1 holds -1 minus the value, so -1 is written with argument 0.
function negative(n) {
  if (n >= 0) {
    fail('bad-argument', 'negative cannot hold ' + n);
  }
  return head(NEGATIVE, -1 - n);
}

function int(n) {
  if (!isFinite(n) || Math.floor(n) !== n) {
    fail('bad-argument', 'int needs a whole number, got ' + n);
  }
  return n < 0 ? negative(n) : unsigned(n);
}

function bytes(value) {
  var b = to_array(value);
  return head(BYTES, b.length).concat(b);
}

function text(value) {
  var b = encode_utf8(String(value), fail);
  return head(TEXT, b.length).concat(b);
}

function bool(value) {
  return [(SIMPLE << 5) | (value ? 21 : 20)];
}

// An unassigned simple value, RFC 8949 table 4. Below 20 it goes in the
// initial byte; 32 to 255 take the one-byte form. 20 to 31 are false, true,
// null, undefined, the float widths and the break, so a caller asking for
// one of those is asking for something else by mistake.
function simple(value) {
  if (typeof value !== 'number' || value < 0 || value > 255 ||
      Math.floor(value) !== value) {
    fail('bad-simple', 'a simple value is 0 to 255');
  }

  if (value >= 20 && value <= 31) {
    fail('reserved-simple',
      'simple value ' + value + ' is assigned: 20 to 23 are false, true, ' +
      'null and undefined, 24 to 27 are the argument and float widths, and ' +
      '28 to 31 are reserved. Use the named writer for what you mean.');
  }

  if (value < 20) {
    return [0xE0 | value];
  }

  return [0xF8, value];
}

function null_() {
  return [(SIMPLE << 5) | 22];
}

function undefined_() {
  return [(SIMPLE << 5) | 23];
}

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

function array(members) {
  var out = head(ARRAY, members.length);
  var i;
  for (i = 0; i < members.length; i++) {
    append(out, members[i]);
  }
  return out;
}

// Takes [encoded_key, encoded_value] pairs and SORTS them, so an unsorted map
// is not something this writer can emit. Leaving the order to the caller
// would make determinism a thing they have to remember, and COSE signs these
// bytes.
function map(pairs) {
  var sorted = pairs.slice().sort(function (a, b) {
    return compare(a[0], b[0]);
  });

  var i;
  for (i = 1; i < sorted.length; i++) {
    if (compare(sorted[i - 1][0], sorted[i][0]) === 0) {
      fail('duplicate-key', 'two entries encode to the same map key');
    }
  }

  var out = head(MAP, sorted.length);
  for (i = 0; i < sorted.length; i++) {
    append(append(out, sorted[i][0]), sorted[i][1]);
  }
  return out;
}

// ⚠ DELIBERATELY NOT SHARED. There are four copies of this comparison in the
// library - two in each direction - and jscpd will flag them forever.
//
// The writer SORTS with it; the reader VALIDATES the order with it. A version
// that compared length before content would make the writer emit a "sorted"
// set that the reader accepts and every external tool rejects, and the round
// trip would pass. That is the sig_to_der failure in a smaller package.
//
// See src/commons/README.md.
function compare(a, b) {
  var n = Math.min(a.length, b.length);
  var i;
  for (i = 0; i < n; i++) {
    if (a[i] !== b[i]) {
      return a[i] - b[i];
    }
  }
  return a.length - b.length;
}

function tag(number, encoded_value) {
  return head(TAG, number).concat(encoded_value);
}

// ---------------------------------------------------------------------------
// Floats
// ---------------------------------------------------------------------------

// Deterministic CBOR requires the shortest width that holds the value
// exactly. Writing a double where a half would do is a second encoding.
function float(value) {
  if (isNaN(value)) {
    // RFC 8949 4.2.1 fixes NaN at the half-precision f9 7e 00.
    return [(SIMPLE << 5) | 25, 0x7E, 0x00];
  }

  var half = to_half_bits(value);
  if (half !== null && from_half(half) === value) {
    return [(SIMPLE << 5) | 25, (half >> 8) & 0xFF, half & 0xFF];
  }

  var single = new DataView(new ArrayBuffer(4));
  single.setFloat32(0, value);
  if (single.getFloat32(0) === value) {
    return [(SIMPLE << 5) | 26,
      single.getUint8(0), single.getUint8(1),
      single.getUint8(2), single.getUint8(3)];
  }

  var d = new DataView(new ArrayBuffer(8));
  d.setFloat64(0, value);
  var out = [(SIMPLE << 5) | 27];
  var i;
  for (i = 0; i < 8; i++) {
    out.push(d.getUint8(i));
  }
  return out;
}

function to_half_bits(v) {
  var buf = new DataView(new ArrayBuffer(4));
  buf.setFloat32(0, v);
  var bits = buf.getUint32(0);

  var sign = (bits >> 16) & 0x8000;
  var exp  = (bits >> 23) & 0xFF;
  var frac = bits & 0x7FFFFF;

  if (exp === 0) { return sign; }
  if (exp === 0xFF) { return sign | 0x7C00 | (frac ? 0x200 : 0); }

  var e = exp - 127 + 15;
  if (e >= 0x1F) { return null; }

  // ⚠ SUBNORMAL HALVES. Exponents too small for a normal half can still be
  // held as m * 2^-24 with m below 1024. This branch was missing - in this
  // file and, identically, in the reader - so 2^-24 was written as a single
  // and read back without complaint. See cbor_reader.fits_half.
  if (e <= 0) {
    var m = Math.abs(v) * 16777216;           // v / 2^-24
    if (m === Math.floor(m) && m >= 1 && m <= 1023) {
      return sign | m;
    }
    return null;
  }

  if (frac & 0x1FFF) { return null; }

  return sign | (e << 10) | (frac >> 13);
}

function from_half(bits) {
  var sign = (bits & 0x8000) ? -1 : 1;
  var exp  = (bits >> 10) & 0x1F;
  var frac = bits & 0x3FF;

  if (exp === 0)    { return sign * frac * Math.pow(2, -24); }
  if (exp === 0x1F) { return frac ? NaN : sign * Infinity; }
  return sign * (frac + 1024) * Math.pow(2, exp - 25);
}

// ---------------------------------------------------------------------------
// UTF-8
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Generic
// ---------------------------------------------------------------------------

// Encodes a plain JavaScript value. Maps must be supplied as [key, value]
// pair arrays rather than objects, because an object cannot express an
// integer key - and in COSE the difference between the label 1 and the label
// "1" is the difference between a registered parameter and a private one.
function encode_value(v, depth) {
  var d = depth === undefined ? 0 : depth;

  if (d > 64) {
    fail('cbor-too-deep', 'nesting deeper than 64 levels');
  }

  if (v === null)      { return null_(); }
  if (v === undefined) { return undefined_(); }
  if (typeof v === 'boolean') { return bool(v); }

  if (typeof v === 'number') {
    // ⚠ AN INTEGRAL DOUBLE ABOVE 2^53 IS A FLOAT. 1e300 has no fractional
    // part, and the first version sent it to int(), which refused it as out
    // of range - so a number JavaScript holds exactly could not be written.
    return Number.isSafeInteger(v) ? int(v) : float(v);
  }
  if (typeof v === 'string') { return text(v); }

  if (v instanceof Uint8Array ||
      (typeof Buffer !== 'undefined' && Buffer.isBuffer(v))) {
    return bytes(v);
  }

  if (Object.prototype.toString.call(v) === '[object Array]') {
    var members = [];
    var i;
    for (i = 0; i < v.length; i++) {
      members.push(encode_value(v[i], d + 1));
    }
    return array(members);
  }

  if (v && typeof v === 'object' &&
      Object.prototype.hasOwnProperty.call(v, 'pairs')) {
    var pairs = [];
    var j;
    for (j = 0; j < v.pairs.length; j++) {
      pairs.push([
        encode_value(v.pairs[j][0], d + 1),
        encode_value(v.pairs[j][1], d + 1)
      ]);
    }
    return map(pairs);
  }

  fail('unsupported-value',
    'cannot encode this value; wrap a map as { pairs: [[k, v], ...] }');
}

// ---------------------------------------------------------------------------



function encode(v) {
  return to_bytes(encode_value(v, 0));
}

export {
  head,
  unsigned,
  negative,
  int,
  bytes,
  text,
  bool,
  simple,
  null_ as null,
  undefined_ as undefined,
  float,
  array,
  map,
  tag,
  encode_value,
  encode,
  to_bytes
};
