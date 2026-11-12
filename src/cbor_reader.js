// CBOR, RFC 8949, read under the DETERMINISTIC encoding requirements of
// section 4.2.1.
//
// CBOR has DER's problem exactly, and most implementations do not enforce the
// fix. Section 4.2.1 defines a deterministic form; section 4.2 notes that
// plain CBOR allows many encodings of one value. That matters here for the
// same reason it matters in DER: COSE signs a byte string, so two encodings
// of one value is a signature that verifies over two different inputs, and a
// verifier and a filter can disagree about what was signed.
//
// The four rules, all enforced:
//
//   shortest argument   17 is 0x11, never 0x18 0x11
//   no indefinite       the length is stated, never terminated by a break
//   sorted map keys     bytewise on the encoded key
//   no duplicate keys   the JSON failure, in binary
//
// Structure mirrors der_reader: a cursor that validates on every read, and no
// way to reach a value except through a call that checks it.


import { to_bytes } from './commons/bytes.js';
import { decode_utf8 } from './commons/decode_text.js';
import { make_fail } from './commons/fail.js';

var fail = make_fail('cbor');


// Major types, in the top three bits of the initial byte.
var UNSIGNED  = 0;
var NEGATIVE  = 1;
var BYTES     = 2;
var TEXT      = 3;
var ARRAY     = 4;
var MAP       = 5;
var TAG       = 6;
var SIMPLE    = 7;

var TYPE_NAMES = ['unsigned', 'negative', 'byte string', 'text string',
                  'array', 'map', 'tag', 'simple/float'];

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

function Reader(buf, pos, end) {
  this.buf = buf;
  this.pos = pos;
  this.end = end;
}

Reader.prototype.remaining = function () {
  return this.end - this.pos;
};

Reader.prototype.peek_type = function () {
  if (this.pos >= this.end) {
    return null;
  }
  return this.buf[this.pos] >> 5;
};

// Reads the initial byte and its argument. This is where three of the four
// determinism rules live, so every value passes through it.
Reader.prototype._head = function () {
  var start = this.pos;

  if (this.pos >= this.end) {
    fail(start, 'truncated', 'expected a value, input ended');
  }

  var initial = this.buf[this.pos];
  var major   = initial >> 5;
  var info    = initial & 0x1F;
  this.pos += 1;

  if (info < 24) {
    return { major: major, info: info, value: info, start: start };
  }

  if (info === 31) {
    // The indefinite-length form, terminated by a break. The end of a value
    // is then decided by its content rather than stated up front, which is
    // exactly the ambiguity determinism removes.
    fail(start, 'indefinite-length',
      'indefinite-length ' + TYPE_NAMES[major] +
      ' is not deterministic CBOR');
  }

  if (info > 27) {
    fail(start, 'reserved-additional-info',
      'additional information ' + info + ' is reserved');
  }

  var bytes = 1 << (info - 24);          // 24->1, 25->2, 26->4, 27->8

  if (this.pos + bytes > this.end) {
    fail(start, 'truncated',
      'argument of ' + bytes + ' byte(s) runs past the end');
  }

  // ⚠ A FLOAT'S ARGUMENT IS BITS, NOT A NUMBER.
  //
  // Major type 7 with 8 argument bytes is a double, and the first version
  // assembled those bytes into an integer like any other argument - which
  // then failed the 2^53 check below for every double with a normal
  // exponent. Nothing written by cbor_writer as a double could be read
  // back; the tests never wrote one. Floats keep their raw bytes.
  if (major === SIMPLE && info >= 25) {
    var raw = this.buf.subarray(this.pos, this.pos + bytes);
    this.pos += bytes;
    return { major: major, info: info, value: null, raw: raw, start: start };
  }

  var value = 0;
  var i;
  for (i = 0; i < bytes; i++) {
    value = (value * 256) + this.buf[this.pos + i];
  }
  this.pos += bytes;

  // Beyond 2^53 the value cannot be held exactly, and a length or a key that
  // comes back as a different number than it went in is worse than a refusal.
  if (value > Number.MAX_SAFE_INTEGER) {
    fail(start, 'value-too-large',
      'argument exceeds the exactly representable range');
  }

  // Shortest-form: the argument must not be written wider than it needs to
  // be. 17 encoded as 0x18 0x11 is a second encoding of 0x11.
  //
  // Floats are exempt here - major type 7 uses the same bits for half, single
  // and double precision, and their shortest-form rule is about the VALUE,
  // handled in _simple.
  if (major !== SIMPLE) {
    var minimum;
    if (value < 24)          { minimum = 0; }
    else if (value < 0x100)  { minimum = 24; }
    else if (value < 0x10000) { minimum = 25; }
    else if (value < 0x100000000) { minimum = 26; }
    else { minimum = 27; }

    if (info !== minimum) {
      fail(start, 'non-shortest-argument',
        'argument ' + value + ' is written with additional information ' +
        info + ', but ' + minimum + ' would hold it');
    }
  }

  return { major: major, info: info, value: value, start: start };
};

Reader.prototype._expect = function (major) {
  var h = this._head();
  if (h.major !== major) {
    fail(h.start, 'unexpected-type',
      'expected ' + TYPE_NAMES[major] + ', got ' + TYPE_NAMES[h.major]);
  }
  return h;
};

// ---------------------------------------------------------------------------
// Scalars
// ---------------------------------------------------------------------------

Reader.prototype.read_unsigned = function () {
  return this._expect(UNSIGNED).value;
};

// Major type 1 encodes -1 minus the argument, so the argument 0 is -1.
Reader.prototype.read_negative = function () {
  return -1 - this._expect(NEGATIVE).value;
};

// Either sign. COSE label values are small negative integers, so this is the
// common case there.
Reader.prototype.read_int = function () {
  var t = this.peek_type();

  if (t === UNSIGNED) { return this.read_unsigned(); }
  if (t === NEGATIVE) { return this.read_negative(); }

  fail(this.pos, 'unexpected-type',
    'expected an integer, got ' +
    (t === null ? 'end of input' : TYPE_NAMES[t]));
};

Reader.prototype.read_bytes = function () {
  var h = this._expect(BYTES);

  if (this.pos + h.value > this.end) {
    fail(h.start, 'length-exceeds-input',
      'byte string of ' + h.value + ' runs past the end');
  }

  var out = this.buf.subarray(this.pos, this.pos + h.value);
  this.pos += h.value;
  return out;
};

Reader.prototype.read_text = function () {
  var h = this._expect(TEXT);

  if (this.pos + h.value > this.end) {
    fail(h.start, 'length-exceeds-input',
      'text string of ' + h.value + ' runs past the end');
  }

  var bytes = this.buf.subarray(this.pos, this.pos + h.value);
  this.pos += h.value;
  return decode_utf8(bytes, fail, h.start);
};

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

// Returns the member count. The caller then reads that many values, which
// keeps the cursor model: nothing is buffered and nothing is skipped.
Reader.prototype.read_array_header = function () {
  return this._expect(ARRAY).value;
};

Reader.prototype.read_map_header = function () {
  return this._expect(MAP).value;
};

Reader.prototype.read_tag = function () {
  return this._expect(TAG).value;
};

// ---------------------------------------------------------------------------
// Simple values and floats
// ---------------------------------------------------------------------------

Reader.prototype._simple = function () {
  var h = this._head();

  if (h.major !== SIMPLE) {
    fail(h.start, 'unexpected-type',
      'expected a simple value, got ' + TYPE_NAMES[h.major]);
  }

  if (h.info === 20) { return false; }
  if (h.info === 21) { return true; }
  if (h.info === 22) { return null; }
  if (h.info === 23) { return undefined; }

  // ⚠ RFC 8949 table 4: additional information 0 to 19 are UNASSIGNED SIMPLE
  // VALUES, and they are well-formed.
  //
  // This branch did not exist, so every one of them failed as a reserved
  // additional information - which conflated two different things. 28 to 30
  // ARE reserved and must be refused; 0 to 19 are merely unassigned, and
  // section 3.3 makes rejecting them a POLICY choice rather than a
  // well-formedness one.
  //
  // Returned in the same shape as a one-byte simple value, so a caller
  // handles both the same way and can apply their own policy.
  //
  // Found by the RFC 8949 sweep - the CBOR tests were written case by case
  // and never enumerated the table.
  if (h.info <= 19) {
    return { simple: h.info };
  }

  if (h.info === 24) {
    // A one-byte simple value below 32 could have been written in the initial
    // byte alone, so writing it long is a second encoding.
    if (h.value < 32) {
      fail(h.start, 'non-shortest-argument',
        'simple value ' + h.value + ' must be written in the initial byte');
    }
    return { simple: h.value };
  }

  if (h.info === 25) { return read_float(this, h, 2); }
  if (h.info === 26) { return read_float(this, h, 4); }
  if (h.info === 27) { return read_float(this, h, 8); }

  // 28, 29 and 30 are reserved by RFC 8949 and assigned to nothing. 31 is
  // the break, which _head has already refused as an indefinite length.
  fail(h.start, 'reserved-additional-info',
    'additional information ' + h.info + ' is reserved in major type 7');
};

// The head has already consumed the argument bytes as an integer, so the
// float is rebuilt from them. Deterministic CBOR requires the SHORTEST width
// that preserves the value exactly, so a double holding a number a half
// would represent is refused.
function read_float(r, h, width) {
  var view = new DataView(h.raw.buffer, h.raw.byteOffset, width);
  var value;
  var half_bits = width === 2 ? view.getUint16(0) : null;

  if (width === 2) {
    value = from_half(half_bits);
  } else if (width === 4) {
    value = view.getFloat32(0);
  } else {
    value = view.getFloat64(0);
  }

  if (isNaN(value)) {
    // RFC 8949 4.2.1: NaN is written as the half-precision 0xf97e00.
    if (half_bits !== 0x7E00) {
      fail(h.start, 'non-canonical-nan',
        'NaN must be encoded as f9 7e 00');
    }
    return value;
  }

  if (width > 2 && fits_half(value)) {
    fail(h.start, 'non-shortest-float',
      'value fits in half precision but is written in ' + width + ' bytes');
  }
  if (width > 4 && fits_single(value)) {
    fail(h.start, 'non-shortest-float',
      'value fits in single precision but is written in 8 bytes');
  }

  return value;
}

function from_half(bits) {
  var sign = (bits & 0x8000) ? -1 : 1;
  var exp  = (bits >> 10) & 0x1F;
  var frac = bits & 0x3FF;

  if (exp === 0)    { return sign * frac * Math.pow(2, -24); }
  if (exp === 0x1F) { return frac ? NaN : sign * Infinity; }
  return sign * (frac + 1024) * Math.pow(2, exp - 25);
}

// ⚠ DELIBERATELY NOT SHARED with cbor_writer's half conversion, and written
// a different way: the writer builds the bit pattern, this asks whether
// ANY half holds the value.
//
// Both used to build bits, identically, and both dropped the SUBNORMAL
// halves - 2^-24 and its multiples up to 1023 of them - so the writer
// emitted 2^-24 as a single and this reader accepted it as shortest. The
// round trip passed. Checked against Python's struct 'e' format now.
function fits_half(v) {
  if (v === 0 || !isFinite(v)) { return true; }

  var a = Math.abs(v);

  // Above the largest finite half.
  if (a > 65504) { return false; }

  // A half is m * 2^(e-25) with 1024 <= m < 2048 for normals, or
  // m * 2^-24 with m < 1024 for subnormals. Either way the value is an
  // integer multiple of 2^-24 that fits 11 significant bits at its scale.
  var e = Math.floor(Math.log(a) / Math.LN2);
  // log2 can be off by one at exact powers of two; correct it.
  if (Math.pow(2, e) > a) { e -= 1; }
  if (Math.pow(2, e + 1) <= a) { e += 1; }

  var step = e < -14 ? Math.pow(2, -24) : Math.pow(2, e - 10);
  var m = a / step;

  return m === Math.floor(m);
}

function fits_single(v) {
  var buf = new DataView(new ArrayBuffer(4));
  buf.setFloat32(0, v);
  return buf.getFloat32(0) === v;
}

Reader.prototype.read_bool = function () {
  var v = this._simple();
  if (typeof v !== 'boolean') {
    fail(this.pos, 'unexpected-type', 'expected a boolean');
  }
  return v;
};

// ---------------------------------------------------------------------------
// Generic value
// ---------------------------------------------------------------------------

// Reads any value into plain JavaScript. Maps come back as an array of
// [key, value] pairs rather than an object, because CBOR keys are not
// restricted to strings and collapsing an integer key to "1" would lose the
// distinction between 1 and "1" - which in COSE is the distinction between a
// registered label and a private one.
Reader.prototype.read_value = function (depth) {
  var d = depth === undefined ? 0 : depth;

  if (d > 64) {
    fail(this.pos, 'cbor-too-deep', 'nesting deeper than 64 levels');
  }

  var t = this.peek_type();

  if (t === null) {
    fail(this.pos, 'truncated', 'expected a value, input ended');
  }
  if (t === UNSIGNED) { return this.read_unsigned(); }
  if (t === NEGATIVE) { return this.read_negative(); }
  if (t === BYTES)    { return this.read_bytes(); }
  if (t === TEXT)     { return this.read_text(); }
  if (t === SIMPLE)   { return this._simple(); }

  if (t === TAG) {
    var tag = this.read_tag();
    return { tag: tag, value: this.read_value(d + 1) };
  }

  if (t === ARRAY) {
    var n = this.read_array_header();
    var arr = [];
    var i;
    for (i = 0; i < n; i++) {
      if (this.remaining() === 0) {
        fail(this.pos, 'truncated',
          'array declared ' + n + ' members, input ended after ' + i);
      }
      arr.push(this.read_value(d + 1));
    }
    return arr;
  }

  return this.read_map(d);
};

// Enforces the two map rules. Both are about the same thing: a map whose
// meaning depends on the reader.
Reader.prototype.read_map = function (depth) {
  var d = depth === undefined ? 0 : depth;
  var n = this.read_map_header();

  var out = [];
  var previous = null;
  var i;

  for (i = 0; i < n; i++) {
    if (this.remaining() === 0) {
      fail(this.pos, 'truncated',
        'map declared ' + n + ' pairs, input ended after ' + i);
    }

    var key_start = this.pos;
    var key = this.read_value(d + 1);
    var key_bytes = this.buf.subarray(key_start, this.pos);

    if (previous !== null) {
      var cmp = compare(previous, key_bytes);

      // Duplicates first, because an unsorted map with a duplicate should be
      // reported as a duplicate - it is the more serious of the two.
      if (cmp === 0) {
        fail(key_start, 'duplicate-key',
          'this map key appears more than once');
      }
      // RFC 8949 4.2.1: keys sorted bytewise on their encodings. An unsorted
      // map is a second encoding of the same map, and COSE signs the bytes.
      if (cmp > 0) {
        fail(key_start, 'map-not-sorted',
          'map keys are not in bytewise ascending order');
      }
    }

    previous = key_bytes;
    out.push([key, this.read_value(d + 1)]);
  }

  return out;
};

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

// ---------------------------------------------------------------------------
// Raw capture
// ---------------------------------------------------------------------------

// Reads one complete value and returns its bytes without interpreting them.
//
// COSE needs this: a protected header is a byte string wrapping an encoded
// map, and the bytes that were signed are the bytes that arrived. Re-encoding
// the map would change the signature input for any input that deviates from
// deterministic form.
Reader.prototype.capture = function () {
  var start = this.pos;
  this.read_value(0);
  return this.buf.subarray(start, this.pos);
};

// ---------------------------------------------------------------------------
// UTF-8
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------


function reader(input) {
  var bytes = to_bytes(input);
  return new Reader(bytes, 0, bytes.length);
}

// The form to reach for: the end check happens whether or not the callback
// remembers it, so trailing bytes after the top-level value are always
// caught.
function read(input, fn) {
  var r = reader(input);
  var out = fn(r);

  if (r.pos < r.end) {
    fail(r.pos, 'trailing-bytes',
      (r.end - r.pos) + ' unconsumed byte(s)');
  }
  return out;
}

// Decodes one complete value from a buffer that holds exactly one.
function decode(input) {
  return read(input, function (r) { return r.read_value(0); });
}

export {
  reader,
  read,
  decode,
  Reader,
  UNSIGNED, NEGATIVE, BYTES, TEXT, ARRAY, MAP, TAG, SIMPLE
};
