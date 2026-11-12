// Byte encodings: base16, base32, base64, base64url, base58 and base58check.
//
// The bit-packed ones - base16, base32, base64 - are one codec with different
// alphabets and group sizes. base58 is not: it is a radix conversion, with no
// group boundary at all, which is why it needs its own implementation and why
// its leading-zero handling is a special case rather than padding.
//
// bech32 is in its own file. Its BCH checksum is the reason the format
// exists, not a detail of it, and folding it in here as "base32 with a
// checksum" would lose the error-detection property that justifies the format
// - which makes it a worse base32.
//
// TWO RULES THROUGHOUT:
//
//   Trailing bits that a truncated group cannot represent must be ZERO.
//   Otherwise "MA==" and "MB==" decode to the same byte, and one value has
//   several encodings - the same malleability the DER reader refuses.
//
//   A checksum is never optional. base58check carries one, and a decoder that
//   skips verifying it turns a typo into a valid-looking address for money
//   nobody controls.


import { to_bytes } from './commons/bytes.js';
import { make_fail_here } from './commons/fail.js';

var fail = make_fail_here('base');


// ---------------------------------------------------------------------------
// Bit-packed codecs
// ---------------------------------------------------------------------------

var ALPHABETS = {
  base16: '0123456789abcdef',
  base32: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',           // RFC 4648
  base32hex: '0123456789ABCDEFGHIJKLMNOPQRSTUV',        // RFC 4648 section 7
  base64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  base64url: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
};

var BITS = { base16: 4, base32: 5, base32hex: 5, base64: 6, base64url: 6 };

// RFC 4648 requires padding for base32 and base64. RFC 7515 appendix C
// forbids it for base64url. Neither is a preference: accepting padding where
// it is forbidden, or omitting it where it is required, gives one value two
// encodings.
var PADDED = {
  base16: false, base32: true, base32hex: true,
  base64: true, base64url: false
};

function build(name) {
  var alphabet = ALPHABETS[name];
  var table = {};
  var i;

  for (i = 0; i < alphabet.length; i++) {
    table[alphabet.charAt(i)] = i;
  }

  // base16 is written lowercase and read either way, because hex from a tool
  // is as likely to be uppercase as not and the two cannot mean different
  // things. Every other alphabet here is case-SIGNIFICANT - base64 'a' and
  // 'A' are different values - so folding case would corrupt the data.
  //
  // ⚠ RFC 4648 section 8 specifies the UPPERCASE alphabet, so emitting
  // lowercase is a deliberate divergence: base16 here is the hex codec the
  // whole library displays bytes with, and `openssl`, `xxd` and every other
  // tool a caller will compare against write lowercase.
  //
  // What is NOT accepted is MIXED case within one string - see decode. Two
  // pure spellings a caller may have received from elsewhere is a
  // concession; a third that nothing produces is malleability for nothing,
  // and multibase makes the distinction explicit with 'f' and 'F' as
  // separate prefixes.
  if (name === 'base16') {
    var upper = alphabet.toUpperCase();
    for (i = 0; i < upper.length; i++) {
      table[upper.charAt(i)] = i;
    }
  }

  // ⚠ A SECOND INDEX, BECAUSE THE OBJECT ONE IS SIX TIMES SLOWER.
  //
  // Measured over 1366 characters:
  //
  //   charAt + hasOwnProperty    42.4 us
  //   charAt + object lookup     29.5 us
  //   charCodeAt + typed array    6.4 us
  //
  // charAt allocates a one-character string on every call and the property
  // lookup hashes it. A 128-entry Int16Array indexed by code point does
  // neither, and -1 for "not in this alphabet" preserves the refusal exactly
  // - a byte above 0x7F falls outside the array and reads as undefined,
  // which is also not >= 0.
  //
  // The object table stays: encode() uses `alphabet`, and `table` is part of
  // the shape other code reads.
  var index = new Int16Array(128);
  var j;

  for (j = 0; j < 128; j++) {
    index[j] = -1;
  }

  var k;

  for (k in table) {
    if (Object.prototype.hasOwnProperty.call(table, k) &&
        k.charCodeAt(0) < 128) {
      index[k.charCodeAt(0)] = table[k];
    }
  }

  return { name: name, alphabet: alphabet, table: table, index: index,
           bits: BITS[name], padded: PADDED[name] };
}

var CODECS = {};
(function () {
  var name;
  for (name in ALPHABETS) {
    if (Object.prototype.hasOwnProperty.call(ALPHABETS, name)) {
      CODECS[name] = build(name);
    }
  }
}());

function codec(name) {
  if (!Object.prototype.hasOwnProperty.call(CODECS, name)) {
    fail('unknown-codec', 'no codec named "' + name + '"');
  }
  return CODECS[name];
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

// ⚠ `out += ` IN A LOOP, AND MEASUREMENT SAYS THAT IS THE RIGHT CHOICE.
//
// This was rewritten to push into an array and join once, on the assumption
// that repeated concatenation is quadratic. Measured over 1366 characters:
//
//   out += charAt          14.1 us
//   array push + join      45.0 us      <- THREE TIMES SLOWER
//   String.fromCharCode    10.1 us
//
// V8 represents a growing string as a rope and flattens it once, so `+=` is
// already doing what the array version does by hand - and the array version
// pays for the boxing and the join on top.
//
// fromCharCode.apply is faster still and is not used: it takes the whole
// output as arguments, which blows the stack somewhere above 100,000
// characters, and a base64 encoder that fails on large inputs would be a
// worse trade than four microseconds.
//
// Recorded because the rewrite LOOKED obviously right, and the only reason
// it did not ship is that the benchmark ran afterwards.
function encode(name, input) {
  var c = codec(name);
  var bytes = to_bytes(input);

  if (c.bits === 4) {
    return encode_hex(bytes);
  }
  if (c.bits === 6) {
    return encode_base64(c, bytes);
  }

  var out = '';
  var buffer = 0;
  var held = 0;
  var i;

  for (i = 0; i < bytes.length; i++) {
    buffer = (buffer << 8) | bytes[i];
    held += 8;

    while (held >= c.bits) {
      held -= c.bits;
      out += c.alphabet.charAt((buffer >> held) & ((1 << c.bits) - 1));
    }
  }

  // The final partial group is padded with ZERO bits, which is what makes the
  // decoder's check for non-zero trailing bits meaningful.
  if (held > 0) {
    out += c.alphabet.charAt((buffer << (c.bits - held)) &
                             ((1 << c.bits) - 1));
  }

  return pad_out(c, out);
}

function pad_out(c, out) {
  if (c.padded) {
    // The group size in characters: 8 for base32, 4 for base64.
    var group = lcm(8, c.bits) / c.bits;
    while (out.length % group !== 0) {
      out += '=';
    }
  }
  return out;
}

// ⚠ THE TWO CODECS EVERY FORMAT USES, A WHOLE GROUP AT A TIME.
//
// The bit loop above spends a shift, a mask and a charAt per CHARACTER:
// 86ms for a megabyte of base64 and 121ms of hex, against well under a
// millisecond for Buffer - and a JWE, a CMS blob or a PEM bundle is that
// size. Here a whole group is done at once - a byte to two hex digits,
// three bytes to four base64 characters - writing character CODES into a
// Uint16Array, turned into a string by String.fromCharCode.apply one chunk
// at a time. The chunk is what makes apply safe: the note above refuses it
// for the whole output because the arguments overflow the stack somewhere
// past 100,000; 8,192 never does. Measured on a megabyte: base64 86 -> 5ms,
// hex 121 -> 8ms (a table of character-pair strings and `+=` got only to
// 23 and 37). Decoding writes into a Uint8Array allocated once: 32 -> 10ms. The output is the same string - checked against Buffer over
// every length up to 300 and three random megabytes (base.test.js).
var CHUNK = 8192;

function chunked(n, fill) {
  var codes = new Uint16Array(CHUNK);
  var pieces = [];
  var done = 0;
  while (done < n) {
    var len = Math.min(CHUNK, n - done);
    fill(codes, done, len);
    pieces.push(String.fromCharCode.apply(null, len === CHUNK ? codes : codes.subarray(0, len)));
    done += len;
  }
  return pieces.join('');
}

function codes_of(alphabet) {
  var out = [];
  var k;
  for (k = 0; k < alphabet.length; k++) {
    out.push(alphabet.charCodeAt(k));
  }
  return out;
}

var HEX_CODES = codes_of(ALPHABETS.base16);

// Characters [from, from + len) of the hex of `bytes`: a byte is two, and a
// chunk is even, so no byte straddles one.
function encode_hex(bytes) {
  return chunked(bytes.length * 2, function (codes, from, len) {
    var b = from >> 1;
    var k;
    for (k = 0; k < len; k += 2) {
      var v = bytes[b++];
      codes[k] = HEX_CODES[v >> 4];
      codes[k + 1] = HEX_CODES[v & 15];
    }
  });
}

// The whole groups go through chunks - 8,192 characters is 2,048 groups, so
// none straddles one - and the one or two bytes left after them are their
// bits then ZERO bits, as the bit loop wrote them.
function encode_base64(c, bytes) {
  if (c.codes === undefined) {
    c.codes = codes_of(c.alphabet);
  }
  var a = c.codes;
  var n = bytes.length;
  var whole = n - (n % 3);
  var out = chunked(whole / 3 * 4, function (codes, from, len) {
    var b = from / 4 * 3;
    var k;
    for (k = 0; k < len; k += 4) {
      var v = (bytes[b] << 16) | (bytes[b + 1] << 8) | bytes[b + 2];
      b += 3;
      codes[k] = a[v >> 18];
      codes[k + 1] = a[(v >> 12) & 63];
      codes[k + 2] = a[(v >> 6) & 63];
      codes[k + 3] = a[v & 63];
    }
  });
  var v;
  if (n - whole === 1) {
    v = bytes[whole];
    out += c.alphabet.charAt(v >> 2) + c.alphabet.charAt((v & 3) << 4);
  } else if (n - whole === 2) {
    v = (bytes[whole] << 8) | bytes[whole + 1];
    out += c.alphabet.charAt(v >> 10) + c.alphabet.charAt((v >> 4) & 63) +
           c.alphabet.charAt((v & 15) << 2);
  }
  return pad_out(c, out);
}

function lcm(a, b) {
  return (a * b) / gcd(a, b);
}

function gcd(a, b) {
  while (b !== 0) {
    var t = b;
    b = a % b;
    a = t;
  }
  return a;
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

function decode(name, text) {
  // ⚠ MIXED CASE IN base16 IS A THIRD SPELLING.
  //
  // 'ABCD' and 'abcd' are both in circulation and both mean the same bytes,
  // so both are read. 'AbCd' is produced by nothing and means the same
  // again - which is one more way to write a value that is supposed to have
  // one canonical form.
  //
  // Found by running the RFC 4648 vectors as a sweep rather than as
  // individual cases.
  if (name === 'base16' && /[a-f]/.test(text) && /[A-F]/.test(text)) {
    fail('mixed-case',
      'base16 is read in either case and written in lower, and this string ' +
      'mixes the two - which is a third spelling of the same bytes');
  }

  var c = codec(name);

  if (typeof text !== 'string') {
    fail('bad-input', name + ' expects a string');
  }

  // Whitespace is refused rather than stripped. A value with a newline in the
  // middle is a value that arrived through something that reformatted it, and
  // silently accepting it means the caller never learns. PEM strips line
  // breaks before the codec sees the body, which is where that belongs.
  if (/\s/.test(text)) {
    fail('whitespace', name + ' value contains whitespace');
  }

  var body = text;
  var pad = 0;

  if (c.padded) {
    var m = /=+$/.exec(text);
    if (m !== null) {
      pad = m[0].length;
      body = text.substr(0, text.length - pad);
    }

    var group = lcm(8, c.bits) / c.bits;
    if (text.length % group !== 0) {
      fail('bad-length',
        name + ' length ' + text.length + ' is not a multiple of ' + group);
    }
    if (pad >= group) {
      fail('bad-padding', 'too much padding');
    }
  } else if (/=/.test(text)) {
    fail('bad-padding',
      name + ' does not use padding, and this value has some');
  }

  var buffer = 0;
  var held = 0;
  // Exactly the whole bytes the characters carry, allocated once: pushing
  // onto an array and converting at the end cost twice the decode itself.
  var out = new Uint8Array(Math.floor(body.length * c.bits / 8));
  var at = 0;
  var i;

  for (i = 0; i < body.length; i++) {
    var code = body.charCodeAt(i);
    // ⚠ A code point above 127 reads as undefined here, and `undefined < 0`
    // is false - so the check catches it exactly as it caught a missing
    // property. See the note on `index` in codec().
    var value = code < 128 ? c.index[code] : -1;

    if (value < 0) {
      fail('bad-character',
        '"' + body.charAt(i) + '" is not in the ' + name + ' alphabet');
    }

    buffer = (buffer << c.bits) | value;
    held += c.bits;

    if (held >= 8) {
      held -= 8;
      out[at++] = (buffer >> held) & 0xFF;
      // Only the held bits matter; keeping the rest would overflow 32 bits.
      buffer &= (1 << held) - 1;
    }
  }

  // ⚠ CHECKED FIRST. A whole dangling character is a LENGTH error - an odd
  // number of hex digits - and was reported as "non-zero bits" whenever
  // that last digit was not 0, which sent people looking for a padding bug.
  //
  // The leftover must be small enough to BE a leftover: five held bits in
  // base32 would mean a whole character contributed nothing.
  if (held >= c.bits) {
    fail('bad-length', name + ' value has a trailing partial character');
  }

  // The bits left over from the final character cannot be part of any byte.
  // If they are not zero, this value and the correctly-encoded one decode the
  // same - which means the same bytes have several spellings, and a system
  // comparing encoded strings and a system comparing decoded bytes disagree.
  if (held > 0 && (buffer & ((1 << held) - 1)) !== 0) {
    fail('non-canonical',
      name + ' has non-zero bits after the last whole byte');
  }

  return out;
}

// ---------------------------------------------------------------------------
// base58
// ---------------------------------------------------------------------------

// Not a bit-packed codec. base58 is a radix conversion over the whole value,
// which is why it has no group size, no padding, and why leading zero bytes
// need explicit handling: 0x00 0x01 and 0x01 are different byte strings that
// convert to the same number.
//
// The alphabet omits 0, O, I and l, which is the point - those are the
// characters people transcribe wrongly.
var B58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

var B58_TABLE = (function () {
  var t = {};
  var i;
  for (i = 0; i < B58_ALPHABET.length; i++) {
    t[B58_ALPHABET.charAt(i)] = i;
  }
  return t;
}());

function base58_encode(input) {
  var bytes = to_bytes(input);

  // Each leading zero byte becomes one '1'. Without this, 0x00 0x01 and 0x01
  // would encode identically and a Bitcoin address would lose its version
  // byte.
  var zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) {
    zeros += 1;
  }

  var out = '';
  var i, j;

  for (i = 0; i < zeros; i++) {
    out += '1';
  }

  // Everything after the leading zeros. Empty when the input is empty or all
  // zeros - and the digits array must then stay empty too, or a spurious '1'
  // is appended and the empty string encodes to something.
  var digits = [];

  for (i = zeros; i < bytes.length; i++) {
    var carry = bytes[i];
    for (j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  for (i = digits.length - 1; i >= 0; i--) {
    out += B58_ALPHABET.charAt(digits[i]);
  }

  return out;
}

function base58_decode(text) {
  if (typeof text !== 'string') {
    fail('bad-input', 'base58 expects a string');
  }
  if (/\s/.test(text)) {
    fail('whitespace', 'base58 value contains whitespace');
  }

  var zeros = 0;
  while (zeros < text.length && text.charAt(zeros) === '1') {
    zeros += 1;
  }

  // The digit accumulator starts EMPTY, so an all-'1' string decodes to
  // exactly that many zero bytes and the empty string decodes to nothing.
  var bytes = [];
  var i, j;

  for (i = zeros; i < text.length; i++) {
    var ch = text.charAt(i);

    if (!Object.prototype.hasOwnProperty.call(B58_TABLE, ch)) {
      // Naming the confusable characters is worth doing: 0, O, I and l are
      // absent from the alphabet precisely because people write them for
      // something else, so an error here is very likely a transcription
      // mistake rather than a corrupt value.
      var hint = /[0OIl]/.test(ch)
        ? ' - base58 omits 0, O, I and l because they are easily confused'
        : '';
      fail('bad-character',
        '"' + ch + '" is not in the base58 alphabet' + hint);
    }

    var carry = B58_TABLE[ch];
    for (j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xFF;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xFF);
      carry >>= 8;
    }
  }

  var out = [];
  for (i = 0; i < zeros; i++) {
    out.push(0);
  }
  for (i = bytes.length - 1; i >= 0; i--) {
    out.push(bytes[i]);
  }

  return new Uint8Array(out);
}

// ---------------------------------------------------------------------------
// base58check
// ---------------------------------------------------------------------------

// The checksum is the first four bytes of SHA-256 applied twice. This library
// performs no cryptography, so the hash is supplied by the caller - see
// DECISIONS 0.1. What is NOT optional is verifying it: a decoder that skips
// the check turns a typo into a valid-looking address for money nobody
// controls, so there is no flag to turn it off.
function base58check_encode(payload, sha256) {
  if (typeof sha256 !== 'function') {
    fail('missing-hash',
      'base58check needs a sha256 function; this library performs no ' +
      'cryptography - pass cryptographic-primitives\'s');
  }

  var bytes = to_bytes(payload);
  var digest = to_bytes(sha256(to_bytes(sha256(bytes))));

  var full = new Uint8Array(bytes.length + 4);
  full.set(bytes, 0);
  full.set(digest.subarray(0, 4), bytes.length);

  return base58_encode(full);
}

function base58check_decode(text, sha256) {
  if (typeof sha256 !== 'function') {
    fail('missing-hash',
      'base58check needs a sha256 function; this library performs no ' +
      'cryptography - pass cryptographic-primitives\'s');
  }

  var full = base58_decode(text);

  if (full.length < 5) {
    fail('too-short',
      'a base58check value is at least five bytes: one of payload and four ' +
      'of checksum');
  }

  var payload = full.subarray(0, full.length - 4);
  var found   = full.subarray(full.length - 4);
  var digest  = to_bytes(sha256(to_bytes(sha256(payload))));

  var i;
  for (i = 0; i < 4; i++) {
    if (digest[i] !== found[i]) {
      fail('bad-checksum',
        'the base58check checksum does not match; this value has been ' +
        'mistyped or corrupted');
    }
  }

  return payload;
}

// ---------------------------------------------------------------------------


// Named shorthands, so a caller writes to_base64url(x) rather than
// encode('base64url', x).
function to_hex(b)        { return encode('base16', b); }
function from_hex(s)      { return decode('base16', s); }
function to_base32(b)     { return encode('base32', b); }
function from_base32(s)   { return decode('base32', s); }
function to_base64(b)     { return encode('base64', b); }
function from_base64(s)   { return decode('base64', s); }
function to_base64url(b)  { return encode('base64url', b); }
function from_base64url(s) { return decode('base64url', s); }

export {
  encode,
  decode,
  to_hex, from_hex,
  to_base32, from_base32,
  to_base64, from_base64,
  to_base64url, from_base64url,
  base58_encode, base58_decode,
  base58check_encode, base58check_decode,
  ALPHABETS
};

