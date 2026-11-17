// Text DECODING, shared by the readers and BY THE READERS ONLY.
//
// ⚠ THE ENCODER IS IN A DIFFERENT FILE AND MUST STAY THERE.
//
// If one module held both decode_utf8 and encode_utf8, a single mistake -
// accepting overlong forms and also producing them - would appear in both
// directions and cancel itself out on a round trip. Every test would pass
// over a pair that agrees with itself and with nothing else in the world.
//
// That is the sig_to_der failure exactly: a short-form length of 135 written
// by the encoder and accepted by the decoder, invisible for as long as the
// two only ever spoke to each other.
//
// So the split is by DIRECTION, not by concern. der_reader and cbor_reader
// share this file, because two decoders cannot cancel each other out. Neither
// writer may import it.

// Latin-1: one byte, one code point. Used for the ASCII-ish string types
// where every byte is already validated to be in range.
function latin1(bytes) {
  var s = '';
  var i;
  for (i = 0; i < bytes.length; i++) {
    s += String.fromCharCode(bytes[i]);
  }
  return s;
}

// A UTF-8 decoder that REFUSES what a lenient one accepts.
//
// Node's TextDecoder substitutes U+FFFD for malformed input, which turns two
// different byte strings into one string. That matters because X.509 subject
// names are compared, and a filter checking the bytes would see something
// different from the consumer decoding them.
//
// `fail` is passed in so the error carries the calling module's family and
// offset - a UTF-8 problem in a certificate should say `der`, and the same
// problem in a COSE payload should say `cbor`.
// ⚠ CODE UNITS GO INTO A Uint16Array AND BECOME TEXT A CHUNK AT A TIME.
// One `s +=` per character made an 8 MB FIDO metadata BLOB take 0.8 s here
// (DECISIONS 33); the same chunking as base.js's text output.
var UNIT_CHUNK = 8192;

function decode_utf8(bytes, fail, pos) {
  var pieces = [];
  // At most one unit per byte (and two for a 4-byte sequence, which takes
  // four bytes) - so a short string gets a short buffer: allocating the
  // whole chunk for a five-letter name cost more than decoding it.
  var units = new Uint16Array(Math.min(UNIT_CHUNK, bytes.length + 1));
  var n = 0;
  var i = 0;

  while (i < bytes.length) {
    var b = bytes[i];
    var cp;
    var need;

    if (b < 0x80) {
      cp = b; need = 0;
    } else if ((b & 0xE0) === 0xC0) {
      cp = b & 0x1F; need = 1;
    } else if ((b & 0xF0) === 0xE0) {
      cp = b & 0x0F; need = 2;
    } else if ((b & 0xF8) === 0xF0) {
      cp = b & 0x07; need = 3;
    } else {
      fail(pos, 'bad-utf8', 'invalid UTF-8 lead byte at offset ' + i);
    }

    if (need > 0 && i + need >= bytes.length) {
      fail(pos, 'bad-utf8', 'UTF-8 sequence truncated at offset ' + i);
    }

    var j;
    for (j = 1; j <= need; j++) {
      if ((bytes[i + j] & 0xC0) !== 0x80) {
        fail(pos, 'bad-utf8',
          'invalid UTF-8 continuation byte at offset ' + (i + j));
      }
      cp = (cp << 6) | (bytes[i + j] & 0x3F);
    }

    // Overlong encodings are the classic UTF-8 attack: a character written
    // in more bytes than it needs gives one character several encodings, so
    // a filter inspecting the bytes sees something different from the
    // consumer that decodes them.
    if ((need === 1 && cp < 0x80) ||
        (need === 2 && cp < 0x800) ||
        (need === 3 && cp < 0x10000)) {
      fail(pos, 'overlong-utf8', 'overlong UTF-8 encoding at offset ' + i);
    }

    if (cp >= 0xD800 && cp <= 0xDFFF) {
      fail(pos, 'bad-utf8',
        'UTF-8 encodes a surrogate code point at offset ' + i);
    }
    if (cp > 0x10FFFF) {
      fail(pos, 'bad-utf8', 'code point above U+10FFFF at offset ' + i);
    }

    if (n + 2 > units.length) {
      pieces.push(String.fromCharCode.apply(null, units.subarray(0, n)));
      n = 0;
    }
    if (cp > 0xFFFF) {
      cp -= 0x10000;
      units[n++] = 0xD800 + (cp >> 10);
      units[n++] = 0xDC00 + (cp & 0x3FF);
    } else {
      units[n++] = cp;
    }

    i += need + 1;
  }

  pieces.push(String.fromCharCode.apply(null, units.subarray(0, n)));
  return pieces.join('');
}

export {
  latin1,
  decode_utf8
};
