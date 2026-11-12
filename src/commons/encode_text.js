// Text ENCODING, shared by the writers and BY THE WRITERS ONLY.
//
// ⚠ THE DECODER IS IN commons/decode_text.js AND MUST STAY THERE.
//
// See the note at the top of that file. The short version: a module holding
// both directions can be wrong in both and look right, because the only test
// that ever exercises the pair is a round trip between them.
//
// der_writer and cbor_writer share this file. Neither reader may import it.

// Refuses an unpaired surrogate rather than emitting U+FFFD, so that two
// different inputs cannot produce the same bytes. `fail` is passed in so the
// error carries the calling module's family.
// The Unicode code points of a JavaScript string, refusing an unpaired
// surrogate. Shared by every text ENCODER - UTF-8 here, UCS-4 in
// der_writer's UniversalString - because the pairing rule is one rule.
// `code` names the failure in the caller's terms.
function code_points(text, fail, code) {
  var out = [];
  var i = 0;

  while (i < text.length) {
    var cp = text.charCodeAt(i);

    if (cp >= 0xD800 && cp <= 0xDBFF) {
      var low = text.charCodeAt(i + 1);
      if (!(low >= 0xDC00 && low <= 0xDFFF)) {
        fail(code, 'unpaired high surrogate at index ' + i);
      }
      cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
      i += 2;
    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
      fail(code, 'unpaired low surrogate at index ' + i);
    } else {
      i += 1;
    }

    out.push(cp);
  }

  return out;
}

function encode_utf8(text, fail) {
  var cps = code_points(text, fail, 'bad-utf8');
  var out = [];
  var i;

  for (i = 0; i < cps.length; i++) {
    var cp = cps[i];

    if (cp < 0x80) {
      out.push(cp);
    } else if (cp < 0x800) {
      out.push(0xC0 | (cp >> 6));
      out.push(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
      out.push(0xE0 | (cp >> 12));
      out.push(0x80 | ((cp >> 6) & 0x3F));
      out.push(0x80 | (cp & 0x3F));
    } else {
      out.push(0xF0 | (cp >> 18));
      out.push(0x80 | ((cp >> 12) & 0x3F));
      out.push(0x80 | ((cp >> 6) & 0x3F));
      out.push(0x80 | (cp & 0x3F));
    }
  }

  return out;
}

// ASCII, for the string types whose character set has already been checked.
function ascii(text) {
  var out = [];
  var i;
  for (i = 0; i < text.length; i++) {
    out.push(text.charCodeAt(i) & 0x7F);
  }
  return out;
}

export {
  code_points,
  encode_utf8,
  ascii
};
