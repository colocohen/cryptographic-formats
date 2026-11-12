// bech32 (BIP 173) and bech32m (BIP 350).
//
// This has its own file rather than sitting in base.js as "base32 with a
// checksum", because the checksum IS the format. It is a BCH code over
// GF(32), and it guarantees detection of any error touching four characters
// or fewer, plus any run of errors up to 4 characters long. A plain checksum
// - a hash prefix, a sum - detects a random error with high probability and
// gives no guarantee at all about the specific errors people actually make:
// transposing two characters, or mistyping one.
//
// So implementing bech32 without the BCH property produces something that
// looks right, encodes and decodes correctly, passes a round-trip test - and
// is a WORSE base32, because it costs the checksum characters without buying
// what they are for.
//
// The address format for Bitcoin, Lightning, Nostr (npub), Cosmos and
// Cardano, which is what puts it past the inclusion test in the brief.


import { to_bytes } from './commons/bytes.js';
import { make_fail_here } from './commons/fail.js';

var fail = make_fail_here('bech32');


// The data alphabet. Deliberately not the RFC 4648 base32 alphabet: this one
// is ordered so that characters easily confused for one another are far apart
// in value, and it omits 1, b, i and o.
var CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

var TABLE = (function () {
  var t = {};
  var i;
  for (i = 0; i < CHARSET.length; i++) {
    t[CHARSET.charAt(i)] = i;
  }
  return t;
}());

// The two encodings differ ONLY in this constant. BIP 350 changed it after
// bech32 was found to have a weakness: a final character of 'p' could have
// characters inserted or deleted next to it without breaking the checksum, so
// segwit v1 addresses use bech32m instead. Using the wrong constant produces
// an address that no wallet accepts, and the two must never be
// interchangeable.
var BECH32_CONST  = 1;
var BECH32M_CONST = 0x2bc830a3;

// ---------------------------------------------------------------------------
// The BCH checksum
// ---------------------------------------------------------------------------

// The generator polynomial, from BIP 173. Each step multiplies by x and
// reduces modulo the generator, which is what gives the error-detection
// guarantee - not the fact that six characters are appended.
var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values) {
  var chk = 1;
  var i, j;

  for (i = 0; i < values.length; i++) {
    var top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ values[i];

    for (j = 0; j < 5; j++) {
      if ((top >> j) & 1) {
        chk ^= GEN[j];
      }
    }
  }

  return chk >>> 0;
}

// The human-readable part enters the checksum as its high bits, then a zero,
// then its low bits - so the hrp is covered by the checksum and an address
// cannot be moved between networks by editing the prefix.
function hrp_expand(hrp) {
  var out = [];
  var i;

  for (i = 0; i < hrp.length; i++) {
    out.push(hrp.charCodeAt(i) >> 5);
  }
  out.push(0);
  for (i = 0; i < hrp.length; i++) {
    out.push(hrp.charCodeAt(i) & 31);
  }

  return out;
}

function create_checksum(hrp, data, constant) {
  var values = hrp_expand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  var mod = polymod(values) ^ constant;
  var out = [];
  var i;

  for (i = 0; i < 6; i++) {
    out.push((mod >> (5 * (5 - i))) & 31);
  }

  return out;
}

function verify_checksum(hrp, data) {
  var mod = polymod(hrp_expand(hrp).concat(data));

  if (mod === BECH32_CONST)  { return 'bech32'; }
  if (mod === BECH32M_CONST) { return 'bech32m'; }
  return null;
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

// BIP 173 caps an address at 90 characters, which is what the BCH guarantee
// was computed for: beyond that length the code's error-detection properties
// no longer hold as stated. Lightning invoices and some Nostr values
// deliberately exceed it, so the limit is a parameter - but it defaults to
// the safe value and a caller raising it is making a decision.
var DEFAULT_LIMIT = 90;

function encode(hrp, data, options) {
  // ⚠ A STRING HERE IS THE WRONG SHAPE, AND FALLING BACK TO bech32 SILENTLY
  //    IS THE WORST POSSIBLE RESPONSE.
  //
  // `encode(hrp, data, 'bech32m')` reads `'bech32m'.variant`, which is
  // undefined, so the default applied and the caller got a bech32 string
  // while believing they had asked for bech32m. The two differ only in a
  // checksum constant, so the output LOOKS right - which is exactly the
  // failure the note at the top of this file warns about, arriving through
  // the API rather than through the algorithm.
  //
  // Found by an edge-case sweep, where a test wrote the call that way and
  // the two variants came back identical.
  if (options !== undefined && options !== null &&
      typeof options !== 'object') {
    fail('bad-options',
      'options is an object: encode(hrp, data, { variant: "bech32m" }). ' +
      'A bare string is read as a property lookup that yields undefined, ' +
      'and you would get bech32 without being told.');
  }

  var opts = options || {};
  var variant = opts.variant || 'bech32';
  var limit = opts.limit === undefined ? DEFAULT_LIMIT : opts.limit;

  if (variant !== 'bech32' && variant !== 'bech32m') {
    fail('bad-variant',
      'variant must be "bech32" or "bech32m", got "' + variant + '"');
  }

  check_hrp(hrp);

  var values = to_values(data);
  var constant = variant === 'bech32' ? BECH32_CONST : BECH32M_CONST;
  var checksum = create_checksum(hrp, values, constant);
  var combined = values.concat(checksum);

  var out = hrp + '1';
  var i;
  for (i = 0; i < combined.length; i++) {
    out += CHARSET.charAt(combined[i]);
  }

  if (limit !== null && out.length > limit) {
    fail('too-long',
      'the value is ' + out.length + ' characters, over the limit of ' +
      limit + '; BIP 173 caps an address at 90 and the checksum guarantee ' +
      'was computed for that length');
  }

  return out;
}

function check_hrp(hrp) {
  if (typeof hrp !== 'string' || hrp.length === 0) {
    fail('bad-hrp', 'the human-readable part cannot be empty');
  }
  if (hrp.length > 83) {
    fail('bad-hrp', 'the human-readable part is limited to 83 characters');
  }

  var i;
  for (i = 0; i < hrp.length; i++) {
    var c = hrp.charCodeAt(i);
    if (c < 33 || c > 126) {
      fail('bad-hrp',
        'the human-readable part must be printable ASCII, character ' + i +
        ' is 0x' + c.toString(16));
    }
    if (c >= 65 && c <= 90) {
      fail('bad-hrp',
        'the human-readable part must be lowercase when encoding');
    }
  }
}

function to_values(data) {
  var out = [];
  var i;

  for (i = 0; i < data.length; i++) {
    var v = data[i];
    if (typeof v !== 'number' || v < 0 || v > 31 || Math.floor(v) !== v) {
      fail('bad-data',
        'data values are 5-bit groups (0 to 31); index ' + i + ' is ' + v);
    }
    out.push(v);
  }

  return out;
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

function decode(text, options) {
  // The same guard as encode: a bare string here would be read as a property
  // lookup yielding undefined, and the caller would get whichever variant
  // the checksum happens to be rather than the one they asked to check.
  if (options !== undefined && options !== null &&
      typeof options !== 'object') {
    fail('bad-options',
      'options is an object: decode(text, { variant: "bech32m" })');
  }

  var opts = options || {};
  var limit = opts.limit === undefined ? DEFAULT_LIMIT : opts.limit;

  if (typeof text !== 'string') {
    fail('bad-input', 'bech32 expects a string');
  }

  if (limit !== null && text.length > limit) {
    fail('too-long',
      'the value is ' + text.length + ' characters, over the limit of ' +
      limit);
  }

  // BIP 173: a mixed-case string is INVALID. The format is case-insensitive
  // so that it can be read aloud and written in either case, but allowing a
  // mixture would give one address several spellings - and the checksum is
  // computed over one of them.
  var has_lower = /[a-z]/.test(text);
  var has_upper = /[A-Z]/.test(text);

  if (has_lower && has_upper) {
    fail('mixed-case',
      'bech32 is case-insensitive but a mixed-case value is invalid, ' +
      'because one address would then have several spellings');
  }

  var lower = text.toLowerCase();

  // The separator is the LAST '1', because '1' is not in the data alphabet
  // but may appear in the human-readable part.
  var sep = lower.lastIndexOf('1');

  if (sep === -1) {
    fail('no-separator', 'no "1" separator found');
  }
  if (sep === 0) {
    fail('bad-hrp', 'the human-readable part is empty');
  }
  if (sep + 7 > lower.length) {
    fail('too-short',
      'not enough characters after the separator for a six-character ' +
      'checksum');
  }

  var hrp = lower.substr(0, sep);
  var i;

  for (i = 0; i < hrp.length; i++) {
    var c = hrp.charCodeAt(i);
    if (c < 33 || c > 126) {
      fail('bad-hrp',
        'the human-readable part must be printable ASCII');
    }
  }

  var values = [];
  for (i = sep + 1; i < lower.length; i++) {
    var ch = lower.charAt(i);
    if (!Object.prototype.hasOwnProperty.call(TABLE, ch)) {
      var hint = /[1bio]/.test(ch)
        ? ' - bech32 omits 1, b, i and o'
        : '';
      fail('bad-character',
        '"' + ch + '" is not in the bech32 alphabet' + hint);
    }
    values.push(TABLE[ch]);
  }

  // NOT OPTIONAL, and there is no flag to skip it. A decoder that returns the
  // data without checking turns a typo into a valid-looking address for money
  // nobody controls - and the checksum is the entire reason this format
  // exists rather than base32.
  var variant = verify_checksum(hrp, values);

  if (variant === null) {
    fail('bad-checksum',
      'the bech32 checksum does not match; this value has been mistyped or ' +
      'corrupted');
  }

  // ⚠ IF THE CALLER NAMED A VARIANT, IT IS AN ASSERTION AND NOT A HINT.
  //
  // The decoder works out which variant a string uses from its checksum, and
  // reporting that is right. But a caller who passes { variant: 'bech32m' }
  // is saying "this must be bech32m" - they are about to treat the payload
  // as a segwit v1 address - and quietly handing back a bech32 string with a
  // note attached is how a v0 address gets spent as a v1.
  //
  // Found by an edge-case sweep: the option was accepted, validated, and
  // then never compared against what was actually there.
  if (opts.variant !== undefined && opts.variant !== variant) {
    fail('variant-mismatch',
      'this string is ' + variant + ' and ' + opts.variant + ' was ' +
      'required. The two differ only in a checksum constant, so the ' +
      'payload looks identical and only this check tells them apart.');
  }

  return {
    hrp: hrp,
    data: values.slice(0, values.length - 6),
    variant: variant
  };
}

// ---------------------------------------------------------------------------
// Bit conversion
// ---------------------------------------------------------------------------

// bech32 carries 5-bit groups; callers have bytes. The conversion pads with
// zero bits on encode and REFUSES non-zero padding on decode, for the same
// reason base64 does: otherwise two values decode to the same bytes.
function to_words(input) {
  return convert(to_bytes(input), 8, 5, true);
}

function from_words(words) {
  return new Uint8Array(convert(words, 5, 8, false));
}

function convert(values, from, to, pad) {
  var acc = 0;
  var bits = 0;
  var out = [];
  var max = (1 << to) - 1;
  var i;

  for (i = 0; i < values.length; i++) {
    var v = values[i];

    if (v < 0 || (v >> from) !== 0) {
      fail('bad-data',
        'value ' + v + ' at index ' + i + ' does not fit in ' + from +
        ' bits');
    }

    acc = (acc << from) | v;
    bits += from;

    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & max);
    }
  }

  if (pad) {
    if (bits > 0) {
      out.push((acc << (to - bits)) & max);
    }
  } else {
    if (bits >= from) {
      fail('bad-padding', 'a whole group of padding bits is left over');
    }
    if (((acc << (to - bits)) & max) !== 0) {
      fail('non-canonical',
        'the padding bits are not zero, so this value and the correctly ' +
        'padded one would decode the same');
    }
  }

  return out;
}

// ---------------------------------------------------------------------------
// Convenience for whole byte strings
// ---------------------------------------------------------------------------

function encode_bytes(hrp, data, options) {
  return encode(hrp, to_words(data), options);
}

function decode_bytes(text, options) {
  var d = decode(text, options);
  return { hrp: d.hrp, bytes: from_words(d.data), variant: d.variant };
}


export {
  encode,
  decode,
  encode_bytes,
  decode_bytes,
  to_words,
  from_words,
  CHARSET,
  DEFAULT_LIMIT
};
