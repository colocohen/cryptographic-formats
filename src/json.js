// A JSON scanner that refuses what JSON.parse accepts.
//
// The reason this file exists, in one line:
//
//   JSON.parse('{"kty":"EC","kty":"RSA"}')   ->   { kty: 'RSA' }
//
// Two byte strings meaning one thing, decided silently and in favour of the
// LAST occurrence. That is precisely the failure this library exists to
// refuse, and it is not theoretical: duplicate-member confusion has been a
// real JOSE attack family, because a filter that inspects a token and the
// verifier that consumes it can disagree about which value counts. A JWS
// header with two `alg` members is a token whose algorithm depends on who is
// reading it.
//
// JSON.parse cannot refuse it. A reviver sees each member, but the object is
// already collapsing them, and there is no hook that fires on the collision.
// So the text is scanned instead.
//
// Beyond duplicates, this scanner also refuses:
//
//   - anything after the top-level value (the JSON equivalent of trailing
//     DER bytes)
//   - leading zeros and other non-canonical number forms
//   - lone surrogates in \u escapes, which JSON.parse turns into a string
//     that cannot be re-encoded to the same bytes
//   - raw control characters inside strings, which RFC 8259 forbids
//
// It does NOT try to be a general JSON parser for arbitrary documents. It is
// for keys and headers: small, machine-generated, and read by something that
// makes security decisions on the result.


import { decode_utf8 } from './commons/decode_text.js';
import { make_fail } from './commons/fail.js';

var fail = make_fail('json');


// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

function Scanner(text) {
  this.text = text;
  this.pos = 0;
}

Scanner.prototype.error = function (code, detail) {
  fail(this.pos, code, detail);
};

Scanner.prototype.peek = function () {
  return this.pos < this.text.length ? this.text.charAt(this.pos) : null;
};

// RFC 8259 section 2: only these four characters are insignificant
// whitespace. A vertical tab or a form feed between tokens is not JSON, and
// accepting it means the same document has more than one spelling.
Scanner.prototype.skip_space = function () {
  while (this.pos < this.text.length) {
    var c = this.text.charAt(this.pos);
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
      this.pos += 1;
    } else {
      break;
    }
  }
};

Scanner.prototype.expect = function (ch) {
  if (this.peek() !== ch) {
    this.error('bad-json',
      'expected "' + ch + '", got ' +
      (this.peek() === null ? 'end of input' : '"' + this.peek() + '"'));
  }
  this.pos += 1;
};

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

Scanner.prototype.value = function (depth) {
  if (depth > 64) {
    // Bounded so that a deeply nested document cannot exhaust the stack.
    // Keys and headers are two or three levels deep.
    this.error('json-too-deep', 'nesting deeper than 64 levels');
  }

  this.skip_space();
  var c = this.peek();

  if (c === null) {
    this.error('bad-json', 'unexpected end of input');
  }
  if (c === '{') { return this.object(depth); }
  if (c === '[') { return this.array(depth); }
  if (c === '"') { return this.string(); }
  if (c === '-' || (c >= '0' && c <= '9')) { return this.number(); }

  if (this.text.substr(this.pos, 4) === 'true') {
    this.pos += 4; return true;
  }
  if (this.text.substr(this.pos, 5) === 'false') {
    this.pos += 5; return false;
  }
  if (this.text.substr(this.pos, 4) === 'null') {
    this.pos += 4; return null;
  }

  this.error('bad-json', 'unexpected character "' + c + '"');
};

Scanner.prototype.object = function (depth) {
  this.expect('{');

  var out = {};
  var seen = {};

  this.skip_space();
  if (this.peek() === '}') {
    this.pos += 1;
    return out;
  }

  for (;;) {
    this.skip_space();

    if (this.peek() !== '"') {
      this.error('bad-json', 'object member names must be strings');
    }

    var key_at = this.pos;
    var key = this.string();

    // THE reason this file exists.
    //
    // Note the guard shape: a plain `seen[key]` would also match inherited
    // properties, so a document with a member called "constructor" or
    // "__proto__" would be reported as a duplicate on its first appearance.
    //
    // And the record goes in through put(), as the value does: `seen[key] =
    // true` with the key "__proto__" sets no property - it tries to change
    // seen's prototype - so the member's second appearance passed as its
    // first (DECISIONS 42).
    if (Object.prototype.hasOwnProperty.call(seen, key)) {
      fail(key_at, 'duplicate-member',
        'member "' + key + '" appears more than once; JSON.parse would ' +
        'silently keep the last one');
    }
    put(seen, key, true);

    this.skip_space();
    this.expect(':');

    var v = this.value(depth + 1);

    put(out, key, v);

    this.skip_space();

    if (this.peek() === ',') {
      this.pos += 1;
      continue;
    }
    if (this.peek() === '}') {
      this.pos += 1;
      return out;
    }
    this.error('bad-json', 'expected "," or "}" in object');
  }
};

Scanner.prototype.array = function (depth) {
  this.expect('[');

  var out = [];

  this.skip_space();
  if (this.peek() === ']') {
    this.pos += 1;
    return out;
  }

  for (;;) {
    out.push(this.value(depth + 1));
    this.skip_space();

    if (this.peek() === ',') {
      this.pos += 1;
      continue;
    }
    if (this.peek() === ']') {
      this.pos += 1;
      return out;
    }
    this.error('bad-json', 'expected "," or "]" in array');
  }
};

// ---------------------------------------------------------------------------
// Strings
// ---------------------------------------------------------------------------

var ESCAPES = {
  '"': '"', '\\': '\\', '/': '/',
  b: '\b', f: '\f', n: '\n', r: '\r', t: '\t'
};

Scanner.prototype.string = function () {
  this.expect('"');

  var out = '';

  for (;;) {
    if (this.pos >= this.text.length) {
      this.error('bad-json', 'unterminated string');
    }

    var c = this.text.charAt(this.pos);
    var code = this.text.charCodeAt(this.pos);

    if (c === '"') {
      this.pos += 1;
      return out;
    }

    if (code < 0x20) {
      // RFC 8259 section 7: characters below U+0020 must be escaped. A raw
      // newline inside a string is a document that some parsers accept and
      // others do not.
      this.error('bad-json',
        'unescaped control character U+' + hex4(code) + ' in string');
    }

    if (c !== '\\') {
      // A run of plain characters is taken in one slice, not one `+=` each
      // (DECISIONS 33).
      var end = this.pos + 1;
      var t = this.text;
      var k;
      while (end < t.length && (k = t.charCodeAt(end)) !== 0x22 &&
             k !== 0x5C && k >= 0x20) {
        end += 1;
      }
      out += t.slice(this.pos, end);
      this.pos = end;
      continue;
    }

    this.pos += 1;
    var e = this.peek();

    if (e === null) {
      this.error('bad-json', 'unterminated escape');
    }

    if (Object.prototype.hasOwnProperty.call(ESCAPES, e)) {
      out += ESCAPES[e];
      this.pos += 1;
      continue;
    }

    if (e !== 'u') {
      this.error('bad-json', 'unknown escape "\\' + e + '"');
    }

    this.pos += 1;
    var cp = this.hex4();

    if (cp >= 0xD800 && cp <= 0xDBFF) {
      // A high surrogate must be followed by its low half. JSON.parse builds
      // a string containing a lone surrogate, which cannot be re-encoded to
      // UTF-8 and comes back as U+FFFD - so the value that was checked and
      // the value that is used are different strings.
      if (this.text.substr(this.pos, 2) !== '\\u') {
        this.error('lone-surrogate',
          'high surrogate is not followed by a low surrogate');
      }
      this.pos += 2;
      var low = this.hex4();
      if (!(low >= 0xDC00 && low <= 0xDFFF)) {
        this.error('lone-surrogate',
          'high surrogate is followed by U+' + hex4(low) +
          ', which is not a low surrogate');
      }
      out += String.fromCharCode(cp) + String.fromCharCode(low);
      continue;
    }

    if (cp >= 0xDC00 && cp <= 0xDFFF) {
      this.error('lone-surrogate',
        'low surrogate U+' + hex4(cp) + ' with no high surrogate before it');
    }

    out += String.fromCharCode(cp);
  }
};

Scanner.prototype.hex4 = function () {
  var s = this.text.substr(this.pos, 4);

  if (s.length !== 4 || !/^[0-9a-fA-F]{4}$/.test(s)) {
    this.error('bad-json', '\\u must be followed by four hex digits');
  }

  this.pos += 4;
  return parseInt(s, 16);
};

function hex4(n) {
  var s = n.toString(16).toUpperCase();
  while (s.length < 4) {
    s = '0' + s;
  }
  return s;
}

// ---------------------------------------------------------------------------
// Numbers
// ---------------------------------------------------------------------------

// RFC 8259 section 6 forbids leading zeros, a leading plus, a bare leading or
// trailing decimal point, and hex or octal forms. Each of those would be a
// second spelling of a value, and several of them parse to something
// different in a lenient reader than in a strict one.
var NUMBER = /^-?(0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?/;

Scanner.prototype.number = function () {
  var m = NUMBER.exec(this.text.substr(this.pos));

  if (m === null) {
    this.error('bad-json', 'malformed number');
  }

  var text = m[0];

  // The regex matched a prefix; if what follows is still number-like, the
  // literal was something the grammar rejects - 01, 1.., 1e, .5 - and
  // stopping quietly would read only the acceptable part.
  var next = this.text.charAt(this.pos + text.length);
  if (/[0-9.eE+\-]/.test(next)) {
    this.error('non-canonical-number',
      'malformed number literal near "' + text + next + '"');
  }

  this.pos += text.length;

  var value = Number(text);
  if (!isFinite(value)) {
    this.error('bad-json', 'number is not finite');
  }

  // Integers beyond 2^53 lose precision silently. A key parameter or a JWT
  // claim that comes back as a different number than it went in is worse
  // than a refusal.
  if (m[2] === undefined && m[3] === undefined &&
      Math.abs(value) > Number.MAX_SAFE_INTEGER) {
    this.error('number-too-large',
      'integer ' + text + ' cannot be represented exactly');
  }

  return value;
};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

// Parses one JSON value and refuses anything after it. Trailing content is
// the JSON equivalent of trailing DER bytes: everything the caller wanted was
// present, and something else was there too.
function parse(text) {
  if (typeof text !== 'string') {
    if (text instanceof Uint8Array ||
        (typeof Buffer !== 'undefined' && Buffer.isBuffer(text))) {
      text = utf8_to_string(text);
    } else {
      fail(0, 'bad-input', 'expected a string or bytes');
    }
  }

  // A byte-order mark is not JSON. RFC 8259 section 8.1 says implementations
  // MAY ignore one; refusing keeps a single spelling and the caller can strip
  // it themselves if they know it is there.
  if (text.charAt(0) === '\uFEFF') {
    fail(0, 'byte-order-mark',
      'input starts with a byte-order mark, which is not JSON');
  }

  var s = new Scanner(text);
  var value = s.value(0);

  s.skip_space();
  if (s.pos < text.length) {
    fail(s.pos, 'trailing-content',
      (text.length - s.pos) + ' character(s) after the top-level value');
  }

  return value;
}

// A reader, so it shares commons/decode_text.js with der_reader and
// cbor_reader. The wrapper adapts the signature: this module's `fail` takes
// the offset first.
function utf8_to_string(bytes) {
  return decode_utf8(bytes, function (pos, code, detail) {
    fail(pos, code, detail);
  }, 0);
}

// ---------------------------------------------------------------------------
// Member access
// ---------------------------------------------------------------------------

// Reading a member off a parsed object. Uses hasOwnProperty so that a missing
// member cannot be answered by something inherited from Object.prototype -
// `jwk.constructor` is truthy on any object, and a check written as
// `if (jwk.kty)` would pass on a document that has no kty at all.
function member(obj, name) {
  if (!obj || typeof obj !== 'object') {
    return undefined;
  }
  if (!Object.prototype.hasOwnProperty.call(obj, name)) {
    return undefined;
  }
  return obj[name];
}

// Sets a member as an own, enumerable property - through defineProperty, so
// that a member named __proto__ lands as an ordinary key rather than
// reaching the prototype. What the parser does, and what code adding
// members to a parsed document must do too (sd_jwt.js does).
function put(obj, name, value) {
  Object.defineProperty(obj, name, {
    value: value, writable: true, enumerable: true, configurable: true
  });
}

function has(obj, name) {
  return !!obj && typeof obj === 'object' &&
    Object.prototype.hasOwnProperty.call(obj, name);
}

export {
  parse,
  member,
  has,
  put,
  utf8_to_string
};
