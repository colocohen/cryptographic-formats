// The pieces JWS and JWE share, which is more than it looks.
//
// Both are "a base64url header, some base64url parts, joined by dots", and
// both police the same header rules - so `crit` was checked twice, base64url
// was decoded with two near-identical wrappers, and the ASCII conversion for
// the signing input and the AAD was written out in each.
//
// ⚠ IS THIS SAFE TO SHARE? The question from commons/README.md is:
//
//     If this were wrong, would a round trip through this library still pass?
//
// Taken function by function:
//
//   check_crit    pure validation, produces nothing. A mistake refuses good
//                 tokens or accepts bad ones, and neither cancels out.
//
//   decode_b64    decode side only. base.js holds the one base64url codec
//                 and this only shapes the error, so there is no second
//                 implementation to disagree with.
//
//   ascii         used to build the SIGNING INPUT and the AAD, which is the
//                 risky category on the face of it - but it REFUSES anything
//                 above 0x7F rather than transforming it, so a mistake here
//                 throws instead of producing bytes that quietly round-trip.
//                 A silent transformation would belong in commons/
//                 encode_text.js, on the writer side only.
//
// None of them is half of an encode/decode pair, so all three may be shared.

import * as B from './base.js';
import * as JSON_ from './json.js';
import { encode_utf8 } from './commons/encode_text.js';

// ---------------------------------------------------------------------------

// base64url with the caller's error family. `what` names the part, because
// "bad base64url" in a five-part token leaves the reader checking all five.
function decode_part(text, what, fail) {
  if (typeof text !== 'string') {
    fail('bad-base64url', what + ' must be a base64url string');
  }
  if (text === '') {
    return new Uint8Array(0);
  }

  try {
    return B.decode('base64url', text);
  } catch (e) {
    fail('bad-base64url',
      what + ': ' + e.message.replace(/^cryptographic-formats: base: /, ''));
  }
}

// The ASCII of a header string, for a signing input or an AAD.
//
// Refuses anything above 0x7F rather than truncating it: base64url is an
// ASCII alphabet, so a character outside it means the string is not the one
// that was signed, and silently masking it would produce bytes that verify
// against nothing.
function ascii(text, fail) {
  var out = new Uint8Array(text.length);
  var i;

  for (i = 0; i < text.length; i++) {
    var c = text.charCodeAt(i);

    if (c > 0x7F) {
      fail('bad-input',
        'expected ASCII, found a character above 0x7F at index ' + i);
    }
    out[i] = c;
  }

  return out;
}

// ⚠ RFC 7515 section 4.1.11 and RFC 7516 section 4.1.13, which say the same
// thing: every name in `crit` MUST be understood, and MUST be present in the
// protected header.
//
// A token saying "you must understand X" that is processed by something which
// does not is a token being processed against its own instructions.
//
// `registered` differs between the two - JWS forbids naming alg, kid, jwk or
// crit; JWE forbids alg, enc and crit - because the point of the rule is that
// a name every implementation must already handle cannot be smuggled past a
// check that only inspects unrecognised entries.
//
// ⚠ "UNDERSTOOD" IS A LIST, AND THE CALLER EXTENDS IT.
//
// The first version checked that every crit name was present in the header
// and stopped there - which is the half of the rule that costs nothing. A
// token with crit ["foo"] reached its payload, and a token with crit ["b64"]
// and b64 false was processed as if b64 were true: the signing input built
// over base64url text the signer never signed. RFC 7515 says to REFUSE a
// name you do not understand, so this refuses unless the name is in
// `understood` - what the module itself implements, plus whatever the caller
// passes in `options.understood` because THEY implement it.
function check_crit(crit, header, registered, understood, fail) {
  if (!Array.isArray(crit) || crit.length === 0) {
    fail('bad-crit', 'crit must be a non-empty array of header names');
  }

  var seen = {};
  var i;

  for (i = 0; i < crit.length; i++) {
    if (typeof crit[i] !== 'string') {
      fail('bad-crit', 'crit entries must be strings');
    }
    if (Object.prototype.hasOwnProperty.call(seen, crit[i])) {
      fail('bad-crit', 'crit names "' + crit[i] + '" twice');
    }
    seen[crit[i]] = true;

    if (registered.indexOf(crit[i]) !== -1) {
      fail('bad-crit',
        'crit must not name the registered header "' + crit[i] + '"');
    }
    if (!JSON_.has(header, crit[i])) {
      fail('bad-crit',
        'crit names "' + crit[i] + '", which is not in the protected header');
    }
    if (understood.indexOf(crit[i]) === -1) {
      fail('crit-not-understood',
        'crit says "' + crit[i] + '" must be understood, and nothing here ' +
        'implements it. If your code does, pass it in options.understood');
    }
  }
}

// The names this module understands, followed by the caller's. A caller
// extending the list is saying "I implement this", which is the only thing
// that can make an unknown extension safe to accept.
function understood_names(own, options, fail) {
  var extra = options && options.understood;

  if (extra === undefined || extra === null) {
    return own;
  }
  if (!Array.isArray(extra)) {
    fail('bad-options', 'options.understood must be an array of names');
  }
  return own.concat(extra);
}

// ⚠ THE HEADERS ARE ONE SET, SPLIT ACROSS PLACES, AND THE PLACES MUST NOT
//    OVERLAP.
//
// RFC 7515 7.2.1 and RFC 7516 7.2.1: the JOSE header is the UNION of the
// protected, shared-unprotected and per-recipient headers, and their names
// MUST be disjoint. A kid in both the protected and an unprotected header is
// two answers to one question, and a filter reading one while the verifier
// reads the other is the attack.
//
// `parts` is a list of [label, object-or-null]. Returns the union.
function union_headers(parts, fail) {
  var out = {};
  var from = {};
  var i;

  for (i = 0; i < parts.length; i++) {
    var label = parts[i][0];
    var h = parts[i][1];

    if (h === null || h === undefined) { continue; }

    if (typeof h !== 'object' || Array.isArray(h)) {
      fail('bad-header', 'the ' + label + ' header is not a JSON object');
    }

    var k;
    for (k in h) {
      if (!Object.prototype.hasOwnProperty.call(h, k)) { continue; }
      if (Object.prototype.hasOwnProperty.call(from, k)) {
        fail('header-not-disjoint',
          '"' + k + '" appears in both the ' + from[k] + ' and the ' + label +
          ' header; RFC 7515 and 7516 require them to be disjoint');
      }
      from[k] = label;
      out[k] = h[k];
    }
  }

  return out;
}

// The protected header as it goes into a token: BASE64URL(UTF8(JSON)).
//
// ⚠ UTF-8, NOT ASCII. The first version ran JSON.stringify's output through
// ascii(), and JSON.stringify does not escape non-ASCII - so a kid of
// "clé-1" refused to serialize. RFC 7515 5.1 step 2 says UTF-8.
function encode_header(header, fail) {
  if (!header || typeof header !== 'object' || Array.isArray(header)) {
    fail('bad-header', 'a header object is required');
  }
  return B.encode('base64url', encode_utf8(JSON.stringify(header), fail));
}

// Both JWS and JWE arrive either as a compact string with dots or as a JSON
// document, and both decide which by looking at the first non-space
// character. (Both modules now CALL this. The first version had it here AND
// a copy inside each decode, and the similarity budget recorded "both
// modules now call the shared function" - which they did not.) The two entry points were byte-identical - found by a
// structural similarity sweep, not by jscpd, whose default threshold is
// longer than the function.
//
// Safe to share: it dispatches, it does not encode or decode anything.
function split_serialization(input, to_bytes, on_json, on_compact) {
  var text = typeof input === 'string'
    ? input
    : JSON_.utf8_to_string(to_bytes(input));

  var trimmed = text.replace(/^\s+|\s+$/g, '');

  if (trimmed.charAt(0) === '{') {
    return on_json(trimmed);
  }

  return on_compact(trimmed);
}

export {
  split_serialization,
  decode_part,
  ascii,
  check_crit,
  understood_names,
  union_headers,
  encode_header
};
