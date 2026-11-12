// JSON Web Token, RFC 7519 - the claims layer over a JWS.
//
// jws.js answers "which bytes were signed, and with what". This answers the
// question that comes after: "the signature is good - is the TOKEN good?"
// Most JWT vulnerabilities live here, not in the signature:
//
//   an expired token accepted        exp checked against the wrong clock, or
//                                    not checked because it was absent
//   a token for someone else         aud present and never compared - RFC
//                                    7519 4.1.3 says such a token MUST be
//                                    rejected, and most code reads past it
//   a token of the wrong kind        an ID token accepted as an access
//                                    token: typ, RFC 8725 3.11
//   a claim of the wrong type        "exp": "1700000000" - a string - that
//                                    compares as NaN and therefore never
//                                    expires
//
// ⚠ THE ORDER IS FIXED, AND IT IS THE POINT.
//
//   var t = jwt.decode(token);                       // structure only
//   var key = jws.select_key(t.jws, my_jwks);        // your keys, by kid
//   var ok = flex.verify(t.alg, key, t.signing_input, t.signature);
//   var claims = jwt.claims(t, ['ES256'], ok, {      // only now
//     issuer: 'https://issuer.example', audience: 'my-api' });
//
// claims() will not return anything until it has been told the signature
// verified, the algorithm is one the caller accepts, and the claims pass.
// There is no function here that hands over claims without all three.
//
// This library performs no cryptography: `verified` is the caller's result.

import * as JWS from './jws.js';
import * as JSON_ from './json.js';
import * as CLAIMS from './claims.js';
import { make_fail_here } from './commons/fail.js';
import { encode_utf8 } from './commons/encode_text.js';

var fail = make_fail_here('jwt');

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

// A JWT is a JWS or JWE in COMPACT serialization - RFC 7519 section 7.2.
// The JSON serializations are not JWTs, and a five-part token is encrypted:
// decrypt it with jwe.js first, and decode what comes out (whose cty is
// "JWT" when it is a nested token).
function decode(token, options) {
  if (typeof token !== 'string') {
    fail('bad-token', 'a JWT is a string');
  }

  var t = token.replace(/^\s+|\s+$/g, '');

  if (t.charAt(0) === '{') {
    fail('not-compact',
      'a JWT uses the compact serialization (RFC 7519 7.2); this is JSON');
  }

  var dots = t.split('.').length - 1;

  if (dots === 4) {
    fail('encrypted-jwt',
      'this is an encrypted JWT (five parts). Decrypt it with jwe.js and ' +
      'decode the plaintext');
  }
  if (dots !== 2) {
    fail('bad-token', 'a signed JWT has three dot-separated parts');
  }

  var jws = JWS.decode(t, options);

  return {
    jws:           jws,
    alg:           jws.alg,
    header:        jws.header,
    typ:           JSON_.has(jws.header, 'typ')
                     ? JSON_.member(jws.header, 'typ') : null,
    // The two things a verifier needs, under the names it looks for.
    signing_input: JWS.signing_input(jws),
    signature:     jws.signature
  };
}

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

// The registered claims and the type each must have, RFC 7519 4.1. A claim
// of the wrong type is REFUSED rather than ignored: an `exp` that is a
// string is not "no expiry", it is a token whose author was confused, or
// one built to slip past a comparison that coerces.
var REGISTERED = {
  iss: 'string',
  sub: 'string',
  aud: 'audience',
  exp: 'date',
  nbf: 'date',
  iat: 'date',
  jti: 'string'
};

// options:
//
//   now          seconds since the epoch, or a Date. Defaults to the system
//                clock; pass it when you have a better one.
//   leeway       seconds of clock skew to allow on exp and nbf. Default 0 -
//                choose it, do not inherit it.
//   issuer       a string or list. When given, `iss` must be present and
//                be one of them.
//   audience     a string or list of the audiences YOU are. When the token
//                carries `aud`, this is REQUIRED, and one must match.
//   subject      when given, `sub` must equal it.
//   typ          when given, the header's typ must match, ignoring case
//                and an "application/" prefix (RFC 7515 4.1.9).
//   max_age      seconds. When given, `iat` is required and may be no
//                older than this.
//   require      claim names that must be present. `exp` is required
//                unless this list is given and leaves it out - a token
//                with no expiry is valid forever, and that should be a
//                decision.
function claims(decoded, accepted, verified, options) {
  var opts = options || {};

  // The payload, through the JWS gate: refuses unless verified is true and
  // the algorithm is on the caller's list.
  var bytes = JWS.read_verified(decoded.jws, accepted, verified);
  var c = JSON_.parse(bytes);

  if (c === null || typeof c !== 'object' || Array.isArray(c)) {
    fail('bad-claims', 'a JWT payload is a JSON object');
  }

  CLAIMS.check_types(c, REGISTERED, fail);

  if (opts.typ !== undefined) {
    CLAIMS.check_typ(decoded.typ, opts.typ, fail);
  }

  return CLAIMS.check(c, opts, fail);
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

// The signing input for a new token. The caller signs `bytes` and passes the
// signature to jwt.assemble(prepared, signature).
//
// Claims are type-checked on the way OUT as well as in - a token this
// library writes is one it would accept. `typ` defaults to "JWT" when the
// header names none; pass an explicit one ("at+jwt" for RFC 9068 access
// tokens) to make the token's kind unambiguous.
function prepare(header, payload) {
  if (!header || typeof header !== 'object' || Array.isArray(header)) {
    fail('bad-header', 'a header object is required');
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    fail('bad-claims', 'the claims are a JSON object');
  }

  CLAIMS.check_types(payload, REGISTERED, fail);

  var h = {};
  var k;
  for (k in header) {
    if (Object.prototype.hasOwnProperty.call(header, k)) { h[k] = header[k]; }
  }
  if (h.typ === undefined) {
    h.typ = 'JWT';
  }

  return JWS.prepare(h, new Uint8Array(encode_utf8(JSON.stringify(payload),
    fail)));
}

// A JWT is a JWS in compact form (RFC 7519 7.1), so this is jws.assemble
// with the one serialization a JWT may have.
function assemble(prepared, signature) {
  return JWS.assemble(prepared, signature);
}

export {
  decode,
  claims,
  prepare,
  assemble,
  REGISTERED
};
