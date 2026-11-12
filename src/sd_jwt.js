// Selective Disclosure for JWTs, RFC 9901 - a JWT whose claims the holder
// can reveal one at a time.
//
//   <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~[<KB-JWT>]
//
// The issuer signs digests, not values: each selectively disclosable claim
// is a Disclosure - base64url of the JSON array [salt, name, value], or
// [salt, value] for an array element - and the JWT carries the digest of
// that string in an `_sd` array (or as {"...": digest} in an array). The
// holder sends the Disclosures it chooses; the verifier puts back each one
// whose digest the signed JWT carries.
//
// ⚠ THE DIGESTS ARE THE CALLER'S, AS EVERY HASH IN THIS LIBRARY IS.
//
//   var t = sd_jwt.decode(text);
//   var ok = flex.verify(t.jwt.alg, issuer_key, t.jwt.signing_input,
//                        t.jwt.signature);
//   var digests = t.disclosures.map(function (d) {      // t.sd_alg: sha-256
//     return sha256(d.digest_input); });
//   // with key binding (RFC 9901 7.3) - the holder's key is claims' cnf:
//   var kb_ok = flex.verify(t.kb.alg, cnf_key, t.kb.signing_input,
//                           t.kb.signature);
//   var kb = sd_jwt.key_binding(t, ['ES256'], kb_ok, { audience, nonce,
//            max_age: 300, sd_hash: sha256(t.sd_hash_input) });
//   var claims = sd_jwt.claims(t, ['ES256'], ok, { digests: digests,
//            key_binding: kb, issuer: 'https://issuer.example.com' });
//
// claims() returns the Processed SD-JWT Payload (RFC 9901 7.1) only when
// the signature verified, every Disclosure is referenced exactly once, no
// digest appears twice, and the claims pass the checks jwt.claims makes -
// the same code, claims.js.

import * as JWT from './jwt.js';
import * as JWS from './jws.js';
import * as JSON_ from './json.js';
import * as BASE from './base.js';
import * as CLAIMS from './claims.js';

import { to_bytes } from './commons/bytes.js';
import { make_fail_here } from './commons/fail.js';
import { encode_utf8, ascii } from './commons/encode_text.js';

var fail = make_fail_here('sd-jwt');

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

// The structure: the issuer's JWT (as jwt.decode reads it), each
// Disclosure with the bytes its digest is over, the KB-JWT if there is one,
// and the hash the issuer named. Nothing here is trusted yet.
function decode(text) {
  if (typeof text !== 'string') {
    fail('bad-input', 'an SD-JWT is a string');
  }

  var parts = text.replace(/^\s+|\s+$/g, '').split('~');

  if (parts.length < 2) {
    fail('not-sd-jwt', 'an SD-JWT is <JWT>~ followed by Disclosures, each ' +
      'with its ~ (RFC 9901 4) - this has no ~ at all');
  }

  var kb_text = parts[parts.length - 1];
  var disclosure_texts = parts.slice(1, parts.length - 1);
  var i;

  var disclosures = [];
  var seen = {};

  for (i = 0; i < disclosure_texts.length; i++) {
    var d = read_disclosure(disclosure_texts[i]);
    // RFC 9901 4: "A Holder MUST NOT ... send a Disclosure more than once."
    if (Object.prototype.hasOwnProperty.call(seen, d.encoded)) {
      fail('duplicate-disclosure', 'a Disclosure appears twice');
    }
    seen[d.encoded] = true;
    disclosures.push(d);
  }

  var jwt = JWT.decode(parts[0]);
  var kb = kb_text === '' ? null : JWT.decode(kb_text);

  return {
    jwt:          jwt,
    disclosures:  disclosures,
    kb:           kb,
    // RFC 9901 4.1.1: from the top level of the payload, default sha-256 -
    // read here, before verification, only so the caller knows which hash
    // to compute. claims() reads it again from the verified payload.
    sd_alg:       sd_alg_of(unverified_payload(jwt)),
    // RFC 9901 4.3.1: the KB-JWT's sd_hash is over this - the presentation
    // up to and including the last ~, as US-ASCII.
    sd_hash_input: new Uint8Array(ascii(
      parts.slice(0, parts.length - 1).join('~') + '~'))
  };
}

// A Disclosure: base64url of a JSON array - [salt, name, value] for an
// object property, [salt, value] for an array element (RFC 9901 4.2).
function read_disclosure(encoded) {
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) {
    fail('bad-disclosure', 'a Disclosure is base64url (RFC 9901 4); this ' +
      'is empty or has other characters');
  }

  var arr = JSON_.parse(BASE.from_base64url(encoded));

  if (!Array.isArray(arr) || (arr.length !== 2 && arr.length !== 3)) {
    fail('bad-disclosure', 'a Disclosure is a JSON array of two or three ' +
      'elements, RFC 9901 4.2');
  }
  if (typeof arr[0] !== 'string') {
    fail('bad-disclosure', 'the salt is a string, RFC 9901 4.2.1');
  }
  if (arr.length === 3) {
    check_name(arr[1]);
  }

  return {
    encoded:      encoded,
    salt:         arr[0],
    // null for an array element.
    name:         arr.length === 3 ? arr[1] : null,
    value:        arr[arr.length - 1],
    // RFC 9901 4.2.3: the digest is over the US-ASCII of the base64url
    // string - not over the JSON it encodes.
    digest_input: digest_input(encoded)
  };
}

function check_name(name) {
  if (typeof name !== 'string') {
    fail('bad-disclosure', 'the claim name is a string, RFC 9901 4.2.1');
  }
  if (name === '_sd' || name === '...') {
    fail('bad-disclosure', 'a Disclosure may not name "' + name +
      '" (RFC 9901 4.2.1)');
  }
}

// What a Disclosure's digest is computed over.
function digest_input(encoded) {
  return new Uint8Array(ascii(encoded));
}

function unverified_payload(jwt) {
  return JSON_.parse(BASE.from_base64url(jwt.jws.payload_b64));
}

function sd_alg_of(payload) {
  if (!JSON_.has(payload, '_sd_alg')) {
    return 'sha-256';
  }
  var a = JSON_.member(payload, '_sd_alg');
  if (typeof a !== 'string') {
    fail('bad-sd-alg', '_sd_alg is a string, RFC 9901 4.1.1');
  }
  return a;
}

// ---------------------------------------------------------------------------
// Claims - RFC 9901 7.1
// ---------------------------------------------------------------------------

// options: jwt.claims's - now, leeway, issuer, audience, subject, max_age,
// require, typ - and:
//
//   digests       REQUIRED. For each of decoded.disclosures, in order, its
//                 digest under decoded.sd_alg: bytes, or base64url.
//   key_binding   REQUIRED, and the verifier's policy, not the token's
//                 (RFC 9901 7.3 step 1): false when no KB-JWT is expected -
//                 and one present is refused - or what key_binding()
//                 returned, which a token without a KB-JWT cannot supply.
//   sd_algs       the hashes acceptable for _sd_alg. Default ['sha-256'].
function claims(decoded, accepted, verified, options) {
  var opts = options || {};

  if (Array.isArray(accepted) && accepted.indexOf('none') !== -1) {
    fail('none-accepted', 'RFC 9901 4.1: the issuer-signed JWT MUST NOT use ' +
      'none, and a list accepting it cannot be used here');
  }

  if (opts.key_binding === undefined) {
    fail('key-binding-not-decided', 'pass options.key_binding: false when ' +
      'none is required, or the result of key_binding() - RFC 9901 7.3: ' +
      'the decision MUST NOT depend on whether the holder sent one');
  }
  if (opts.key_binding === false && decoded.kb !== null) {
    fail('unexpected-key-binding', 'an SD-JWT was expected, and this ends ' +
      'with a KB-JWT (RFC 9901 4)');
  }
  if (opts.key_binding !== false &&
      (decoded.kb === null || !opts.key_binding || opts.key_binding.sd_hash === undefined)) {
    fail('key-binding-required', 'key binding is required and was not ' +
      'checked: pass what key_binding() returned');
  }

  var bytes = JWS.read_verified(decoded.jwt.jws, accepted, verified);
  var payload = JSON_.parse(bytes);

  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    fail('bad-claims', 'the payload is a JSON object');
  }

  if (opts.typ !== undefined) {
    CLAIMS.check_typ(decoded.jwt.typ, opts.typ, fail);
  }

  var alg = sd_alg_of(payload);
  var algs = opts.sd_algs || ['sha-256'];

  if (algs.indexOf(alg) === -1) {
    fail('sd-alg-not-accepted', '_sd_alg is ' + alg + ', and the accepted ' +
      'hashes are ' + algs.join(', '));
  }

  var by_digest = digests_by_value(decoded.disclosures, opts.digests);
  var state = { by_digest: by_digest, used: {}, seen: {} };

  var out = process_value(payload, state, 0);
  delete_member(out, '_sd_alg');

  // RFC 9901 7.1 step 5: every Disclosure referenced.
  var k;
  for (k in by_digest) {
    if (Object.prototype.hasOwnProperty.call(by_digest, k) &&
        !Object.prototype.hasOwnProperty.call(state.used, k)) {
      fail('unreferenced-disclosure', 'the Disclosure for ' +
        (by_digest[k].name === null ? 'an array element' : '"' + by_digest[k].name + '"') +
        ' is referenced by no digest in the issuer-signed JWT');
    }
  }

  CLAIMS.check_types(out, JWT.REGISTERED, fail);
  return CLAIMS.check(out, opts, fail);
}

// { base64url digest: disclosure }.
function digests_by_value(disclosures, digests) {
  if (!Array.isArray(digests) || digests.length !== disclosures.length) {
    fail('bad-digests', 'options.digests holds one digest per Disclosure, ' +
      'in the order of decoded.disclosures: ' + disclosures.length);
  }
  var out = {};
  var i;
  for (i = 0; i < digests.length; i++) {
    out[as_b64url(digests[i])] = disclosures[i];
  }
  return out;
}

function as_b64url(d) {
  return typeof d === 'string' ? d : BASE.to_base64url(to_bytes(d));
}

// RFC 9901 7.1 step 3: replace each digest with its Disclosure's claim,
// recursively; drop array elements whose digest has no Disclosure; remove
// every _sd. Depth-limited, as the JSON parser is.
function process_value(v, state, depth) {
  if (depth > 64) {
    fail('too-deep', 'nested more than 64 levels');
  }
  if (Array.isArray(v)) {
    return process_array(v, state, depth);
  }
  if (v !== null && typeof v === 'object') {
    return process_object(v, state, depth);
  }
  return v;
}

function process_array(arr, state, depth) {
  var out = [];
  var i;

  for (i = 0; i < arr.length; i++) {
    var e = arr[i];
    var keys = e !== null && typeof e === 'object' && !Array.isArray(e) ? Object.keys(e) : [];

    if (keys.length === 1 && keys[0] === '...' && typeof e['...'] === 'string') {
      var d = take(e['...'], state);
      if (d === null) { continue; }             // a decoy, or not disclosed
      if (d.name !== null) {
        fail('bad-disclosure', 'an array element\'s Disclosure has two ' +
          'elements; this one names "' + d.name + '" (RFC 9901 7.1)');
      }
      out.push(process_value(d.value, state, depth + 1));
    } else {
      out.push(process_value(e, state, depth + 1));
    }
  }
  return out;
}

function process_object(obj, state, depth) {
  var out = {};
  var k;

  for (k in obj) {
    if (!Object.prototype.hasOwnProperty.call(obj, k) || k === '_sd') { continue; }
    if (k === '_sd_alg' && depth > 0) {
      fail('misplaced-sd-alg', '_sd_alg is at the top level only, RFC 9901 4.1.1');
    }
    JSON_.put(out, k, process_value(obj[k], state, depth + 1));
  }

  if (!JSON_.has(obj, '_sd')) {
    return out;
  }

  var list = obj._sd;
  if (!Array.isArray(list) || !list.every(function (x) { return typeof x === 'string'; })) {
    fail('bad-sd', '_sd is an array of digest strings, RFC 9901 4.2.4.1');
  }

  var i;
  for (i = 0; i < list.length; i++) {
    var d = take(list[i], state);
    if (d === null) { continue; }
    if (d.name === null) {
      fail('bad-disclosure', 'an _sd digest names a two-element Disclosure; ' +
        'object properties have three (RFC 9901 7.1)');
    }
    if (JSON_.has(out, d.name)) {
      fail('claim-exists', '"' + d.name + '" is disclosed where the object ' +
        'already has it (RFC 9901 7.1)');
    }
    JSON_.put(out, d.name, process_value(d.value, state, depth + 1));
  }
  return out;
}

// The Disclosure for a digest found in the payload - or null - refusing a
// digest seen twice (RFC 9901 7.1 step 4).
function take(digest, state) {
  if (Object.prototype.hasOwnProperty.call(state.seen, digest)) {
    fail('duplicate-digest', 'a digest appears twice in the SD-JWT, ' +
      'RFC 9901 7.1');
  }
  state.seen[digest] = true;

  if (!Object.prototype.hasOwnProperty.call(state.by_digest, digest)) {
    return null;
  }
  state.used[digest] = true;
  return state.by_digest[digest];
}

function delete_member(obj, name) {
  if (JSON_.has(obj, name)) { delete obj[name]; }
}

// ---------------------------------------------------------------------------
// Key binding - RFC 9901 4.3, 7.3
// ---------------------------------------------------------------------------

// The KB-JWT, checked: typ kb+jwt, a signature the caller verified with the
// holder's key (the issuer-signed JWT's cnf), and iat, aud, nonce and
// sd_hash. options:
//
//   sd_hash    REQUIRED: the digest of decoded.sd_hash_input under
//              decoded.sd_alg - bytes, or base64url
//   audience   REQUIRED: who you are; aud must be exactly this
//   nonce      REQUIRED: the nonce this transaction sent
//   max_age    REQUIRED: how old, in seconds, the KB-JWT may be
//   now, leeway as jwt.claims
//
// Returns the KB-JWT's claims, for claims()'s options.key_binding.
function key_binding(decoded, accepted, verified, options) {
  var opts = options || {};

  if (decoded.kb === null) {
    fail('key-binding-required', 'key binding is required and this ' +
      'SD-JWT has no KB-JWT (RFC 9901 7.3 step 2)');
  }
  if (Array.isArray(accepted) && accepted.indexOf('none') !== -1) {
    fail('none-accepted', 'a KB-JWT MUST NOT use none, RFC 9901 4.3');
  }

  var k;
  var need = ['sd_hash', 'audience', 'nonce', 'max_age'];
  for (k = 0; k < need.length; k++) {
    if (opts[need[k]] === undefined) {
      fail('bad-options', 'key_binding needs options.' + need[k]);
    }
  }

  CLAIMS.check_typ(decoded.kb.typ, 'kb+jwt', fail);

  var c = JSON_.parse(JWS.read_verified(decoded.kb.jws, accepted, verified));

  if (c === null || typeof c !== 'object' || Array.isArray(c)) {
    fail('bad-claims', 'the KB-JWT payload is a JSON object');
  }

  CLAIMS.check_types(c, JWT.REGISTERED, fail);

  if (typeof JSON_.member(c, 'aud') !== 'string') {
    fail('bad-claim', 'a KB-JWT\'s aud is a single string, RFC 9901 4.3');
  }
  if (typeof JSON_.member(c, 'nonce') !== 'string' ||
      typeof JSON_.member(c, 'sd_hash') !== 'string') {
    fail('missing-claim', 'a KB-JWT carries nonce and sd_hash as strings, ' +
      'RFC 9901 4.3');
  }

  CLAIMS.check(c, { now: opts.now, leeway: opts.leeway, audience: opts.audience,
    max_age: opts.max_age, require: ['iat', 'aud', 'nonce', 'sd_hash'] }, fail);

  if (c.nonce !== opts.nonce) {
    fail('wrong-nonce', 'the KB-JWT was made for another transaction ' +
      '(RFC 9901 7.3 step 5f)');
  }
  if (c.sd_hash !== as_b64url(opts.sd_hash)) {
    fail('wrong-sd-hash', 'sd_hash is not the digest of this presentation: ' +
      'the KB-JWT was made for other Disclosures (RFC 9901 7.3 step 5g)');
  }

  return c;
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

// A Disclosure: [salt, name, value] for an object property, [salt, value]
// for an array element. The salt is the caller's - RFC 9901 9.3: 128 bits
// of randomness, base64url. Returns the string, and what its digest is
// over: the digest goes into the payload as an _sd entry, or {"...": d}.
function disclosure(parts) {
  if (!Array.isArray(parts) || (parts.length !== 2 && parts.length !== 3)) {
    fail('bad-disclosure', 'a Disclosure is [salt, name, value] or ' +
      '[salt, value]');
  }
  if (typeof parts[0] !== 'string' || parts[0].length < 16) {
    fail('bad-salt', 'the salt is a string of at least 128 bits - RFC 9901 ' +
      '9.3: base64url of 16 random bytes is 22 characters');
  }
  if (parts.length === 3) {
    check_name(parts[1]);
  }
  var encoded = BASE.to_base64url(new Uint8Array(encode_utf8(JSON.stringify(parts), fail)));
  return { encoded: encoded, digest_input: digest_input(encoded) };
}

// <JWT>~<D1>~...~<DN>~, and the KB-JWT after it when given.
function serialize(issuer_jwt, disclosures, kb_jwt) {
  var list = (disclosures || []).map(function (d) {
    return typeof d === 'string' ? d : d.encoded;
  });
  return issuer_jwt + '~' + list.map(function (d) { return d + '~'; }).join('') +
    (kb_jwt === undefined || kb_jwt === null ? '' : kb_jwt);
}

// The KB-JWT's signing input, from what the holder presents: typ kb+jwt,
// and the claims RFC 9901 4.3 requires. sd_hash is the caller's digest of
// the presentation - the US-ASCII of serialize(issuer_jwt, disclosures).
function kb_prepare(header, payload) {
  var p = payload || {};
  if (typeof p.aud !== 'string' || typeof p.nonce !== 'string' ||
      typeof p.iat !== 'number' || p.sd_hash === undefined) {
    fail('bad-claims', 'a KB-JWT carries iat, aud (one string), nonce and ' +
      'sd_hash, RFC 9901 4.3');
  }
  var h = {};
  var k;
  for (k in header || {}) {
    if (Object.prototype.hasOwnProperty.call(header, k)) { h[k] = header[k]; }
  }
  h.typ = 'kb+jwt';
  var claims_ = {};
  for (k in p) {
    if (Object.prototype.hasOwnProperty.call(p, k)) { claims_[k] = p[k]; }
  }
  claims_.sd_hash = as_b64url(p.sd_hash);
  return JWT.prepare(h, claims_);
}

// The KB-JWT, from kb_prepare's input and the holder's signature - a JWT,
// compact, as jwt.assemble writes it.
function kb_assemble(prepared, signature) {
  return JWT.assemble(prepared, signature);
}

export {
  decode,
  claims,
  key_binding,
  disclosure,
  serialize,
  kb_prepare,
  kb_assemble
};
