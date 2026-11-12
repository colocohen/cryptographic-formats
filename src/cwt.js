// CBOR Web Token, RFC 8392 - the claims layer over a COSE message, as a
// JWT is over a JWS.
//
// The claims are JWT's (RFC 8392 3.1 gives each "the same meaning and
// processing rules"), under integer labels in a CBOR map:
//
//   1 iss   2 sub   3 aud   4 exp   5 nbf   6 iat   7 cti (bytes)
//
// and the token is a COSE_Sign1, Sign, Mac0, Mac, Encrypt0 or Encrypt,
// optionally inside the CWT tag 61. The order is jwt.js's, for the same
// reason:
//
//   var t = cwt.decode(bytes);                          // structure only
//   var input = cose.sign1_signing_input(t.message);    // what was signed
//   var ok = flex.verify(t.alg, key, input, t.message.signature);
//   var claims = cwt.claims(t, ['ES256'], ok, { audience: 'coap://light' });
//
// claims() returns nothing until it is told the signature or MAC verified,
// the algorithm is one the caller accepts, and the claims pass - checked by
// claims.js, the code jwt.claims uses. For an encrypted CWT the caller
// decrypts first and hands the plaintext over as options.plaintext.
//
// This library performs no cryptography: `verified` is the caller's result.

import * as CBOR from './cbor_reader.js';
import * as W from './cbor_writer.js';
import * as COSE from './cose.js';
import * as CLAIMS from './claims.js';

import { to_bytes } from './commons/bytes.js';
import { make_fail_here } from './commons/fail.js';

var fail = make_fail_here('cwt');

// RFC 8392 6: the CWT CBOR tag.
var TAG_CWT = 61;

// RFC 8392 3.1 / 9: the claim keys, and the types claims.js checks.
var LABELS = { iss: 1, sub: 2, aud: 3, exp: 4, nbf: 5, iat: 6, cti: 7 };

var REGISTERED = {
  iss: 'string',
  sub: 'string',
  aud: 'audience',
  exp: 'date',
  nbf: 'date',
  iat: 'date',
  cti: 'bytes'
};

// The COSE message types a CWT can be, by tag - and the decoder for each.
var TYPES = {
  16: { type: 'encrypt0', decode: COSE.encrypt0_decode },
  17: { type: 'mac0',     decode: COSE.mac0_decode },
  18: { type: 'sign1',    decode: COSE.sign1_decode },
  96: { type: 'encrypt',  decode: COSE.encrypt_decode },
  97: { type: 'mac',      decode: COSE.mac_decode },
  98: { type: 'sign',     decode: COSE.sign_decode }
};

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

// The structure, nothing more: which COSE message it is, the message as
// cose.js reads it, and the algorithm.
//
// ⚠ AN UNTAGGED COSE MESSAGE DOES NOT SAY WHICH IT IS. RFC 8392 7.2: the
// type is then known from context, and here the context is options.type
// ('sign1', 'mac0', ...). Guessing from the array length would read a
// Mac0 as a Sign1 - both are four elements.
function decode(input, options) {
  var bytes = to_bytes(input);
  var opts = options || {};

  var outer = CBOR.read(bytes, function (r) {
    var cwt_tagged = false;
    var start = r.pos;

    if (r.peek_type() === CBOR.TAG) {
      var t = r.read_tag();
      if (t === TAG_CWT) {
        cwt_tagged = true;
        start = r.pos;
        if (r.peek_type() === CBOR.TAG) { t = r.read_tag(); } else { t = null; }
      }
      r.pos = r.end;
      return { cwt_tagged: cwt_tagged, cose_tag: t, inner: bytes.subarray(start) };
    }
    r.pos = r.end;
    return { cwt_tagged: false, cose_tag: null, inner: bytes };
  });

  var kind;

  if (outer.cose_tag !== null) {
    kind = TYPES[outer.cose_tag];
    if (kind === undefined) {
      fail('not-cose', 'tag ' + outer.cose_tag + ' is not a COSE message');
    }
    if (opts.type !== undefined && opts.type !== kind.type) {
      fail('wrong-type', 'this is a COSE ' + kind.type + ', not ' + opts.type);
    }
  } else {
    var k;
    for (k in TYPES) {
      if (Object.prototype.hasOwnProperty.call(TYPES, k) &&
          TYPES[k].type === opts.type) {
        kind = TYPES[k];
      }
    }
    if (kind === undefined) {
      fail('untagged', 'an untagged COSE message does not say which it is ' +
        '(RFC 8392 7.2): pass options.type - sign1, sign, mac0, mac, ' +
        'encrypt0 or encrypt');
    }
  }

  // cose.js's options are its own: what is understood in a crit header.
  var message = kind.decode(outer.inner,
    opts.understood === undefined ? undefined : { understood: opts.understood });

  return {
    cwt_tagged: outer.cwt_tagged,
    type:       kind.type,
    message:    message,
    // For sign and mac the algorithm is per signer or recipient; claims()
    // takes the signer's index for a COSE_Sign.
    alg:        message.alg === undefined ? null : message.alg,
    // RFC 8392 7.1 step 7: content type 61 - or "application/cwt" - in the
    // protected header means the payload is itself a CWT.
    nested:     nested(message)
  };
}

function nested(message) {
  var ct = null;
  var i;
  for (i = 0; i < message.protected.length; i++) {
    if (message.protected[i][0] === COSE.HEADER_LABEL.content_type) {
      ct = message.protected[i][1];
    }
  }
  return ct === TAG_CWT || ct === 'application/cwt';
}

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

// options: jwt.claims's - now, leeway, issuer, audience, subject, max_age,
// require (default ['exp']) - and:
//
//   plaintext   for encrypt0 / encrypt: the decrypted payload
//   payload     for a detached sign1 / mac0 payload
//   signer      for sign: which signature `verified` is about (default 0)
//
// Returns the claims by name - iss, sub, aud, exp, nbf, iat, cti - and
// `extra`: every other [label, value] pair, as the map carried it.
function claims(decoded, accepted, verified, options) {
  var opts = options || {};

  if (verified !== true) {
    fail('not-verified', 'the signature or MAC was not confirmed. Build the ' +
      'input with cose.js, check it with cryptographic-primitives, and pass the result here');
  }

  var alg = decoded.alg;

  if (decoded.type === 'sign') {
    var s = decoded.message.signatures[opts.signer === undefined ? 0 : opts.signer];
    alg = s === undefined ? null : s.alg;
  }

  if (!Array.isArray(accepted) || accepted.length === 0) {
    fail('no-accepted-algorithms', 'name the algorithms you accept: ' +
      'claims(t, ["ES256"], ok). There is no default');
  }
  if (accepted.indexOf(alg) === -1) {
    fail('algorithm-not-accepted', 'this token uses ' + alg +
      ', and the accepted list is ' + accepted.join(', '));
  }

  var payload;

  if (decoded.type === 'encrypt0' || decoded.type === 'encrypt') {
    if (opts.plaintext === undefined) {
      fail('encrypted', 'an encrypted CWT: decrypt it (cose.encrypt0_aad ' +
        'is the AAD) and pass the plaintext as options.plaintext');
    }
    payload = to_bytes(opts.plaintext);
  } else {
    payload = decoded.message.payload !== null ? decoded.message.payload
      : opts.payload === undefined ? null : to_bytes(opts.payload);
    if (payload === null) {
      fail('detached-payload', 'this message has a detached payload; pass ' +
        'it as options.payload');
    }
  }

  if (decoded.nested) {
    fail('nested-cwt', 'the content type says the payload is another CWT ' +
      '(RFC 8392 7.1): decode(payload) and verify that one');
  }

  var c = from_map(payload);
  CLAIMS.check_types(c, REGISTERED, fail);
  return CLAIMS.check(c, opts, fail);
}

// The claims map, keyed by name. RFC 8392 7.2 step 2: the payload MUST be a
// CBOR map, and a key appears once - which the CBOR reader enforces.
function from_map(payload) {
  var pairs = CBOR.read(payload, function (r) {
    if (r.peek_type() !== CBOR.MAP) {
      fail('bad-claims', 'a CWT Claims Set is a CBOR map, RFC 8392 7.2');
    }
    return r.read_map(0);
  });

  var out = { extra: [] };
  var names = {};
  var k;
  for (k in LABELS) {
    if (Object.prototype.hasOwnProperty.call(LABELS, k)) { names[LABELS[k]] = k; }
  }

  var i;
  for (i = 0; i < pairs.length; i++) {
    var label = pairs[i][0];
    if (typeof label === 'number' && names[label] !== undefined) {
      out[names[label]] = pairs[i][1];
    } else {
      out.extra.push(pairs[i]);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

// The claims as the CBOR map a COSE message carries as its payload. The
// registered ones by name; others as `extra: [[label, encoded value]]`, the
// value already CBOR (cbor_writer). Claims are type-checked on the way OUT:
// a token this library writes is one it would accept.
//
//   var payload = cwt.claims_to_cbor({ iss: 'coap://as', exp: 1444064944 });
//   var p = cose.sign1_prepare({ protected: [[1, -7]], payload: payload });
//   var token = cwt.tagged(cose.sign1_assemble(p, sign(p.bytes)));
function claims_to_cbor(c) {
  if (!c || typeof c !== 'object' || Array.isArray(c)) {
    fail('bad-claims', 'the claims are an object');
  }

  CLAIMS.check_types(c, REGISTERED, fail);

  var pairs = [];
  var k;

  for (k in c) {
    if (!Object.prototype.hasOwnProperty.call(c, k) || k === 'extra') { continue; }
    if (LABELS[k] === undefined) {
      fail('unknown-claim', '"' + k + '" is not a registered CWT claim - ' +
        'pass it in extra as [label, cbor]');
    }
    pairs.push([W.int(LABELS[k]), claim_value(k, c[k])]);
  }

  var extra = c.extra || [];
  var i;
  for (i = 0; i < extra.length; i++) {
    pairs.push([typeof extra[i][0] === 'number' ? W.int(extra[i][0]) : W.text(extra[i][0]),
                Array.prototype.slice.call(to_bytes(extra[i][1]))]);
  }

  return W.to_bytes(W.map(pairs));
}

function claim_value(name, v) {
  if (REGISTERED[name] === 'bytes') { return W.bytes(v); }
  if (REGISTERED[name] === 'date') {
    return Math.floor(v) === v ? W.int(v) : W.float(v);
  }
  if (Array.isArray(v)) { return W.array(v.map(function (a) { return W.text(a); })); }
  return W.text(v);
}

// RFC 8392 6: a COSE message inside the CWT tag, 61. Optional - and what
// says "this is a CWT" where nothing else does.
function tagged(cose_message) {
  return W.to_bytes(W.tag(TAG_CWT, Array.prototype.slice.call(to_bytes(cose_message))));
}

export {
  decode,
  claims,
  claims_to_cbor,
  tagged,
  LABELS,
  TAG_CWT
};
