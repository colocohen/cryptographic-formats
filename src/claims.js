// The registered claims of a token, checked - shared by jwt.js (RFC 7519)
// and cwt.js (RFC 8392), whose claims mean the same and are checked the
// same way: RFC 8392 3.1 gives each CWT claim "the same meaning and
// processing rules" as the JWT claim of that name. One copy, so a fix to
// one cannot miss the other. Internal: no declarations.
//
// The claims arrive as a plain object keyed by the JWT names - cwt.js maps
// its integer labels first - and `fail` is the caller's, so a refusal
// names the format it came from.

import { has } from './json.js';

// Each claim in `table` that is present must be of its type:
//
//   string     a string
//   date       NumericDate - a finite number (RFC 7519 2, RFC 8392 2)
//   audience   a string, or a non-empty list of strings
//   bytes      a Uint8Array (CWT's cti)
//
// A claim of the wrong type is REFUSED rather than ignored: an `exp` that
// is a string is not "no expiry", it is a token whose author was confused,
// or one built to slip past a comparison that coerces.
function check_types(c, table, fail) {
  var k;

  for (k in table) {
    if (!Object.prototype.hasOwnProperty.call(table, k) ||
        !has(c, k)) {
      continue;
    }

    var v = c[k];
    var want = table[k];

    if (want === 'string' && typeof v !== 'string') {
      fail('bad-claim', '"' + k + '" must be a string');
    }
    if (want === 'date' && (typeof v !== 'number' || !isFinite(v))) {
      // NumericDate, RFC 7519 2: a JSON number. A string here compares as
      // NaN, and NaN is never greater than now - so "exp": "123" would
      // never expire under a coercing comparison.
      fail('bad-claim', '"' + k + '" must be a number of seconds');
    }
    if (want === 'bytes' && !(v instanceof Uint8Array)) {
      fail('bad-claim', '"' + k + '" must be a byte string');
    }
    if (want === 'audience') {
      var ok = typeof v === 'string' ||
        (Array.isArray(v) && v.length > 0 &&
         v.every(function (a) { return typeof a === 'string'; }));
      if (!ok) {
        fail('bad-claim', '"aud" must be a string or a non-empty list of them');
      }
    }
  }
}

// A token's typ against the one expected, ignoring case and an
// "application/" prefix (RFC 7515 4.1.9).
function check_typ(have, want, fail) {
  var norm = function (t) {
    return String(t).toLowerCase().replace(/^application\//, '');
  };

  if (have === null || norm(have) !== norm(want)) {
    fail('wrong-typ',
      'the header says typ ' + (have === null ? 'nothing' : '"' + have + '"') +
      ', and "' + want + '" was expected - RFC 8725 3.11: a token of one ' +
      'kind accepted as another is a substitution attack');
  }
}

// The checks after the types, in a fixed order. Returns the claims.
// See jwt.claims for the options.
function check(c, opts, fail) {
  var i;
  var now = seconds(opts.now === undefined ? new Date() : opts.now, fail);
  var leeway = opts.leeway === undefined ? 0 : opts.leeway;

  if (typeof leeway !== 'number' || !(leeway >= 0) || leeway > 600) {
    fail('bad-options', 'leeway is seconds, from 0 to 600');
  }

  var required = Array.isArray(opts.require) ? opts.require : ['exp'];
  var i;

  for (i = 0; i < required.length; i++) {
    if (!has(c, required[i])) {
      fail('missing-claim', 'the token has no "' + required[i] + '" claim');
    }
  }

  if (has(c, 'exp') && now >= c.exp + leeway) {
    fail('expired', 'the token expired at ' + iso(c.exp));
  }

  if (has(c, 'nbf') && now + leeway < c.nbf) {
    fail('not-yet-valid', 'the token is not valid before ' + iso(c.nbf));
  }

  if (has(c, 'iat') && c.iat > now + leeway) {
    fail('issued-in-future', 'the token says it was issued at ' +
      iso(c.iat) + ', which has not happened yet');
  }

  if (opts.max_age !== undefined) {
    if (!has(c, 'iat')) {
      fail('missing-claim', 'max_age needs an "iat" claim to measure from');
    }
    if (now - c.iat > opts.max_age + leeway) {
      fail('too-old', 'the token was issued more than ' + opts.max_age +
        ' seconds ago');
    }
  }

  if (opts.issuer !== undefined) {
    if (!has(c, 'iss') || list(opts.issuer).indexOf(c.iss) === -1) {
      fail('wrong-issuer', 'the token is from ' +
        (has(c, 'iss') ? '"' + c.iss + '"' : 'no stated issuer'));
    }
  }

  // ⚠ RFC 7519 4.1.3: "If the principal processing the claim does not
  // identify itself with a value in the aud claim when this claim is
  // present, then the JWT MUST be rejected." Not checking is not an option
  // the RFC leaves open - so a token with aud and a caller with no audience
  // is refused, with a message saying what to pass.
  if (has(c, 'aud')) {
    if (opts.audience === undefined) {
      fail('audience-not-checked',
        'the token is addressed to ' + JSON.stringify(c.aud) + ', and RFC ' +
        '7519 says it must be rejected unless you are one of them - pass ' +
        'options.audience');
    }
    var mine = list(opts.audience);
    var theirs = list(c.aud);
    var hit = false;
    for (i = 0; i < theirs.length; i++) {
      if (mine.indexOf(theirs[i]) !== -1) { hit = true; }
    }
    if (!hit) {
      fail('wrong-audience', 'the token is for ' + JSON.stringify(c.aud));
    }
  } else if (opts.audience !== undefined) {
    fail('missing-claim', 'an audience was expected and the token has no ' +
      '"aud" claim');
  }

  if (opts.subject !== undefined && c.sub !== opts.subject) {
    fail('wrong-subject', 'the token is about ' +
      (has(c, 'sub') ? '"' + c.sub + '"' : 'no stated subject'));
  }

  return c;
}

function seconds(t, fail) {
  if (t instanceof Date) {
    return t.getTime() / 1000;
  }
  if (typeof t === 'number' && isFinite(t)) {
    return t;
  }
  fail('bad-options', 'now is seconds since the epoch or a Date');
}

function list(v) {
  return Array.isArray(v) ? v : [v];
}

function iso(s) {
  return new Date(s * 1000).toISOString();
}


export {
  check_typ,
  check_types,
  check
};
