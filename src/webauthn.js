// WebAuthn attestation objects and authenticator data, W3C WebAuthn Level 3.
//
// The brief said this "falls out mostly free once CBOR and COSE work", and
// most of it does: an attestationObject is a CBOR map wrapping a COSE key,
// and both of those already exist.
//
// What does NOT fall out free is authenticatorData, which is not CBOR at all.
// It is a fixed binary layout with two variable-length regions and NO LENGTH
// FIELD for either:
//
//   rpIdHash        32 bytes
//   flags            1 byte
//   signCount        4 bytes, big endian
//   [attestedCredentialData]   present when flags bit 6 (AT) is set
//   [extensions]               present when flags bit 7 (ED) is set
//
// ⚠ THE CREDENTIAL PUBLIC KEY HAS NO LENGTH.
//
// attestedCredentialData ends with a COSE_Key in CBOR, and nothing says how
// long it is. The ONLY way to find where it ends - and therefore where the
// extensions begin - is to parse the CBOR and see where the parser stopped.
//
// An implementation that assumes the key runs to the end of authData reads
// the extensions as part of the key when ED is set, and one that guesses a
// length gets it wrong for any key type it did not expect. This is why the
// module needs a real CBOR reader rather than a slice.
//
// ⚠ AND fmt "none" MEANS NO ATTESTATION.
//
// It is a legitimate value - a browser may strip attestation for privacy -
// but a credential registered with it has NOTHING vouching for the
// authenticator. Reading it as "attested" is the failure this format's whole
// purpose runs through, so `attested` is false and the caller has to look.

import * as CBOR from './cbor_reader.js';
import * as COSE from './cose.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, hex, concat_bytes } from './commons/bytes.js';

var fail = make_fail_here('webauthn');

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

// W3C WebAuthn section 6.1. The names are the specification's.
var FLAG = {
  UP: 0x01,   // user present
  UV: 0x04,   // user verified
  BE: 0x08,   // backup eligible
  BS: 0x10,   // backup state
  AT: 0x40,   // attested credential data included
  ED: 0x80    // extension data included
};

// The attestation statement formats in the IANA registry. `none` is in the
// list because it is a real value, not because it attests anything.
var FORMATS = {
  packed:            true,
  tpm:               true,
  'android-key':     true,
  'android-safetynet': true,
  'fido-u2f':        true,
  apple:             true,
  none:              true
};

// ---------------------------------------------------------------------------
// authenticatorData
// ---------------------------------------------------------------------------

// Reads the binary layout. Not CBOR - the only CBOR in here is the credential
// public key, and finding its end is the whole difficulty.
function auth_data_from_bytes(input) {
  var bytes = to_bytes(input);

  if (bytes.length < 37) {
    fail('short-auth-data',
      'authenticatorData is at least 37 bytes (32 hash, 1 flags, 4 count), ' +
      'got ' + bytes.length);
  }

  var flags = bytes[32];

  var out = {
    rp_id_hash: bytes.subarray(0, 32),
    flags:      flags,
    // Reported individually because a relying party checks them
    // individually, and a caller doing `flags & 0x04` by hand is a caller
    // who will one day use the wrong constant.
    user_present:    (flags & FLAG.UP) !== 0,
    user_verified:   (flags & FLAG.UV) !== 0,
    backup_eligible: (flags & FLAG.BE) !== 0,
    backup_state:    (flags & FLAG.BS) !== 0,
    has_credential:  (flags & FLAG.AT) !== 0,
    has_extensions:  (flags & FLAG.ED) !== 0,
    sign_count: (bytes[33] * 0x1000000) + (bytes[34] << 16) +
                (bytes[35] << 8) + bytes[36],
    credential: null,
    extensions: null,
    raw:        bytes
  };

  // ⚠ RFC-level consistency: a backup STATE without backup ELIGIBILITY is a
  // credential claiming to be backed up while saying it cannot be. W3C
  // section 6.1 makes the combination invalid.
  if (out.backup_state && !out.backup_eligible) {
    fail('bad-backup-flags',
      'the BS flag is set without BE: a credential cannot be backed up if ' +
      'it is not eligible for backup');
  }

  var at = 37;

  if (out.has_credential) {
    var read = read_credential(bytes, at);
    out.credential = read.credential;
    at = read.end;
  }

  if (out.has_extensions) {
    // The extensions are a CBOR map starting exactly where the credential
    // public key ended - which is why that end had to be found by parsing
    // rather than assumed.
    var ext = CBOR.reader(bytes.subarray(at));
    out.extensions = ext.read_map(0);
    at += ext.pos;
  }

  if (at !== bytes.length) {
    fail('trailing-bytes',
      (bytes.length - at) + ' unconsumed byte(s) after authenticatorData');
  }

  return out;
}

//   aaguid              16 bytes
//   credentialIdLength   2 bytes, big endian
//   credentialId         credentialIdLength bytes
//   credentialPublicKey  a COSE_Key in CBOR, NO LENGTH GIVEN
function read_credential(bytes, at) {
  if (at + 18 > bytes.length) {
    fail('short-credential-data',
      'attested credential data is truncated before its credential ID');
  }

  var aaguid = bytes.subarray(at, at + 16);
  var id_length = (bytes[at + 16] << 8) | bytes[at + 17];

  // W3C section 6.5.1 caps it at 1023.
  if (id_length > 1023) {
    fail('bad-credential-id',
      'a credential ID is at most 1023 bytes, this claims ' + id_length);
  }
  if (at + 18 + id_length > bytes.length) {
    fail('short-credential-data',
      'the credential ID runs past the end of authenticatorData');
  }

  var id = bytes.subarray(at + 18, at + 18 + id_length);
  var key_at = at + 18 + id_length;

  // ⚠ THE PART THAT NEEDS A REAL CBOR READER.
  //
  // The COSE key has no length field. Parsing it and asking the reader where
  // it stopped is the only way to find the boundary - and when the ED flag
  // is set, the extensions start at exactly that point.
  var r = CBOR.reader(bytes.subarray(key_at));
  var pairs = r.read_map(0);
  var key_end = key_at + r.pos;

  var key = COSE.key_from_cbor(pairs);

  return {
    credential: {
      aaguid:     aaguid,
      aaguid_hex: format_aaguid(aaguid),
      id:         id,
      id_hex:     hex(id),
      key:        key,
      key_bytes:  bytes.subarray(key_at, key_end)
    },
    end: key_end
  };
}

// The canonical 8-4-4-4-12 form, which is how an AAGUID appears in the FIDO
// metadata service - so a caller looking one up does not have to reformat it.
function format_aaguid(bytes) {
  var h = hex(bytes);
  return h.substr(0, 8) + '-' + h.substr(8, 4) + '-' + h.substr(12, 4) +
    '-' + h.substr(16, 4) + '-' + h.substr(20);
}

// ---------------------------------------------------------------------------
// attestationObject
// ---------------------------------------------------------------------------

//   attestationObject = {
//     fmt:      text,
//     attStmt:  map,
//     authData: bstr }
function from_cbor(input) {
  var bytes = to_bytes(input);

  var pairs = CBOR.read(bytes, function (r) {
    return r.read_map(0);
  });

  var m = index(pairs);

  if (typeof m.fmt !== 'string') {
    fail('missing-fmt', 'an attestation object needs a fmt');
  }
  if (!(m.authData instanceof Uint8Array)) {
    fail('missing-auth-data', 'an attestation object needs authData bytes');
  }
  if (m.attStmt === undefined) {
    fail('missing-att-stmt', 'an attestation object needs an attStmt');
  }

  if (FORMATS[m.fmt] === undefined) {
    fail('unknown-format',
      'unrecognised attestation format "' + m.fmt + '"');
  }

  var auth = auth_data_from_bytes(m.authData);

  var out = {
    fmt:        m.fmt,
    // ⚠ `none` is a legitimate value and attests NOTHING. A browser may
    // strip attestation for privacy, and a credential registered that way
    // has nothing vouching for the authenticator - so this is false and the
    // caller has to look rather than assuming a parsed object is an attested
    // one.
    attested:   m.fmt !== 'none',
    att_stmt:   index(m.attStmt),
    auth_data:  auth,
    auth_data_bytes: m.authData,
    der:        bytes
  };

  if (m.fmt === 'none') {
    // W3C section 8.7: the statement must be EMPTY. A `none` attestation
    // carrying a statement is a message contradicting itself, and a relying
    // party that ignored the fmt might read the statement as if it meant
    // something.
    if (m.attStmt.length !== 0) {
      fail('none-with-statement',
        'fmt is "none", which attests nothing, and yet the attStmt is not ' +
        'empty');
    }
  } else {
    check_statement(out);
  }

  return out;
}

function check_statement(att) {
  var s = att.att_stmt;

  // ⚠ apple HAS NO sig (W3C 8.8: appleStmtFormat is x5c alone). The
  // nonce in the leaf certificate is what binds it - SHA-256 of
  // signing_input, read by x509.js as the appleNonce extension. This
  // required a sig, and refused every real Apple attestation (DECISIONS 34).
  if (att.fmt === 'apple') {
    if (!Array.isArray(s.x5c) || s.x5c.length === 0) {
      fail('missing-certificate', 'apple attestation requires an x5c chain');
    }
    if (s.sig !== undefined) {
      fail('unexpected-signature', 'apple attestation has no sig (W3C 8.8)');
    }
  }

  if (att.fmt === 'packed' || att.fmt === 'android-key') {
    if (!(s.sig instanceof Uint8Array)) {
      fail('missing-signature',
        att.fmt + ' attestation requires a sig in the attStmt');
    }
    if (typeof s.alg !== 'number') {
      fail('missing-alg',
        att.fmt + ' attestation requires an alg in the attStmt');
    }
  }

  if (att.fmt === 'fido-u2f') {
    if (!(s.sig instanceof Uint8Array)) {
      fail('missing-signature',
        'fido-u2f attestation requires a sig in the attStmt');
    }
    if (!Array.isArray(s.x5c) || s.x5c.length === 0) {
      // U2F has no self-attestation form: the certificate is how the
      // signature can be checked at all.
      fail('missing-certificate',
        'fido-u2f attestation requires an x5c certificate chain');
    }
  }
}

// ---------------------------------------------------------------------------
// The signing input
// ---------------------------------------------------------------------------

// ⚠ THE BYTES AN ATTESTATION SIGNATURE COVERS.
//
// W3C section 8.2: authenticatorData CONCATENATED with the SHA-256 hash of
// the client data JSON. Not the JSON, and not the two hashed separately - the
// raw authData bytes followed by the 32-byte hash.
//
// The hash is the caller's to compute, because only they have the client data
// and this library performs no cryptography. Passing anything that is not 32
// bytes is refused, because a signature over the wrong input fails silently.
function signing_input(att, client_data_hash) {
  var hash = to_bytes(client_data_hash);

  if (hash.length !== 32) {
    fail('bad-client-data-hash',
      'the client data hash is SHA-256 over the clientDataJSON, so it is 32 ' +
      'bytes; got ' + hash.length +
      (hash.length > 100
        ? ' - this looks like the JSON itself rather than its hash'
        : ''));
  }

  if (att.fmt === 'fido-u2f') {
    return u2f_signing_input(att.auth_data, hash);
  }

  var out = new Uint8Array(att.auth_data_bytes.length + 32);
  out.set(att.auth_data_bytes, 0);
  out.set(hash, att.auth_data_bytes.length);
  return out;
}

// ⚠ fido-u2f SIGNS SOMETHING ELSE (W3C 8.6, step 5): the U2F registration's
// own layout, rebuilt from authData -
//
//   0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F
//
// where publicKeyU2F is the P-256 point, 0x04 || x || y. This returned
// authData || clientDataHash for every format, and a fido-u2f signature
// never verified over it (DECISIONS 32). libfido2 builds the same bytes
// (cred.c, get_signed_hash_u2f).
function u2f_signing_input(auth, hash) {
  var cred = auth.credential;
  if (cred === null) {
    fail('missing-credential', 'a fido-u2f attestation signs the credential, ' +
      'and authData has none');
  }
  if (cred.key.algorithm !== 'ecPublicKey' || cred.key.cose_curve !== 1) {
    fail('bad-u2f-key', 'fido-u2f keys are P-256 (W3C 8.6 step 3)');
  }
  return concat_bytes([new Uint8Array([0]), auth.rp_id_hash, hash, cred.id,
    cred.key.point]);
}

// The same concatenation for an ASSERTION, where there is no attestation
// object - just authData and a signature. W3C section 7.2 step 23.
function assertion_signing_input(auth_data_bytes, client_data_hash) {
  var hash = to_bytes(client_data_hash);

  if (hash.length !== 32) {
    fail('bad-client-data-hash',
      'the client data hash is 32 bytes; got ' + hash.length);
  }

  var auth = to_bytes(auth_data_bytes);
  var out = new Uint8Array(auth.length + 32);
  out.set(auth, 0);
  out.set(hash, auth.length);
  return out;
}

// Whether the attestation is SELF-attested: signed by the credential key
// itself rather than by a separate attestation key with a certificate.
//
// Worth naming, because a self-attestation proves the authenticator holds
// the private key and NOTHING about what the authenticator is. It is not a
// weaker certificate; it is a different claim.
function is_self_attested(att) {
  if (att.fmt === 'none') {
    return false;
  }
  return att.att_stmt.x5c === undefined &&
         att.att_stmt.ecdaaKeyId === undefined;
}

// The attestation certificate chain, when there is one. Returned as raw DER
// for x509.js to parse - one X.509 reader, not two.
function certificates(att) {
  var x5c = att.att_stmt.x5c;

  if (!Array.isArray(x5c)) {
    return [];
  }

  var out = [];
  var i;

  for (i = 0; i < x5c.length; i++) {
    if (!(x5c[i] instanceof Uint8Array)) {
      fail('bad-certificate',
        'x5c entry ' + i + ' is not a byte string');
    }
    out.push(x5c[i]);
  }

  return out;
}

// Whether the rpIdHash matches a relying party ID. The hashing is the
// caller's; this is the comparison, and it exists because doing it wrong
// means accepting a credential registered for a different site.
function rp_id_matches(auth, rp_id_hash) {
  var expected = to_bytes(rp_id_hash);

  if (expected.length !== 32) {
    fail('bad-rp-id-hash',
      'the rpIdHash is SHA-256 over the RP ID, so it is 32 bytes');
  }

  var i;
  for (i = 0; i < 32; i++) {
    if (auth.rp_id_hash[i] !== expected[i]) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------

function index(pairs) {
  var out = {};
  var i;

  if (!Array.isArray(pairs)) {
    return out;
  }

  for (i = 0; i < pairs.length; i++) {
    if (typeof pairs[i][0] === 'string' ||
        typeof pairs[i][0] === 'number') {
      out[pairs[i][0]] = pairs[i][1];
    }
  }
  return out;
}

export {
  from_cbor,
  algorithm_params,
  algorithm_name,
  check_options,
  auth_data_from_bytes,
  signing_input,
  assertion_signing_input,
  u2f_signing_input,
  is_self_attested,
  certificates,
  rp_id_matches,
  FLAG,
  FORMATS
};

// ---------------------------------------------------------------------------
// The one thing a SERVER produces
// ---------------------------------------------------------------------------
//
// ⚠ A NARROW ADDITION, AND THE LIMIT IS DELIBERATE.
//
// Everything else in this module reads what an authenticator produced. The
// server produces exactly one thing in the exchange - the options object it
// sends to start a registration - and that object is JSON, not a binary
// encoding. It is an API structure rather than a container, so building the
// whole of it belongs in a WebAuthn library.
//
// What belongs HERE is the part that IS a format question: `pubKeyCredParams`
// carries COSE ALGORITHM IDENTIFIERS, and this library already has that
// table. A server writing `-7` by hand matches the number to the algorithm
// once and copies it thereafter, and `-257` versus `-259` is one digit.

// The `pubKeyCredParams` entries for a list of algorithm names.
//
//   webauthn.algorithm_params(['ES256', 'RS256'])
//   -> [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }]
//
// ⚠ THE ORDER IS THE SERVER'S PREFERENCE, and it is preserved. An
// authenticator picks the first entry it supports, so putting RS256 before
// ES256 gets RSA keys from anything that can do both.
function algorithm_params(names) {
  if (!Array.isArray(names) || names.length === 0) {
    fail('no-algorithms',
      'algorithm_params takes a non-empty array of names, in the order you ' +
      'prefer them - an authenticator picks the first it supports');
  }

  var out = [];
  var i, label;

  for (i = 0; i < names.length; i++) {
    var found = null;

    for (label in COSE.ALG) {
      if (Object.prototype.hasOwnProperty.call(COSE.ALG, label) &&
          COSE.ALG[label].name === names[i]) {
        found = label;
        break;
      }
    }

    if (found === null) {
      fail('unknown-algorithm',
        '"' + names[i] + '" is not a COSE algorithm name');
    }

    // ⚠ ONLY SIGNATURE ALGORITHMS BELONG HERE. A server that listed A256GCM
    // would be asking an authenticator to create a credential with a content
    // encryption algorithm, and the authenticator would ignore the entry -
    // silently, leaving the server to wonder why no credential was made.
    if (COSE.ALG[found].kind !== 'signature') {
      fail('not-a-signature-algorithm',
        '"' + names[i] + '" is a ' + COSE.ALG[found].kind + ' algorithm. ' +
        'pubKeyCredParams lists what a credential may SIGN with, and an ' +
        'authenticator ignores anything else without saying so.');
    }

    out.push({ type: 'public-key', alg: parseInt(found, 10) });
  }

  return out;
}

// The algorithm name for a COSE identifier, for reading back what an
// authenticator chose.
function algorithm_name(alg) {
  var entry = COSE.ALG[String(alg)];
  return entry === undefined ? null : entry.name;
}

// ⚠ WHAT IS WRONG WITH THE OPTIONS BEFORE THEY ARE SENT.
//
// Returns rather than throws, like every other check() in this library: a
// caller who knows what they are doing can proceed, and one who does not
// gets told which of these matters.
function check_options(options) {
  var problems = [];

  if (options === null || typeof options !== 'object') {
    fail('bad-options', 'check_options takes the options object');
  }

  var challenge = options.challenge;

  if (challenge === undefined || challenge === null) {
    problems.push({
      code: 'no-challenge',
      detail: 'without a challenge the ceremony proves nothing - an old ' +
              'assertion replays'
    });
  } else {
    var length = challenge.length === undefined ? 0 : challenge.length;

    // ⚠ THE SPEC SAYS 16 BYTES MINIMUM, AND 16 IS NOT ENOUGH.
    //
    // WebAuthn level 2 section 13.4.3 sets the floor at 16. That is a floor,
    // not a recommendation, and 32 is what every implementation uses -
    // because a challenge is the only thing standing between a replayed
    // assertion and a successful login.
    if (length < 16) {
      problems.push({
        code: 'short-challenge',
        detail: length + ' bytes. WebAuthn 13.4.3 sets the minimum at 16, ' +
                'and 32 is what implementations use - the challenge is the ' +
                'only thing preventing a replayed assertion.'
      });
    }
  }

  if (options.pubKeyCredParams !== undefined) {
    if (!Array.isArray(options.pubKeyCredParams) ||
        options.pubKeyCredParams.length === 0) {
      problems.push({
        code: 'no-algorithms',
        detail: 'pubKeyCredParams is empty, so no authenticator can decide ' +
                'what kind of key to make'
      });
    } else {
      var i;

      for (i = 0; i < options.pubKeyCredParams.length; i++) {
        var param = options.pubKeyCredParams[i];
        var name = algorithm_name(param.alg);

        if (name === null) {
          problems.push({
            code: 'unknown-algorithm',
            detail: 'pubKeyCredParams names COSE algorithm ' + param.alg +
                    ', which is not in the registry'
          });
        } else if (COSE.ALG[String(param.alg)].kind !== 'signature') {
          problems.push({
            code: 'not-a-signature-algorithm',
            detail: name + ' is a ' + COSE.ALG[String(param.alg)].kind +
                    ' algorithm, and an authenticator will ignore the entry ' +
                    'without saying so'
          });
        }
      }
    }
  }

  if (options.rp !== undefined && options.rp !== null &&
      options.rp.id !== undefined) {
    // ⚠ THE RP ID IS A DOMAIN, NOT A URL, and it must be the origin's
    // domain or a registrable suffix of it. A scheme or a port here makes
    // every registration fail with a message about the origin, which is not
    // where the mistake is.
    if (/^https?:|\/|:\d+$/.test(options.rp.id)) {
      problems.push({
        code: 'rp-id-not-a-domain',
        detail: 'rp.id is "' + options.rp.id + '". It is a DOMAIN - no ' +
                'scheme, no path, no port - and the browser rejects a ' +
                'mismatch with a message about the origin rather than about ' +
                'this.'
      });
    }
  }

  if (options.user !== undefined && options.user !== null) {
    // ⚠ user.id IS AN OPAQUE HANDLE, NOT AN EMAIL OR A USERNAME.
    //
    // WebAuthn 5.4.3 says so outright: it is stored on the authenticator,
    // may be displayed in an account chooser, and cannot be changed later.
    // Putting an email there publishes it to anything that can enumerate
    // credentials.
    if (typeof options.user.id === 'string' &&
        /@|^[a-z]+$/i.test(options.user.id)) {
      problems.push({
        code: 'user-id-looks-personal',
        detail: 'user.id looks like an email or a username. WebAuthn 5.4.3 ' +
                'says it is an OPAQUE handle - it is stored on the ' +
                'authenticator, may be shown in an account chooser, and ' +
                'cannot be changed afterwards.'
      });
    }

    if (options.user.id && options.user.id.length > 64) {
      problems.push({
        code: 'user-id-too-long',
        detail: 'user.id is limited to 64 bytes'
      });
    }
  }

  return problems;
}
