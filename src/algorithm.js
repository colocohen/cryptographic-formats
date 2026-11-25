// Algorithm identifiers WITH their parameters - for the two RSA schemes whose
// parameters are part of what is computed.
//
// ⚠ A NAME ALONE IS NOT ENOUGH FOR PSS OR OAEP.
//
// x509.js reported a PSS certificate's algorithm as "rsassaPss" and stopped.
// To verify it the caller needs the hash, the mask generation function and
// its hash, and the salt length - all in the parameters, none reported. So
// every PSS signature this library read was one nobody could check without
// parsing the DER again by hand. Same for RSA-OAEP in CMS: the label and
// both hashes decide what decrypts.
//
//   RSASSA-PSS-params ::= SEQUENCE {          RFC 4055 3.1
//     hashAlgorithm      [0] HashAlgorithm    DEFAULT sha1,
//     maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
//     saltLength         [2] INTEGER          DEFAULT 20,
//     trailerField       [3] TrailerField     DEFAULT trailerFieldBC }
//
//   RSAES-OAEP-params ::= SEQUENCE {          RFC 4055 4.1
//     hashFunc           [0] AlgorithmIdentifier DEFAULT sha1Identifier,
//     maskGenFunc        [1] AlgorithmIdentifier DEFAULT mgf1SHA1Identifier,
//     pSourceFunc        [2] AlgorithmIdentifier DEFAULT pSpecifiedEmpty }
//
// And for every other signature algorithm, the parameter rule its RFC sets:
// NULL or absent for PKCS#1 v1.5 RSA (RFC 4055 5: accept both), absent for
// ECDSA, DSA and EdDSA. Parameters where there must be none are a place to
// carry bytes the signature does not explain.
//
// The reader (describe) and the writer (to_der) are separate functions and
// each is checked against OpenSSL, not only against the other.

import * as DER from './der_reader.js';
import * as W from './der_writer.js';
import * as OID from './oid.js';
import { PQ_KEYS } from './ec_domain.js';
import { make_fail_here } from './commons/fail.js';
import { to_bytes, int_value, int_bytes } from './commons/bytes.js';

var fail = make_fail_here('algorithm');

var HASHES = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512'];

// The hash a PKCS#1 / ECDSA / DSA signature name implies.
function implied_hash(name) {
  if (name === 'oiwSha1WithRSA' || name === 'oiwDsaWithSHA1') { return 'sha1'; }
  var m = /^(?:sha(\d+)With|ecdsaWithSHA(\d+)|dsaWithSHA(\d+)|md5With|md4With|md2With)/
    .exec(name);
  if (m === null) { return null; }
  if (/^md5/.test(name)) { return 'md5'; }
  if (/^md4/.test(name)) { return 'md4'; }
  if (/^md2/.test(name)) { return 'md2'; }
  return 'sha' + (m[1] || m[2] || m[3]);
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

// Takes an AlgorithmIdentifier as the field tables read it -
// { algorithm: <oid bytes>, parameters: <DER bytes or undefined> } - and
// returns
//
//   { name, scheme, hash, weak, pss?, oaep?, signature_length? }
//
// signature_length: for ML-DSA and SLH-DSA, the one length a signature of
// that parameter set has (FIPS 204 table 2, FIPS 205 table 2). Readers
// refuse a signature of another length with check_signature_length.
//
// scheme: 'pkcs1' | 'pss' | 'ecdsa' | 'dsa' | 'eddsa' | 'ml-dsa' | 'hash-ml-dsa' |
//         'slh-dsa' | 'oaep' | 'rsa' | null
//
// ⚠ weak: true WHEN THE HASH IS MD2, MD4, MD5 OR SHA-1 - under RSA (PKCS#1,
// either OID for SHA-1), PSS, DSA or ECDSA. OpenSSL at security level 1,
// node:tls's default, refuses such a signature on every certificate of a
// chain except the trust anchor (X509_V_ERR_CA_MD_TOO_WEAK, error 68).
//
// The case easy to miss is PSS: RSASSA-PSS-params with no hashAlgorithm is
// SHA-1, RFC 4055's default - so `30 00` is a weak signature that names no
// hash at all. It is reported as one. (PSS with the parameters ABSENT is
// refused: in a signature they are required, RFC 4055 3.1.)
//
// It describes the algorithm and decides nothing: whether a weak signature
// on a trust anchor matters is the verifier's policy.
// ⚠ A POST-QUANTUM SIGNATURE HAS ONE LENGTH, AND IT IS CHECKED HERE.
//
// ML-DSA-65's is 3309 bytes, SLH-DSA-SHA2-128s's 7856: the parameter set
// fixes it. A signature of another length is not one a verifier can be
// asked about - it is a truncated file, or a signature of another set
// under this OID. `fail` is the caller's, so the error is the reader's.
function check_signature_length(params, signature, family_fail) {
  if (params && params.signature_length !== undefined &&
      signature.length !== params.signature_length) {
    family_fail('bad-signature-length',
      params.name + ' signatures are ' + params.signature_length +
      ' bytes; this one is ' + signature.length);
  }
}

// The fixed signature length of a post-quantum signature algorithm, by
// name - undefined for every other algorithm, whose lengths vary.
function signature_length(name) {
  var key = typeof name === 'string'
    ? name.replace(/^hashMlDsa(\d+)WithSha512$/, 'mlDsa$1') : '';
  var k = Object.prototype.hasOwnProperty.call(PQ_KEYS, key) ? PQ_KEYS[key] : undefined;
  return k === undefined ? undefined : k.signature;
}

// describe(), and the signature's length checked against it - what every
// reader of a signed structure calls.
function describe_signature(alg, signature, family_fail) {
  var p = describe(alg);
  check_signature_length(p, signature, family_fail);
  return p;
}

var WEAK_HASHES = { md2: true, md4: true, md5: true, sha1: true };

function describe(alg) {
  var out = describe_algorithm(alg);
  out.weak = is_weak_hash(out.hash);
  return out;
}

// The rule alone, for a reader that learns the hash elsewhere - CMS, where
// rsaEncryption as a signature algorithm takes its hash from the
// digestAlgorithm field.
function is_weak_hash(name) {
  return name !== null && name !== undefined && WEAK_HASHES[name] === true;
}

function describe_algorithm(alg) {
  var name = OID.name_of(alg.algorithm);
  var params = alg.parameters;
  var out = { name: name === null ? OID.to_string(alg.algorithm) : name,
              scheme: null, hash: null };

  if (name === null) {
    return out;
  }

  if (name === 'rsassaPss') {
    if (params === undefined) {
      fail('missing-parameters',
        'RSASSA-PSS in a signature algorithm needs its parameters (RFC ' +
        '4055 3.1); without them the hash and salt length are unknown');
    }
    out.scheme = 'pss';
    out.pss = read_pss(params);
    out.hash = out.pss.hash;
    return out;
  }

  if (name === 'rsaOAEP') {
    out.scheme = 'oaep';
    out.oaep = params === undefined ? oaep_defaults() : read_oaep(params);
    out.hash = out.oaep.hash;
    return out;
  }

  if (name === 'rsaEncryption') {
    // As a key-transport algorithm (CMS ktri) it is PKCS#1 v1.5 encryption.
    null_or_absent(params, name);
    out.scheme = 'rsa';
    return out;
  }

  if (/WithRSA/.test(name) || name === 'oiwSha1WithRSA') {
    null_or_absent(params, name);
    out.scheme = 'pkcs1';
    out.hash = implied_hash(name);
    return out;
  }

  // ⚠ THE POST-QUANTUM SIGNATURES: THE OID IS THE WHOLE ALGORITHM.
  //
  // ML-DSA (RFC 9881 2) and SLH-DSA (RFC 9909 3) name the parameter set in
  // the OID and the parameters MUST be absent - as for Ed25519, and for the
  // same reason: bytes the signature does not explain. Both are "pure"
  // here: the message goes in whole, so there is no hash to report. The
  // pre-hash variants name theirs.
  if (/^mlDsa\d+$/.test(name) || /^slhDsa(Sha2|Shake)_\d+[sf]$/.test(name) ||
      /^hashMlDsa\d+WithSha512$/.test(name)) {
    if (params !== undefined) {
      fail('unexpected-parameters',
        name + ' takes no parameters (RFC 9881 2, RFC 9909 3), and these ' +
        'are bytes the signature does not explain');
    }
    out.scheme = /^slh/.test(name) ? 'slh-dsa'
      : /^hash/.test(name) ? 'hash-ml-dsa' : 'ml-dsa';
    out.hash = /^hash/.test(name) ? 'sha512' : null;
    out.signature_length = signature_length(name);
    return out;
  }

  if (/^ecdsaWith|^dsaWith/.test(name) || name === 'oiwDsaWithSHA1' ||
      name === 'Ed25519' || name === 'Ed448') {
    if (params !== undefined) {
      fail('unexpected-parameters',
        name + ' takes no parameters (RFC 5758 3.2, RFC 8410 3), and these ' +
        'are bytes the signature does not explain');
    }
    out.scheme = /^ecdsa/.test(name) ? 'ecdsa'
      : /^dsa|^oiwDsa/.test(name) ? 'dsa' : 'eddsa';
    out.hash = out.scheme === 'eddsa' ? null : implied_hash(name);
    return out;
  }

  return out;
}

function null_or_absent(params, name) {
  if (params === undefined) { return; }
  if (params.length !== 2 || params[0] !== 0x05 || params[1] !== 0x00) {
    fail('unexpected-parameters',
      name + ' carries NULL parameters or none; these are something else');
  }
}

// A HashAlgorithm: an AlgorithmIdentifier whose parameters are NULL or
// absent (both are written in the wild, RFC 4055 2.1 says accept both).
function read_hash(r) {
  var seq = r.read_sequence();
  var name = OID.name_of(seq.read_oid());

  if (seq.remaining() > 0) {
    seq.read_null();
  }
  seq.expect_end();

  if (name === null || HASHES.indexOf(name) === -1) {
    fail('unsupported-hash', 'an unrecognised hash in RSA parameters');
  }
  return name;
}

// MaskGenAlgorithm: mgf1 with a HashAlgorithm as its parameter. MGF1 is the
// only one defined, so anything else is refused rather than reported.
function read_mgf(r) {
  var seq = r.read_sequence();
  var oid = OID.name_of(seq.read_oid());

  if (oid !== 'mgf1') {
    fail('unsupported-mgf', 'the mask generation function is not MGF1');
  }

  var hash = read_hash(seq);
  seq.expect_end();
  return hash;
}

function read_pss(params) {
  return DER.read(params, function (r) {
    var seq = r.read_sequence();
    var out = { hash: 'sha1', mgf: 'mgf1', mgf_hash: 'sha1',
                salt_length: 20, trailer: 1 };

    if (seq.peek_tag() === 0xA0) {
      var h = seq.read_explicit(0);
      out.hash = read_hash(h);
      h.expect_end();
      default_written(out.hash === 'sha1', 'hashAlgorithm sha1');
    }
    if (seq.peek_tag() === 0xA1) {
      var m = seq.read_explicit(1);
      out.mgf_hash = read_mgf(m);
      m.expect_end();
      default_written(out.mgf_hash === 'sha1', 'maskGenAlgorithm mgf1SHA1');
    }
    if (seq.peek_tag() === 0xA2) {
      var s = seq.read_explicit(2);
      out.salt_length = int_value(s.read_unsigned(), 'saltLength');
      s.expect_end();
      default_written(out.salt_length === 20, 'saltLength 20');
    }
    if (seq.peek_tag() === 0xA3) {
      var t = seq.read_explicit(3);
      out.trailer = int_value(t.read_unsigned(), 'trailerField');
      t.expect_end();
      default_written(out.trailer === 1, 'trailerField 1');
      if (out.trailer !== 1) {
        fail('bad-trailer', 'trailerField must be 1 (0xBC), RFC 4055 3.1');
      }
    }

    seq.expect_end();
    return out;
  });
}

function oaep_defaults() {
  return { hash: 'sha1', mgf: 'mgf1', mgf_hash: 'sha1',
           label: new Uint8Array(0) };
}

function read_oaep(params) {
  return DER.read(params, function (r) {
    var seq = r.read_sequence();
    var out = oaep_defaults();

    if (seq.peek_tag() === 0xA0) {
      var h = seq.read_explicit(0);
      out.hash = read_hash(h);
      h.expect_end();
      default_written(out.hash === 'sha1', 'hashFunc sha1');
    }
    if (seq.peek_tag() === 0xA1) {
      var m = seq.read_explicit(1);
      out.mgf_hash = read_mgf(m);
      m.expect_end();
      default_written(out.mgf_hash === 'sha1', 'maskGenFunc mgf1SHA1');
    }
    if (seq.peek_tag() === 0xA2) {
      var p = seq.read_explicit(2);
      var ps = p.read_sequence();
      if (OID.name_of(ps.read_oid()) !== 'pSpecified') {
        fail('unsupported-psource', 'pSourceFunc is not pSpecified');
      }
      out.label = ps.read_octet_string();
      ps.expect_end();
      p.expect_end();
      default_written(out.label.length === 0, 'pSourceFunc empty');
    }

    seq.expect_end();
    return out;
  });
}

// X.690 11.5: a value equal to its DEFAULT is omitted in DER. Writing it is
// a second encoding of the same parameters.
function default_written(is_default, what) {
  if (is_default) {
    fail('explicit-default',
      what + ' is the DEFAULT and DER omits it; writing it is a second ' +
      'encoding of the same parameters');
  }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

// A signature or key-transport AlgorithmIdentifier.
//
//   'ecdsaWithSHA256'                                   a name
//   { name: 'rsassaPss', hash: 'sha256', salt_length: 32 }
//   { name: 'rsaOAEP', hash: 'sha256', label: <bytes> }
//
// PSS and OAEP use the same hash for MGF1 unless `mgf_hash` says otherwise -
// which is what every implementation writes and what TLS 1.3 requires.
// Defaults are omitted, as DER requires.
function to_der(spec) {
  if (typeof spec === 'string') {
    if (spec === 'rsassaPss' || spec === 'rsaOAEP') {
      fail('missing-parameters',
        spec + ' needs its parameters: { name: "' + spec + '", hash: ' +
        '"sha256", ... }');
    }

    var oid;
    try {
      oid = OID.by_name(spec);
    } catch (e) {
      fail('unknown-algorithm', '"' + spec + '" is not a known algorithm');
    }

    var canonical = OID.canonical_name(spec);

    if (canonical.indexOf('WithRSA') !== -1 || canonical === 'rsaEncryption') {
      return W.sequence([W.oid(oid), W.null()]);
    }
    return W.sequence([W.oid(oid)]);
  }

  if (!spec || typeof spec !== 'object') {
    fail('bad-algorithm', 'an algorithm is a name or a parameter object');
  }

  var hash = spec.hash === undefined ? 'sha1' : spec.hash;
  var mgf_hash = spec.mgf_hash === undefined ? hash : spec.mgf_hash;

  if (HASHES.indexOf(hash) === -1 || HASHES.indexOf(mgf_hash) === -1) {
    fail('unsupported-hash', 'PSS and OAEP take sha1 to sha512');
  }

  var fields = [];

  if (hash !== 'sha1') {
    fields.push(W.explicit(0, hash_to_der(hash)));
  }
  if (mgf_hash !== 'sha1') {
    fields.push(W.explicit(1, W.sequence([W.oid(OID.by_name('mgf1')),
      hash_to_der(mgf_hash)])));
  }

  if (spec.name === 'rsassaPss') {
    var salt = spec.salt_length === undefined
      ? OID.digest_size(hash) : spec.salt_length;

    if (typeof salt !== 'number' || salt < 0 || salt % 1 !== 0) {
      fail('bad-salt-length', 'salt_length is a non-negative integer');
    }
    if (salt !== 20) {
      fields.push(W.explicit(2, W.unsigned(int_bytes(salt))));
    }

    return W.sequence([W.oid(OID.by_name('rsassaPss')), W.sequence(fields)]);
  }

  if (spec.name === 'rsaOAEP') {
    var label = spec.label === undefined
      ? new Uint8Array(0) : to_bytes(spec.label);

    if (label.length > 0) {
      fields.push(W.explicit(2, W.sequence([W.oid(OID.by_name('pSpecified')),
        W.octet_string(label)])));
    }

    return W.sequence([W.oid(OID.by_name('rsaOAEP')), W.sequence(fields)]);
  }

  return to_der(spec.name);
}

// RFC 4055 2.1 says SHOULD omit the NULL; OpenSSL writes it. What OpenSSL
// writes is what this matches, for the reason pkix.digest_algorithm_to_der
// gives.
function hash_to_der(name) {
  return W.sequence([W.oid(OID.by_name(name)), W.null()]);
}

// ---------------------------------------------------------------------------
// Names: the library's own, and node:crypto's
// ---------------------------------------------------------------------------
//
// ⚠ ONE VOCABULARY OUT, TWO ACCEPTED IN.
//
// The library reported a cipher as 'aes256CBC' in one structure and
// 'aes-256-cbc' in another - in the same message, for a CMS password
// recipient - and a PRF as 'hmacWithSHA256' here and 'hmac-sha256' there.
// What it RETURNS is now always the OID-table name, the one the file
// carries. What it TAKES may be either spelling, because the other one is
// what node:crypto and OpenSSL call the same algorithm, and a caller who
// has it in hand should not have to translate. canonical_name() is that
// translation; node_name() goes the other way.
//
// JOSE, COSE and SSH have their own registered names (ES256, A128GCM,
// aes256-ctr) and keep them.
var NODE_NAMES = {
  aes128CBC: 'aes-128-cbc', aes192CBC: 'aes-192-cbc', aes256CBC: 'aes-256-cbc',
  aes128ECB: 'aes-128-ecb', aes192ECB: 'aes-192-ecb', aes256ECB: 'aes-256-ecb',
  aes128GCM: 'aes-128-gcm', aes192GCM: 'aes-192-gcm', aes256GCM: 'aes-256-gcm',
  aes128CCM: 'aes-128-ccm', aes192CCM: 'aes-192-ccm', aes256CCM: 'aes-256-ccm',
  aes128Wrap: 'id-aes128-wrap', aes192Wrap: 'id-aes192-wrap',
  aes256Wrap: 'id-aes256-wrap',
  des_ede3_cbc: 'des-ede3-cbc',
  // node needs OpenSSL's legacy provider for this one (--openssl-legacy-provider).
  desCBC: 'des-cbc',
  rc2CBC: 'rc2-cbc',
  // An HMAC's node name is its HASH: createHmac('sha256', ...) and
  // pbkdf2Sync(..., 'sha256') both take that.
  hmacWithSHA1: 'sha1', hmacWithSHA224: 'sha224', hmacWithSHA256: 'sha256',
  hmacWithSHA384: 'sha384', hmacWithSHA512: 'sha512',
  sha1: 'sha1', sha224: 'sha224', sha256: 'sha256', sha384: 'sha384',
  sha512: 'sha512'
};

// The OpenSSL spellings accepted on input, besides the node names above.
var ALIASES = {
  'hmac-sha1': 'hmacWithSHA1', 'hmac-sha224': 'hmacWithSHA224',
  'hmac-sha256': 'hmacWithSHA256', 'hmac-sha384': 'hmacWithSHA384',
  'hmac-sha512': 'hmacWithSHA512', 'rc2-40-cbc': 'rc2CBC'
};

var FROM_NODE = {};
(function () {
  var k;
  for (k in NODE_NAMES) {
    if (Object.prototype.hasOwnProperty.call(NODE_NAMES, k) &&
        !/^hmacWith/.test(k)) {
      FROM_NODE[NODE_NAMES[k]] = k;
    }
  }
  for (k in ALIASES) {
    if (Object.prototype.hasOwnProperty.call(ALIASES, k)) {
      FROM_NODE[k] = ALIASES[k];
    }
  }
}());

// 'aes-256-cbc' -> 'aes256CBC', 'hmac-sha256' -> 'hmacWithSHA256'. A name
// already canonical comes back unchanged; anything else is refused rather
// than passed on, so a typo fails here and not as "unsupported" later.
function canonical_name(name) {
  if (typeof name !== 'string') {
    fail('bad-algorithm', 'an algorithm name is a string');
  }
  if (Object.prototype.hasOwnProperty.call(NODE_NAMES, name)) {
    return name;
  }
  if (Object.prototype.hasOwnProperty.call(FROM_NODE, name)) {
    return FROM_NODE[name];
  }
  if (known_oid_name(name)) {
    return name;
  }
  fail('unknown-algorithm', '"' + name + '" is not an algorithm name this ' +
    'library knows, in either spelling');
}

function known_oid_name(name) {
  try {
    OID.by_name(name);
    return true;
  } catch (e) {
    return false;
  }
}

// 'aes256CBC' -> 'aes-256-cbc', 'hmacWithSHA256' -> 'sha256' - the string
// node:crypto takes. key_length matters only for RC2, whose node name
// carries it: rc2CBC with 5 bytes is 'rc2-40-cbc'.
function node_name(name, key_length) {
  var c = canonical_name(name);

  if (c === 'rc2CBC' && key_length === 5) {
    return 'rc2-40-cbc';
  }
  if (!Object.prototype.hasOwnProperty.call(NODE_NAMES, c)) {
    fail('no-node-name', c + ' has no node:crypto name - it is not a ' +
      'cipher, MAC or hash node implements by name');
  }
  return NODE_NAMES[c];
}

export {
  // For an RSA-PSS key's parameters (spki.js), which are the same structure
  // as a PSS signature's - but optional there, so not through describe().
  read_pss as read_pss_params,
  check_signature_length,
  describe_signature,
  signature_length,
  describe,
  is_weak_hash,
  to_der,
  implied_hash,
  canonical_name,
  node_name
};
