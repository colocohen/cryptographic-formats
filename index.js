// cryptographic-formats - container and encoding formats around cryptography.
//
// Three levels, each named for what it is, so a caller who drops to a lower
// one knows they have dropped.
//
//   sniff(bytes)              level 2 - "just read this", and it reports what
//                             it guessed
//   spki.from_der(bytes)      level 1 - a specific format
//   der.read(bytes, fn)       level 0 - for structures this library does not
//                             cover
//
// Level 0 is exported deliberately. There are more ASN.1 structures in the
// world than this library will ever describe, and a caller who cannot reach
// the reader does not abandon their requirement - they install a
// BER-permissive parser, and the strictness is lost entirely. Better that
// they stay here.
//
// ⚠ THIS LIBRARY PERFORMS NO CRYPTOGRAPHY.
//
// Where a format contains a cryptographic operation it reports what the
// operation is and hands over the exact bytes it applies to; the caller
// performs it and hands the result back. See DECISIONS 0.1.
//
// ⚠ AND EVERY SIGNED STRUCTURE RETURNS THE ORIGINAL BYTES OF THE SIGNED
// PORTION - `tbs_bytes`, a JWS signing input, a CMS signedAttrs with its tag
// substituted. Never a re-encode: a structure whose DER deviates from
// canonical form would hash differently after a round trip, and its signature
// would fail to verify for reasons that look like a bad key.

// --- level 0: the encodings -------------------------------------------------

import * as der from './src/der_reader.js';
import * as der_writer from './src/der_writer.js';
// ⚠ Imported to RE-EXPORT at level 0, and never called here. The rule that
// only pkcs12.js may USE the BER reader still holds - see structure.test.js,
// which distinguishes the two. Exporting it is the point of level 0: a caller
// with a Windows-written .p12 needs a way to reach it.
import * as ber from './src/ber_reader.js';
import * as fields from './src/fields.js';
import * as tags from './src/tags.js';
import * as oid from './src/oid.js';
import * as real from './src/real.js';
import * as cbor from './src/cbor_reader.js';
import * as cbor_writer from './src/cbor_writer.js';
import * as json from './src/json.js';
import * as base from './src/base.js';
import * as bech32 from './src/bech32.js';
import * as multiformats from './src/multiformats.js';

// --- level 1: the formats ---------------------------------------------------

import * as pem from './src/pem.js';
import * as spki from './src/spki.js';
import * as pkcs8 from './src/pkcs8.js';
import * as pkcs12 from './src/pkcs12.js';
import * as pbes2 from './src/pbes2.js';
import * as x509 from './src/x509.js';
import * as csr from './src/csr.js';
import * as crl from './src/crl.js';
import * as ocsp from './src/ocsp.js';
import * as cms from './src/cms.js';
import * as cms_enveloped from './src/cms_enveloped.js';
import * as tsp from './src/tsp.js';
import * as smime from './src/smime.js';
import * as saml from './src/saml.js';
import * as attrcert from './src/attrcert.js';
import * as crmf from './src/crmf.js';
import * as cmp from './src/cmp.js';
import * as sct from './src/sct.js';
import * as signature from './src/signature.js';
import * as x509_build from './src/x509_build.js';
import * as csr_build from './src/csr_build.js';
import * as cms_build from './src/cms_build.js';
import * as crl_build from './src/crl_build.js';
import * as attrcert_build from './src/attrcert_build.js';
import * as crmf_build from './src/crmf_build.js';
import * as cmp_build from './src/cmp_build.js';
import * as scep from './src/scep.js';
import * as scep_build from './src/scep_build.js';
import * as ocsp_build from './src/ocsp_build.js';
import * as tsp_build from './src/tsp_build.js';
import * as cms_enveloped_build from './src/cms_enveloped_build.js';
import * as pkcs12_build from './src/pkcs12_build.js';
import * as algorithm from './src/algorithm.js';
import * as jwt from './src/jwt.js';
import * as xml from './src/xml_reader.js';
import * as jwk from './src/jwk.js';
import * as jws from './src/jws.js';
import * as jwe from './src/jwe.js';
import * as cose from './src/cose.js';
import * as cwt from './src/cwt.js';
import * as sd_jwt from './src/sd_jwt.js';
import * as openpgp from './src/openpgp.js';
import * as openpgp_build from './src/openpgp_build.js';
import * as webauthn from './src/webauthn.js';
import * as fido_mds from './src/fido_mds.js';
import * as ssh from './src/ssh.js';
import * as params from './src/params.js';

import { FormatError } from './src/error.js';
import { to_bytes } from './src/commons/bytes.js';
import { latin1 } from './src/commons/decode_text.js';
import { ascii } from './src/commons/encode_text.js';
import { make_fail_here } from './src/commons/fail.js';

var fail = make_fail_here('sniff');

// ---------------------------------------------------------------------------
// Level 2: sniff
// ---------------------------------------------------------------------------

// ⚠ THE ONLY FUNCTION IN THIS LIBRARY THAT GUESSES, AND IT ALWAYS SAYS WHAT
// IT GUESSED.
//
// Everything else takes bytes it was told the shape of. This takes bytes and
// works it out, which is a convenience and a risk in the same call - so the
// result carries `format`, and a caller who acts on `value` without reading
// that has skipped the only thing that makes guessing safe.
//
// A PEM label NARROWS the search rather than widening it. A block labelled
// CERTIFICATE is tried as a certificate and nothing else: a file that says
// what it is and is not that is a file to refuse, not a file to keep guessing
// about.
function sniff(input, options) {
  var opts = options || {};

  if (typeof input === 'string') {
    return sniff_text(input, opts);
  }

  var bytes = to_bytes(input);

  if (bytes.length === 0) {
    fail('empty-input', 'nothing to identify');
  }

  // ⚠ A PEM FILE ARRIVING AS BYTES, WHICH IS THE NORMAL CASE.
  //
  // `fs.readFileSync(path)` without an encoding returns a Buffer, so a
  // caller following the README's first example lands here rather than in
  // sniff_text - and a PEM with explanatory text above the block does not
  // start with 0x2D.
  //
  // The first version checked only the first byte and refused exactly the
  // file the README used as its example. The text path already handled it;
  // the byte path did not, and the two disagreed.
  if (bytes[0] === 0x2D || contains_pem_marker(bytes)) {
    return sniff_text(latin1(bytes), opts);
  }

  // An OpenSSH public key line.
  if (bytes[0] === 0x73 || bytes[0] === 0x65) {
    if (/^(ssh-|ecdsa-sha2-|sk-)/.test(latin1(bytes.subarray(0, 16)))) {
      return { format: 'ssh-public',
               value: ssh.key_from_text(latin1(bytes)) };
    }
  }

  if (bytes[0] === 0x7B) {
    return sniff_json(latin1(bytes));
  }

  if (looks_compact(bytes)) {
    return sniff_compact(latin1(bytes));
  }

  // A CBOR map: an attestation object or a COSE structure.
  if ((bytes[0] & 0xE0) === 0xA0 || (bytes[0] & 0xE0) === 0xC0) {
    return sniff_cbor(bytes);
  }

  if (bytes[0] === 0x30) {
    return sniff_der(bytes, opts);
  }

  // ⚠ An S/MIME message arriving as bytes, which is how a mail file arrives.
  //
  // Found by the raw-bytes half of the fixture sweep: the text path
  // recognised it by its headers and the byte path had no case for it at
  // all, so the same file read two ways gave two answers.
  //
  // A MIME header block is printable ASCII, so a cheap look at the first
  // line is enough to decide whether to hand it to the text path.
  if (looks_like_headers(bytes)) {
    return sniff_text(latin1(bytes), opts);
  }

  fail('unrecognised',
    'the first byte is 0x' + bytes[0].toString(16) +
    ', which begins none of the formats this library reads');
}

// ---------------------------------------------------------------------------

// ⚠ THE ORDER MATTERS AND IS NOT ARBITRARY.
//
// Several of these begin with a SEQUENCE holding an INTEGER, and a PKCS#8
// read as a PKCS#1 does not fail cleanly - it produces a key whose fields are
// the wrong numbers. So the candidates carrying a distinguishing OID early
// come first, and each attempt must parse COMPLETELY or be discarded.
var DER_CANDIDATES = [
  { format: 'x509',    read: function (b) { return x509.from_der(b); } },
  { format: 'attribute-certificate',
    read: function (b) { return attrcert.from_der(b); } },
  { format: 'csr',     read: function (b) { return csr.from_der(b); } },
  { format: 'cmp',     read: function (b) { return cmp.from_der(b); } },
  { format: 'crmf',    read: function (b) { return crmf.from_der(b); } },
  { format: 'crl',     read: function (b) { return crl.from_der(b); } },
  { format: 'cms',     read: function (b) { return cms.from_der(b); } },
  { format: 'cms-enveloped',
    read: function (b) { return cms_enveloped.from_der(b); } },
  { format: 'cms-auth-enveloped',
    read: function (b) { return cms_enveloped.auth_from_der(b); } },
  { format: 'cms-authenticated',
    read: function (b) { return cms_enveloped.authenticated_from_der(b); } },
  { format: 'cms-compressed',
    read: function (b) { return cms_enveloped.compressed_from_der(b); } },
  { format: 'cms-digested',
    read: function (b) { return cms_enveloped.digested_from_der(b); } },
  { format: 'cms-encrypted',
    read: function (b) { return cms_enveloped.encrypted_from_der(b); } },
  { format: 'pkcs12',  read: function (b) { return pkcs12.from_der(b); } },
  { format: 'ocsp-response',
    read: function (b) { return ocsp.response_from_der(b); } },
  { format: 'tsp-response',
    read: function (b) { return tsp.response_from_der(b); } },
  { format: 'spki',    read: function (b) { return spki.from_der(b); } },
  { format: 'pkcs8',   read: function (b) { return pkcs8.from_der(b); } },
  { format: 'pkcs8-encrypted',
    read: function (b) { return pkcs8.encrypted_from_der(b); } },
  { format: 'sec1',    read: function (b) { return pkcs8.sec1_from_der(b); } },
  { format: 'pkcs1',   read: function (b) { return pkcs8.pkcs1_from_der(b); } },
  { format: 'ocsp-request',
    read: function (b) { return ocsp.request_from_der(b); } },
  { format: 'tsp-request',
    read: function (b) { return tsp.request_from_der(b); } },
  { format: 'dhparam', read: function (b) { return params.dh_from_der(b); } }
];

function sniff_der(bytes, opts) {
  var only = opts.expect;
  var tried = [];
  var i;

  for (i = 0; i < DER_CANDIDATES.length; i++) {
    var candidate = DER_CANDIDATES[i];

    if (only !== undefined && candidate.format !== only) {
      continue;
    }

    try {
      return { format: candidate.format, value: candidate.read(bytes) };
    } catch (e) {
      tried.push(candidate.format);
    }
  }

  fail('unrecognised-der',
    'this is a DER SEQUENCE and it parsed as none of: ' + tried.join(', ') +
    '. Use the level 1 reader for the format you expect - its error will ' +
    'say what is actually wrong, where this one can only say that nothing ' +
    'matched.');
}

// ---------------------------------------------------------------------------

var PEM_LABELS = {
  'CERTIFICATE':             'x509',
  'X509 CERTIFICATE':        'x509',
  'CERTIFICATE REQUEST':     'csr',
  'NEW CERTIFICATE REQUEST': 'csr',
  'X509 CRL':                'crl',
  'PUBLIC KEY':              'spki',
  'PRIVATE KEY':             'pkcs8',
  'ENCRYPTED PRIVATE KEY':   'pkcs8-encrypted',
  'RSA PRIVATE KEY':         'pkcs1',
  'EC PRIVATE KEY':          'sec1',
  'EC PARAMETERS':           'ecparam',
  'DH PARAMETERS':           'dhparam',
  'PKCS7':                   'cms',
  'CMS':                     'cms',
  'OPENSSH PRIVATE KEY':     'openssh-private',
  'SSH SIGNATURE':           'ssh-signature',

  // ⚠ ADDED AFTER A SWEEP AGAINST RFC 7468 AND WHAT OPENSSL ACTUALLY WRITES.
  //
  // `TRUSTED CERTIFICATE` is what `openssl x509 -trustout` produces, and a
  // trust store built that way is full of them. The body is NOT a plain
  // certificate - it is a certificate followed by an auxiliary structure
  // holding the trust settings - so reading it as one would leave trailing
  // bytes, and reporting that as a malformed certificate would be wrong
  // twice over.
  'TRUSTED CERTIFICATE':     'trusted-certificate',

  // RFC 7468 5.10 - read by attrcert.js, RFC 5755.
  'ATTRIBUTE CERTIFICATE':   'attribute-certificate',

  // `openssl dsa` still writes these.
  'DSA PRIVATE KEY':         'dsa-private',
  'DSA PARAMETERS':          'dsa-parameters',

  // PKCS#1 RSAPublicKey on its own, without the SPKI wrapper.
  'RSA PUBLIC KEY':          'pkcs1-public'
};

// Labels this library RECOGNISES and does not read. Naming them is the
// point: "a bare DSAPrivateKey is not read; use PKCS#8" sends a caller
// somewhere, where "unrecognised PEM label" sends them nowhere.
var UNREAD_LABELS = {
  'dsa-private':
    'DSA private keys are read as PKCS#8; a bare DSAPrivateKey is not',
  'dsa-parameters':
    'DSA domain parameters are not read; params.js covers DH and EC'
};

function sniff_text(text, opts) {
  var trimmed = text.replace(/^\s+/, '');

  // ⚠ A PEM BLOCK MAY HAVE ANYTHING ABOVE IT.
  //
  // `openssl x509 -text` writes a human-readable dump before the block, and
  // that file is one people hand to a parser every day. RFC 7468 section 5.2
  // permits the text explicitly - it calls it "explanatory text" - so
  // requiring the file to BEGIN with the marker refuses a legal and common
  // file.
  //
  // pem.js already skips it; this only has to notice that a block is in
  // there somewhere.
  // OpenPGP's armour looks like PEM and is not: headers, a blank line, an
  // optional checksum (RFC 9580 6.2).
  if (/^-----BEGIN PGP SIGNED MESSAGE-----/.test(trimmed)) {
    return { format: 'openpgp-cleartext', value: openpgp.cleartext_decode(text) };
  }
  if (/^-----BEGIN PGP /.test(trimmed)) {
    var armor = openpgp.armor_decode(text);
    return { format: 'openpgp', armor: armor, value: openpgp.packets_from_bytes(armor.data) };
  }
  if (/^-----BEGIN /.test(trimmed) || /\n-----BEGIN /.test(text)) {
    return sniff_pem(text, opts);
  }
  if (/^\S+-cert-v01@openssh\.com\s/.test(trimmed)) {
    return { format: 'ssh-certificate', value: ssh.certificate_from_text(text) };
  }
  if (/^(ssh-|ecdsa-sha2-|sk-)/.test(trimmed)) {
    return { format: 'ssh-public', value: ssh.key_from_text(text) };
  }
  if (trimmed.charAt(0) === '{') {
    return sniff_json(text);
  }
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\./.test(trimmed)) {
    return sniff_compact(trimmed);
  }
  if (/^(Content-Type|MIME-Version):/im.test(text)) {
    return { format: 'smime', value: smime.from_bytes(ascii(text)) };
  }

  fail('unrecognised', 'this text begins none of the formats read here');
}

function sniff_pem(text, opts) {
  var blocks = pem.decode(text);

  if (blocks.length === 0) {
    fail('no-pem-blocks', 'no PEM block found');
  }

  // Several blocks is a chain or a bundle, and picking one would be a
  // decision this function must not make on the caller's behalf.
  if (blocks.length > 1) {
    return {
      format: 'pem-bundle',
      labels: blocks.map(function (b) { return b.label; }),
      value:  blocks,
      note:   'several PEM blocks. Read them individually - which one you ' +
              'want is a question this cannot answer.'
    };
  }

  var block = blocks[0];

  if (block.encrypted) {
    return {
      format: 'legacy-encrypted-pem',
      label:  block.label,
      value:  block,
      note:   'a legacy RFC 1421 encrypted PEM: the key is encrypted with a ' +
              'password and an IV taken from the headers, not with PBES2.'
    };
  }

  var expected = PEM_LABELS[block.label];

  if (expected === undefined) {
    fail('unknown-pem-label',
      'unrecognised PEM label "' + block.label + '"');
  }

  if (expected === 'openssh-private') {
    return { format: expected, value: ssh.private_from_pem(text) };
  }
  if (expected === 'ssh-signature') {
    return { format: expected, value: ssh.sshsig_from_wire(block.der) };
  }
  if (expected === 'attribute-certificate') {
    return { format: expected, label: block.label,
             value: attrcert.from_der(block.der) };
  }

  if (UNREAD_LABELS[expected] !== undefined) {
    fail('label-not-read',
      'this is a "' + block.label + '" block. ' + UNREAD_LABELS[expected] +
      '.');
  }

  if (expected === 'trusted-certificate') {
    // ⚠ The body is a certificate FOLLOWED BY a trust structure, so it does
    // not parse as a bare certificate. The certificate is captured and the
    // rest reported rather than discarded - a trust store entry says what it
    // is trusted FOR, and dropping that would be dropping the point of the
    // file.
    return read_trusted_certificate(block);
  }

  if (expected === 'pkcs1-public') {
    return { format: expected, label: block.label, value: block.der,
             note: 'a bare PKCS#1 RSAPublicKey, without the SPKI wrapper ' +
                   'that names the algorithm. Read it with der directly, or ' +
                   'wrap it in a SubjectPublicKeyInfo.' };
  }

  if (expected === 'ecparam') {
    return { format: expected, value: params.ec_from_der(block.der) };
  }
  if (expected === 'dhparam') {
    // Routed explicitly rather than through the candidate list: the label
    // has already said what this is, and dh_from_der's own error is far
    // more use than "nothing matched".
    return { format: expected, value: params.dh_from_der(block.der) };
  }

  // ⚠ THE LABEL NARROWS. A block that says CERTIFICATE is tried as a
  // certificate and nothing else.
  var found = sniff_der(block.der, { expect: expected });
  found.label = block.label;
  return found;
}

// ---------------------------------------------------------------------------

// `openssl x509 -trustout` writes a certificate followed by an auxiliary
// structure. Reading it as a plain certificate leaves trailing bytes, and
// reporting THAT as a malformed certificate would be wrong twice over.
function read_trusted_certificate(block) {
  // The certificate is the first complete value; whatever follows is the
  // trust structure. A bare reader rather than read(), which would insist
  // the whole input is one value - the very thing this file is not.
  var reader = der.reader(block.der);
  var cert = x509.from_der(reader.capture());
  var rest = block.der.subarray(reader.pos);

  return {
    format: 'trusted-certificate',
    label:  'TRUSTED CERTIFICATE',
    value:  cert,
    // Not parsed: CertAux is an OpenSSL structure rather than a standard
    // one, and a trust store's settings are the caller's to interpret.
    trust_settings: rest.length > 0 ? rest : null,
    note: rest.length > 0
      ? 'this certificate carries OpenSSL trust settings (' + rest.length +
        ' bytes), which say what it is trusted FOR'
      : null
  };
}

function sniff_json(text) {
  var doc = json.parse(text);

  if (json.has(doc, 'keys')) {
    return { format: 'jwks', value: jwk.set_from_json(doc) };
  }
  if (json.has(doc, 'ciphertext')) {
    return { format: 'jwe', value: jwe.decode(text) };
  }
  if (json.has(doc, 'signature') || json.has(doc, 'signatures')) {
    return { format: 'jws', value: jws.decode(text) };
  }
  if (json.has(doc, 'kty')) {
    return { format: 'jwk', value: jwk.to_key(doc) };
  }

  fail('unrecognised-json',
    'a JSON document with no kty, keys, signature or ciphertext member');
}

function sniff_compact(text) {
  // RFC 9901 4: an SD-JWT is a JWT, then ~-separated Disclosures.
  if (text.indexOf('~') !== -1) {
    return { format: 'sd-jwt', value: sd_jwt.decode(text) };
  }

  var parts = text.replace(/\s+$/, '').split('.');

  if (parts.length === 3) {
    return { format: 'jws', value: jws.decode(text) };
  }
  if (parts.length === 5) {
    return { format: 'jwe', value: jwe.decode(text) };
  }

  fail('unrecognised',
    'a dotted base64url string with ' + parts.length + ' parts is neither a ' +
    'JWS (three) nor a JWE (five)');
}

function sniff_cbor(bytes) {
  // The CWT tag, 61, says what it is (RFC 8392 6) - nothing else starts so.
  if (bytes[0] === 0xD8 && bytes[1] === 0x3D) {
    return { format: 'cwt', value: cwt.decode(bytes) };
  }

  // The more specific one first: an attestation object has fmt, attStmt and
  // authData, where a COSE_Key has integer labels and could be anything.
  try {
    return { format: 'webauthn', value: webauthn.from_cbor(bytes) };
  } catch (e) {
    // fall through
  }

  try {
    var pairs = cbor.read(bytes, function (r) { return r.read_map(0); });
    return { format: 'cose-key', value: cose.key_from_cbor(pairs) };
  } catch (e) {
    fail('unrecognised-cbor',
      'CBOR that is neither a WebAuthn attestation object nor a COSE_Key');
  }
}

// ---------------------------------------------------------------------------

// Whether a PEM begin marker appears anywhere in the first few kilobytes.
// Bounded, because a large DER file must not be scanned end to end looking
// for text that is not there.
function contains_pem_marker(bytes) {
  var limit = bytes.length < 8192 ? bytes.length : 8192;
  var marker = '-----BEGIN ';
  var i;
  var j;

  for (i = 0; i + marker.length <= limit; i++) {
    if (bytes[i] !== 0x2D) {
      continue;
    }
    for (j = 0; j < marker.length; j++) {
      if (bytes[i + j] !== marker.charCodeAt(j)) {
        break;
      }
    }
    if (j === marker.length) {
      return true;
    }
  }

  return false;
}

// A first line of the shape `Name: value`, which is what a MIME or mail
// header block begins with.
function looks_like_headers(bytes) {
  var limit = bytes.length < 200 ? bytes.length : 200;
  var i;

  for (i = 0; i < limit; i++) {
    var b = bytes[i];

    if (b === 0x3A) {                  // ':'
      return i > 0;
    }
    if (b === 0x0A || b === 0x0D || b === 0x20) {
      return false;
    }
    if (b < 0x21 || b > 0x7E) {
      return false;
    }
  }

  return false;
}

function looks_compact(bytes) {
  var dots = 0;
  var i;

  for (i = 0; i < bytes.length && i < 4096; i++) {
    var b = bytes[i];

    if (b === 0x2E) {
      dots += 1;
      continue;
    }
    if (b === 0x0A || b === 0x0D) {
      break;
    }
    if (!((b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) ||
          (b >= 0x30 && b <= 0x39) || b === 0x2D || b === 0x5F ||
          b === 0x7E)) {
      return false;
    }
  }

  return dots === 2 || dots === 4;
}





// ---------------------------------------------------------------------------

export {
  // level 2
  sniff,

  // level 1 - one namespace per format, so a caller reads
  // `cryptographic-formats.x509.from_der(...)` and knows which document governs it
  pem, spki, pkcs8, pkcs12, pbes2,
  x509, csr, crl, ocsp, cms, cms_enveloped, tsp, smime, saml, attrcert,
  crmf, cmp, scep, sct, signature, algorithm,

  // the builders - each the writing half of the module it is named after
  x509_build, csr_build, cms_build, cms_enveloped_build, crl_build,
  ocsp_build, tsp_build, pkcs12_build, attrcert_build, crmf_build, cmp_build,
  scep_build,

  jwk, jws, jwe, jwt, sd_jwt, cose, cwt, webauthn, fido_mds,
  ssh, openpgp, openpgp_build, params,

  // level 0 - the encodings, for structures this library does not describe
  der, der_writer, ber, fields, tags, oid, real, xml,
  cbor, cbor_writer, json, base, bech32, multiformats,

  FormatError
};
