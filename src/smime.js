// S/MIME, RFC 8551 (and RFC 1847 for the multipart structure).
//
// CMS wrapped in MIME. cms.js does the signature; this module's job is to
// find the exact bytes that signature covers, which is where S/MIME goes
// wrong.
//
// ⚠ SCOPE. This is NOT a MIME library.
//
// It finds parts, reads the headers that decide how to treat them, and
// undoes the transfer encoding. It does not decode RFC 2047 words, handle
// nested multiparts beyond one level, or interpret Content-Disposition -
// none of that decides what was signed, which is the only question this
// module exists to answer. Anything more belongs to whatever built the
// message.
//
// ⚠ THE SIGNATURE COVERS THE FIRST PART INCLUDING ITS MIME HEADERS.
//
// Not the body. Not the decoded body. The first body part exactly as it
// appears in the transmitted message - its Content-Type line, its blank
// separator, its content - with CRLF line endings, and WITHOUT the trailing
// CRLF that belongs to the boundary delimiter that follows it.
//
// Every one of those is a way to get a signature that fails on a good
// message and reports nothing, because a wrong hash and a wrong key look
// identical.
//
// ⚠ AND CANONICALIZATION HAPPENS BEFORE SIGNING, NOT AFTER.
//
// RFC 8551 section 3.1.1: text is converted to canonical form - CRLF line
// endings - and THEN signed. A message written with bare LF and signed as-is
// verifies for the sender and nobody else, because every MIME transport
// normalises the line endings in transit.

import * as CMS from './cms.js';
import * as ENVELOPED from './cms_enveloped.js';
import * as B from './base.js';

import { make_fail_here } from './commons/fail.js';
import { to_bytes, bytes_equal, hex } from './commons/bytes.js';
import { ascii } from './commons/encode_text.js';
import { latin1 } from './commons/decode_text.js';

var fail = make_fail_here('smime');

// ---------------------------------------------------------------------------
// Bytes and lines
// ---------------------------------------------------------------------------

var CR = 0x0D;
var LF = 0x0A;

// A MIME header block and a boundary are ASCII by RFC 5322 and 2046, and
// read byte for character - which is latin1 from commons, not a third copy
// of the loop.
var ascii_of = latin1;

function ascii_bytes(text) {
  return new Uint8Array(ascii(text));
}

// ⚠ CANONICAL MIME FORM: every line ends CRLF.
//
// A bare LF becomes CRLF; an existing CRLF is left alone; a bare CR - which
// old Mac software produced - also becomes CRLF. Doing this AFTER signing is
// the mistake: the signature then covers bytes no recipient ever sees.
function canonicalize(input) {
  var bytes = to_bytes(input);
  var out = [];
  var i = 0;

  while (i < bytes.length) {
    var b = bytes[i];

    if (b === CR) {
      out.push(CR, LF);
      i += (i + 1 < bytes.length && bytes[i + 1] === LF) ? 2 : 1;
      continue;
    }
    if (b === LF) {
      out.push(CR, LF);
      i += 1;
      continue;
    }

    out.push(b);
    i += 1;
  }

  return new Uint8Array(out);
}

// Whether a byte string is already canonical. Reported rather than silently
// fixed, because a caller verifying an existing signature must know whether
// the bytes they hold are the bytes that were signed.
function is_canonical(input) {
  var bytes = to_bytes(input);
  var i;

  for (i = 0; i < bytes.length; i++) {
    if (bytes[i] === LF && (i === 0 || bytes[i - 1] !== CR)) {
      return false;
    }
    if (bytes[i] === CR && (i + 1 >= bytes.length || bytes[i + 1] !== LF)) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

// Splits a part into its header block and its body, and returns the OFFSET of
// the body so a caller can slice the original bytes rather than a copy.
//
// The separator is a blank line: CRLF CRLF, or LF LF in a message that never
// went through a transport.
function split_headers(bytes, from) {
  var i = from === undefined ? 0 : from;

  while (i < bytes.length) {
    if (bytes[i] === CR && i + 3 < bytes.length &&
        bytes[i + 1] === LF && bytes[i + 2] === CR && bytes[i + 3] === LF) {
      return { header_end: i, body_start: i + 4 };
    }
    if (bytes[i] === LF && i + 1 < bytes.length && bytes[i + 1] === LF) {
      return { header_end: i, body_start: i + 2 };
    }
    i += 1;
  }

  fail('no-header-separator',
    'no blank line separating headers from body');
}

// Parses a header block. Folded continuation lines - a line beginning with
// space or tab - are joined, because a Content-Type parameter may be folded
// and a parser that missed it would lose the boundary.
function parse_headers(text) {
  var lines = text.split(/\r\n|\n/);
  var out = [];
  var i;

  for (i = 0; i < lines.length; i++) {
    if (lines[i] === '') {
      continue;
    }

    if (/^[ \t]/.test(lines[i]) && out.length > 0) {
      out[out.length - 1].value += ' ' + lines[i].replace(/^[ \t]+/, '');
      continue;
    }

    var colon = lines[i].indexOf(':');

    if (colon === -1) {
      fail('bad-header', 'header line has no colon: "' + lines[i] + '"');
    }

    out.push({
      name:  lines[i].substring(0, colon).toLowerCase(),
      value: lines[i].substring(colon + 1).replace(/^\s+/, '')
    });
  }

  return out;
}

function header(headers, name) {
  var i;
  for (i = 0; i < headers.length; i++) {
    if (headers[i].name === name) {
      return headers[i].value;
    }
  }
  return null;
}

// A Content-Type value: the type, and its parameters. Quoted parameter values
// are unquoted, because `boundary="----X"` and `boundary=----X` name the same
// boundary and a parser that kept the quotes would match neither.
function content_type(value) {
  if (value === null) {
    return { type: null, params: {} };
  }

  var parts = value.split(';');
  var out = {
    type: parts[0].replace(/^\s+|\s+$/g, '').toLowerCase(),
    params: {}
  };
  var i;

  for (i = 1; i < parts.length; i++) {
    var eq = parts[i].indexOf('=');
    if (eq === -1) {
      continue;
    }

    var name = parts[i].substring(0, eq).replace(/^\s+|\s+$/g, '')
      .toLowerCase();
    var v = parts[i].substring(eq + 1).replace(/^\s+|\s+$/g, '');

    if (v.charAt(0) === '"' && v.charAt(v.length - 1) === '"') {
      v = v.substring(1, v.length - 1);
    }

    out.params[name] = v;
  }

  return out;
}

// ---------------------------------------------------------------------------
// Reading a message
// ---------------------------------------------------------------------------

// The two shapes S/MIME uses.
//
//   multipart/signed        the content is visible and a detached signature
//                           travels beside it. A recipient without S/MIME
//                           can still read the message.
//   application/pkcs7-mime  the whole thing is inside the CMS. Opaque.
function from_bytes(input) {
  var bytes = to_bytes(input);
  var split = split_headers(bytes, 0);
  var headers = parse_headers(ascii_of(bytes.subarray(0, split.header_end)));
  var ct = content_type(header(headers, 'content-type'));

  if (ct.type === 'multipart/signed') {
    return read_multipart_signed(bytes, headers, ct, split.body_start);
  }

  if (ct.type === 'application/pkcs7-mime' ||
      ct.type === 'application/x-pkcs7-mime') {
    return read_opaque(bytes, headers, ct, split.body_start);
  }

  fail('not-smime',
    'the content type is ' + (ct.type === null ? '(absent)' : ct.type) +
    ', which is neither multipart/signed nor application/pkcs7-mime');
}

function read_multipart_signed(bytes, headers, ct, body_start) {
  var boundary = ct.params.boundary;

  if (!boundary) {
    fail('no-boundary',
      'multipart/signed with no boundary parameter, so the parts cannot be ' +
      'found');
  }

  // RFC 1847: the protocol parameter says what the second part is, and it
  // must match. A message claiming one protocol and carrying another is one
  // where a verifier and a filter could disagree.
  var protocol = ct.params.protocol;

  var parts = split_parts(bytes, boundary, body_start);

  if (parts.length !== 2) {
    fail('bad-part-count',
      'multipart/signed has exactly two parts, found ' + parts.length);
  }

  var sig_part = read_part(bytes, parts[1]);
  var sig_type = content_type(header(sig_part.headers, 'content-type')).type;

  if (protocol && sig_type && protocol.toLowerCase() !== sig_type) {
    fail('protocol-mismatch',
      'the protocol parameter says ' + protocol + ' and the second part is ' +
      sig_type);
  }
  if (sig_type !== 'application/pkcs7-signature' &&
      sig_type !== 'application/x-pkcs7-signature') {
    fail('bad-signature-part',
      'the second part is ' + sig_type + ', not a pkcs7-signature');
  }

  var signature_der = decode_transfer(sig_part);

  return {
    kind:      'multipart/signed',
    headers:   headers,
    micalg:    ct.params.micalg || null,
    // ⚠ THE BYTES THE SIGNATURE COVERS: the first part INCLUDING its MIME
    // headers, exactly as transmitted, without the CRLF that belongs to the
    // boundary line following it.
    signed_bytes: bytes.subarray(parts[0].start, parts[0].end),
    // The content alone, for a caller who wants to display it. NOT what was
    // signed, and named so.
    content_only: read_part(bytes, parts[0]).body,
    cms:       CMS.from_der(signature_der),
    signature_der: signature_der,
    raw:       bytes
  };
}

function read_opaque(bytes, headers, ct, body_start) {
  var part = {
    start: body_start, end: bytes.length,
    body_start: body_start
  };

  var der = decode_transfer({
    headers: headers,
    body: bytes.subarray(body_start)
  });

  // smime-type says what the CMS holds. A message whose parameter and
  // content disagree is worth refusing rather than trusting either.
  var claimed = (ct.params['smime-type'] || '').toLowerCase();

  var cms = null;
  var enveloped = false;

  try {
    cms = CMS.from_der(der);
  } catch (e) {
    if (e.code === 'unsupported-content-type') {
      // envelopedData: this library reads the structure of signed messages
      // and not encrypted ones, and saying which is more use than a generic
      // refusal.
      enveloped = true;
    } else {
      throw e;
    }
  }

  if (enveloped) {
    // ⚠ NOT A REFUSAL ANY MORE. An encrypted S/MIME message is a real
    // message, and cms_enveloped.js reads it - so this returns rather than
    // fails, and the caller gets the recipients instead of an apology.
    return {
      kind:       'application/pkcs7-mime',
      headers:    headers,
      smime_type: claimed || 'enveloped-data',
      encrypted:  true,
      enveloped:  ENVELOPED.from_der(der),
      signature_der: der,
      raw:        bytes
    };
  }

  if (claimed === 'enveloped-data') {
    fail('smime-type-mismatch',
      'the smime-type parameter says enveloped-data and the content is ' +
      'signedData');
  }

  return {
    kind:      'application/pkcs7-mime',
    headers:   headers,
    smime_type: claimed || null,
    // An opaque message carries its content INSIDE the CMS, so what was
    // signed is the encapsulated content rather than any part of the MIME.
    signed_bytes: cms.content,
    content_only: cms.content,
    cms:       cms,
    signature_der: der,
    raw:       bytes
  };
}

// ---------------------------------------------------------------------------
// Boundaries
// ---------------------------------------------------------------------------

// ⚠ THE BOUNDARY RULES DECIDE WHAT WAS SIGNED, SO THEY ARE WORTH STATING.
//
// RFC 2046 section 5.1.1:
//
//   the delimiter is CRLF "--" boundary
//   the CRLF BEFORE it belongs to the delimiter, not to the part
//   the final delimiter is CRLF "--" boundary "--"
//
// That leading CRLF is the detail: a part's content ends at the byte before
// it. Including it gives a signing input two bytes too long, which fails
// silently.
function split_parts(bytes, boundary, from) {
  var marker = ascii_bytes('--' + boundary);
  var parts = [];
  var at = from;
  var open = null;

  while (at < bytes.length) {
    var found = find(bytes, marker, at);

    if (found === -1) {
      break;
    }

    // The delimiter must sit at the start of a line.
    var line_start = found === 0 ||
      (found >= 2 && bytes[found - 1] === LF && bytes[found - 2] === CR) ||
      (found >= 1 && bytes[found - 1] === LF);

    if (!line_start) {
      at = found + 1;
      continue;
    }

    if (open !== null) {
      // The CRLF immediately before the delimiter belongs to the delimiter.
      var end = found;
      if (end >= 2 && bytes[end - 1] === LF && bytes[end - 2] === CR) {
        end -= 2;
      } else if (end >= 1 && bytes[end - 1] === LF) {
        end -= 1;
      }

      parts.push({ start: open, end: end });
      open = null;
    }

    var after = found + marker.length;

    // The closing delimiter ends with two more hyphens.
    if (after + 1 < bytes.length &&
        bytes[after] === 0x2D && bytes[after + 1] === 0x2D) {
      return parts;
    }

    // Skip the line ending that follows the delimiter.
    if (after + 1 < bytes.length &&
        bytes[after] === CR && bytes[after + 1] === LF) {
      after += 2;
    } else if (after < bytes.length && bytes[after] === LF) {
      after += 1;
    }

    open = after;
    at = after;
  }

  if (open !== null) {
    fail('unterminated-multipart',
      'no closing boundary delimiter');
  }

  return parts;
}

function find(haystack, needle, from) {
  var i;
  var j;

  for (i = from; i + needle.length <= haystack.length; i++) {
    for (j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) {
        break;
      }
    }
    if (j === needle.length) {
      return i;
    }
  }
  return -1;
}

// ⚠ A BODY PART MAY HAVE NO HEADERS AT ALL.
//
// RFC 2046 section 5.1: "the absence of a Content-Type header implies
// text/plain; charset=us-ascii", and a part may begin immediately with its
// content. `openssl smime -sign` produces exactly that for the signed part.
//
// A parser that requires a blank separator refuses the commonest real
// message there is - which is what the first version of this function did.
//
// The distinction is made on the FIRST LINE: a header line has a colon
// before any whitespace. Content that happens to contain a colon later is
// not a header, and content whose first line looks like a header is
// ambiguous in the format itself - so the tie goes to treating it as a
// header, which is what every MIME reader does.
function read_part(bytes, span) {
  var region = bytes.subarray(span.start, span.end);

  if (!starts_with_header(region)) {
    return { headers: [], body: region, raw: region };
  }

  var split = split_headers(region, 0);

  return {
    headers: parse_headers(ascii_of(region.subarray(0, split.header_end))),
    body:    region.subarray(split.body_start),
    raw:     region
  };
}

function starts_with_header(bytes) {
  var i;

  for (i = 0; i < bytes.length; i++) {
    var b = bytes[i];

    if (b === 0x3A) {                  // ':'
      return i > 0;
    }
    if (b === CR || b === LF || b === 0x20 || b === 0x09) {
      return false;
    }
    // A header field name is printable ASCII other than colon.
    if (b < 0x21 || b > 0x7E) {
      return false;
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// Transfer encoding
// ---------------------------------------------------------------------------

// Undoes Content-Transfer-Encoding.
//
// ⚠ This is applied to the SIGNATURE part, never to the signed part. The
// signature travels base64-encoded and has to be decoded to be parsed; the
// signed part is signed AS TRANSMITTED, encoding and all, so decoding it
// would produce bytes nobody signed.
function decode_transfer(part) {
  var encoding = (header(part.headers, 'content-transfer-encoding') || '')
    .toLowerCase().replace(/^\s+|\s+$/g, '');

  if (encoding === 'base64') {
    // Line breaks are not part of the base64; the strict decoder would
    // refuse them, and relaxing base.js would relax it everywhere.
    var text = ascii_of(part.body).replace(/[\r\n\s]/g, '');
    try {
      return B.decode('base64', text);
    } catch (e) {
      fail('bad-base64',
        'the signature part: ' +
        e.message.replace(/^cryptographic-formats: base: /, ''));
    }
  }

  if (encoding === '' || encoding === 'binary' ||
      encoding === '7bit' || encoding === '8bit') {
    return part.body;
  }

  if (encoding === 'quoted-printable') {
    return decode_quoted_printable(part.body);
  }

  fail('unsupported-transfer-encoding',
    'unrecognised Content-Transfer-Encoding "' + encoding + '"');
}

function decode_quoted_printable(bytes) {
  var out = [];
  var i = 0;

  while (i < bytes.length) {
    if (bytes[i] !== 0x3D) {          // '='
      out.push(bytes[i]);
      i += 1;
      continue;
    }

    // A soft line break: "=" at end of line, which encodes nothing.
    if (i + 2 < bytes.length && bytes[i + 1] === CR && bytes[i + 2] === LF) {
      i += 3;
      continue;
    }
    if (i + 1 < bytes.length && bytes[i + 1] === LF) {
      i += 2;
      continue;
    }

    if (i + 2 >= bytes.length) {
      fail('bad-quoted-printable',
        'an "=" at the end with nothing after it');
    }

    var h = String.fromCharCode(bytes[i + 1], bytes[i + 2]);

    if (!/^[0-9A-Fa-f]{2}$/.test(h)) {
      fail('bad-quoted-printable',
        'expected two hex digits after "=", got "' + h + '"');
    }

    out.push(parseInt(h, 16));
    i += 3;
  }

  return new Uint8Array(out);
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// The plan for a signer, with the S/MIME-specific part filled in: the
// detached content a multipart/signed message's CMS needs is the first part
// as transmitted, which this module has already found.
//
// Delegated to cms.js for everything else - including the signedAttrs tag
// substitution, which must have exactly one implementation.
function verification_plan(message, signer_index) {
  var i = signer_index === undefined ? 0 : signer_index;
  var signer = message.cms.signers[i];

  if (signer === undefined) {
    fail('no-such-signer',
      'this message has ' + message.cms.signers.length + ' signers');
  }

  var plan = CMS.verification_plan(message.cms, signer,
    message.signed_bytes);

  plan.signer = signer;
  plan.canonical = is_canonical(message.signed_bytes);

  if (!plan.canonical) {
    // Worth surfacing rather than fixing: a caller verifying an existing
    // signature must know whether the bytes they hold are the bytes that
    // were signed. Canonicalizing here would change the hash.
    plan.note = plan.note + ' NOTE: the signed part is not in canonical ' +
      'MIME form (some line ending is not CRLF). If the signature fails, ' +
      'this is why - a transport normalised the line endings after signing.';
  }

  return plan;
}

// The digest algorithm the micalg parameter names, as an algorithm name
// rather than the MIME spelling. RFC 8551 section 3.4.3.2 writes SHA-256 as
// "sha-256" with a hyphen, and nothing else in this library does.
function micalg_digest(message) {
  if (message.micalg === null) {
    return null;
  }

  var name = message.micalg.toLowerCase().replace(/-/g, '');

  return { sha1: 'sha1', sha256: 'sha256', sha384: 'sha384',
           sha512: 'sha512' }[name] || null;
}

export {
  from_bytes,
  signed_part,
  wrap,
  wrap_opaque,
  canonicalize,
  is_canonical,
  verification_plan,
  micalg_digest,
  content_type,
  parse_headers,
  split_parts
};

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------
//
// ⚠ THE CRLF BEFORE THE BOUNDARY BELONGS TO THE DELIMITER, NOT TO THE PART.
//
// RFC 2046 5.1.1 defines the delimiter as CRLF followed by "--" and the
// boundary, so the line break that appears to end the signed part is
// actually the start of what follows it. A signature computed over the part
// INCLUDING that CRLF verifies nowhere, and the difference is two invisible
// bytes.
//
// This is the single thing that makes S/MIME hard to produce correctly, and
// it is why signed_part() exists: it returns exactly what to hash, and
// wrap() puts the same bytes back with the delimiter added.

// The bytes a signature covers: the part's MIME headers, a blank line, and
// the body - canonicalized, and WITHOUT the trailing CRLF.
function signed_part(content, headers) {
  var bytes = to_bytes(content);
  var lines = [];
  var name;

  var supplied = headers || {};
  var has_type = false;

  for (name in supplied) {
    if (Object.prototype.hasOwnProperty.call(supplied, name)) {
      lines.push(name + ': ' + supplied[name]);
      if (/^content-type$/i.test(name)) {
        has_type = true;
      }
    }
  }

  // ⚠ A PART WITH NO MIME HEADERS IS THE COMMONEST REAL MESSAGE.
  //
  // `openssl smime -sign` produces one, and the first version of the READER
  // in this module refused it. So the writer defaults to none rather than
  // inventing a Content-Type the caller did not ask for - what is signed is
  // what was given.
  var header_text = lines.length === 0 ? '' : lines.join('\r\n') + '\r\n\r\n';

  var header_bytes = ascii(header_text);
  var out = new Uint8Array(header_bytes.length + bytes.length);

  out.set(header_bytes, 0);
  out.set(bytes, header_bytes.length);

  // ⚠ CANONICALIZED BEFORE SIGNING, NOT AFTER.
  //
  // The signature covers the CRLF form, and a message whose line endings are
  // fixed up in transit still verifies - which is the whole reason
  // canonicalization exists here.
  return canonicalize(out);
}

// Wraps a signature and its content into a multipart/signed message.
//
//   var part = smime.signed_part(content, headers);
//   var cms  = cms_build...            // sign `part`
//   var eml  = smime.wrap({ part: part, signature: cms, digest: 'sha256' });
function wrap(parts) {
  if (parts === null || typeof parts !== 'object') {
    fail('bad-input', 'wrap takes an object');
  }

  if (!(parts.part instanceof Uint8Array)) {
    fail('bad-part',
      'wrap needs { part } - the bytes signed_part() returned, unchanged. ' +
      'Rebuilding them here would risk a byte the signature does not cover.');
  }

  if (!(parts.signature instanceof Uint8Array)) {
    fail('bad-signature',
      'wrap needs { signature } - a detached CMS SignedData over the part');
  }

  var digest = parts.digest || 'sha256';

  // ⚠ THE micalg PARAMETER NAMES THE DIGEST, and a receiver may use it to
  // decide whether it can check the signature at all. RFC 5751 3.4.3.2 fixes
  // the spelling - `sha-256`, with the hyphen, not `sha256`.
  var micalg = micalg_for(digest);

  var boundary = parts.boundary ||
    '----cryptographic-formats-' + hex(random_boundary());

  if (/[^A-Za-z0-9'()+_,\-./:=?]/.test(boundary)) {
    fail('bad-boundary',
      'a MIME boundary is drawn from a restricted character set - RFC 2046 ' +
      '5.1.1');
  }

  // ⚠ AND THE BOUNDARY MUST NOT APPEAR IN THE CONTENT.
  //
  // If it does, a reader splits the message in the wrong place and the
  // signature covers something other than what gets read. Checked rather
  // than assumed, because a random boundary makes it improbable and not
  // impossible - and "improbable" is not a property a signature check
  // should rest on.
  if (contains(parts.part, ascii('--' + boundary))) {
    fail('boundary-in-content',
      'the boundary string appears inside the signed content, so a reader ' +
      'would split the message somewhere the signature does not cover');
  }

  var header =
    'MIME-Version: 1.0\r\n' +
    'Content-Type: multipart/signed; protocol="application/pkcs7-signature";' +
    ' micalg=' + micalg + '; boundary="' + boundary + '"\r\n' +
    '\r\n' +
    'This is an S/MIME signed message\r\n' +
    '\r\n' +
    '--' + boundary + '\r\n';

  var between =
    // ⚠ THE CRLF THAT STARTS THIS BELONGS TO THE DELIMITER. The part above
    // ended without one, and this supplies it - which is exactly the
    // arrangement RFC 2046 5.1.1 describes and the one everybody gets wrong.
    '\r\n--' + boundary + '\r\n' +
    'Content-Type: application/pkcs7-signature; name="smime.p7s"\r\n' +
    'Content-Transfer-Encoding: base64\r\n' +
    'Content-Disposition: attachment; filename="smime.p7s"\r\n' +
    '\r\n';

  var footer = '\r\n--' + boundary + '--\r\n';

  var b64 = B.encode('base64', parts.signature)
    .replace(/(.{64})/g, '$1\r\n');

  return join([
    ascii(header),
    parts.part,
    ascii(between),
    ascii(b64),
    ascii(footer)
  ]);
}

// An application/pkcs7-mime message - the opaque form, where the whole
// message is inside the CMS structure.
var SMIME_TYPES = ['signed-data', 'enveloped-data', 'authEnveloped-data',
                   'compressed-data', 'certs-only'];

function wrap_opaque(signature, options) {
  if (!(signature instanceof Uint8Array)) {
    fail('bad-signature', 'wrap_opaque takes the CMS bytes');
  }

  var opts = options || {};
  var type = opts.smime_type || 'signed-data';

  // RFC 8551 3.2.2. The filename is smime.p7m for every one of them - the
  // ternary that chose between two identical names said otherwise.
  if (SMIME_TYPES.indexOf(type) === -1) {
    fail('bad-smime-type', 'smime-type is one of ' + SMIME_TYPES.join(', '));
  }
  var name = 'smime.p7m';

  var header =
    'MIME-Version: 1.0\r\n' +
    'Content-Disposition: attachment; filename="' + name + '"\r\n' +
    'Content-Type: application/pkcs7-mime; smime-type=' + type +
      '; name="' + name + '"\r\n' +
    'Content-Transfer-Encoding: base64\r\n' +
    '\r\n';

  var b64 = B.encode('base64', signature)
    .replace(/(.{64})/g, '$1\r\n');

  return join([ascii(header), ascii(b64), ascii('\r\n')]);
}

// RFC 5751 3.4.3.2. The hyphen is part of the spelling.
function micalg_for(digest) {
  var names = {
    sha1:   'sha1',
    sha224: 'sha-224',
    sha256: 'sha-256',
    sha384: 'sha-384',
    sha512: 'sha-512'
  };

  if (names[digest] === undefined) {
    fail('unsupported-digest',
      'no micalg name for "' + digest + '"');
  }

  return names[digest];
}

function contains(haystack, needle) {
  return find(haystack, needle, 0) !== -1;
}

function join(chunks) {
  var total = 0;
  var i;

  for (i = 0; i < chunks.length; i++) {
    total += chunks[i].length;
  }

  var out = new Uint8Array(total);
  var at = 0;

  for (i = 0; i < chunks.length; i++) {
    out.set(chunks[i], at);
    at += chunks[i].length;
  }

  return out;
}

// ⚠ NOT CRYPTOGRAPHIC, AND IT DOES NOT NEED TO BE.
//
// A MIME boundary needs to be unlikely to appear in the content, not
// unguessable - the signature is what provides the security and wrap()
// checks the boundary is absent regardless. Using Math.random keeps this
// module free of the crypto dependency the whole library refuses.
function random_boundary() {
  var out = new Uint8Array(12);
  var i;

  for (i = 0; i < out.length; i++) {
    out[i] = Math.floor(Math.random() * 256);
  }

  return out;
}
