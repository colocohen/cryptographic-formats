// PEM armour, RFC 7468.
//
// The format is trivial and the traps are not. Four of them, in order of how
// often they are missed:
//
//   1. A file holds MANY blocks. Certificate chains are the normal case, and
//      a parser that reads the first block and stops silently drops the rest
//      of the chain.
//   2. The BEGIN and END labels must MATCH. A parser that reads only BEGIN
//      accepts `BEGIN CERTIFICATE ... END PRIVATE KEY`, which is a file
//      claiming to be two things.
//   3. Text is allowed before and after a block, and OpenSSL puts a
//      human-readable dump there. It is skipped, not an error.
//   4. Legacy encrypted PEM - `Proc-Type: 4,ENCRYPTED` with `DEK-Info` - is a
//      THIRD thing, neither PKCS#8 nor PBES2. Read it, refuse to write it.


import * as B from './base.js';
import { make_fail_line } from './commons/fail.js';
import { to_bytes } from './commons/bytes.js';
import { latin1 } from './commons/decode_text.js';

var fail = make_fail_line('pem');


// ---------------------------------------------------------------------------
// base64
// ---------------------------------------------------------------------------

// Delegated to base.js rather than implemented again. There is one base64
// codec in this library and PEM uses it, which matters because the strictness
// is the point: a PEM body with non-zero bits after the last whole byte is
// the same malleability the DER reader refuses, and two implementations would
// be two chances to get that wrong.
//
// The wrappers exist because the errors should say `pem`, not `base`: a
// caller handed a certificate file wants to know their PEM is malformed, not
// that a codec they never called complained.

function base64_decode(text, line) {
  try {
    return B.decode('base64', text);
  } catch (e) {
    fail(e.code === 'non-canonical' ? 'non-canonical-base64' : 'bad-base64',
      e.message.replace(/^cryptographic-formats: base: /, ''), line);
  }
}

function base64_encode(bytes) {
  return B.encode('base64', bytes);
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

var BEGIN = /^-----BEGIN ([A-Za-z0-9 .-]*)-----[ \t]*$/;
var END   = /^-----END ([A-Za-z0-9 .-]*)-----[ \t]*$/;
var HEADER = /^([A-Za-z-]+):\s*(.*)$/;

// Returns every block in the file, in order.
//
// Always an array, never "the first block". A caller that wants one block can
// check the length; a caller handed only the first block has no way to know
// the rest existed.
//
// ⚠ ALL OR NOTHING, ON PURPOSE: one malformed block refuses the file. A
// bundle with a block that does not decode is a bundle something has been
// done to, and handing back the rest as if nothing happened is the
// silent-skip this library refuses elsewhere. decode_skipping is the
// explicit way to take the good blocks and a list of the bad.
function decode(text) {
  var lines = split_lines(text);
  var blocks = [];
  var i = 0;

  while (i < lines.length) {
    if (BEGIN.exec(lines[i]) === null) {
      // Explanatory text outside a block is allowed by RFC 7468 and OpenSSL
      // emits it. Skipped rather than refused.
      i += 1;
      continue;
    }
    var extent = block_extent(lines, i);
    blocks.push(read_block(lines, i, extent));
    i = extent.next;
  }

  if (blocks.length === 0) {
    fail('no-pem-block', 'no PEM block found');
  }

  return blocks;
}

// ⚠ THE GOOD BLOCKS, AND EVERY BAD ONE NAMED - FOR A TRUST STORE.
//
// node reading a CA bundle skips a block it cannot read, and a verifier
// loading one wants the same, rather than losing every anchor to one
// corrupt entry (reported from lemon). Not silently: the result is
// { blocks, skipped }, each skipped block with its label, line, and the
// error decode would have thrown - so the caller can log it, count it, or
// refuse the bundle after all. A block ends at its END line, or at the next
// BEGIN when it has none, and reading resumes there.
//
// Only PEM errors are skipped; what is inside a good block (a certificate
// that does not parse) is the caller's to skip. A file with no block at all
// is still refused.
function decode_skipping(text) {
  var lines = split_lines(text);
  var out = { blocks: [], skipped: [] };
  var i = 0;

  while (i < lines.length) {
    var begin = BEGIN.exec(lines[i]);
    if (begin === null) {
      i += 1;
      continue;
    }
    var extent = block_extent(lines, i);
    try {
      out.blocks.push(read_block(lines, i, extent));
    } catch (e) {
      if (e.family !== 'pem') { throw e; }
      out.skipped.push({ label: begin[1], line: i + 1, code: e.code,
        detail: e.message.replace(/^cryptographic-formats: pem: /, '') });
    }
    i = extent.next;
  }

  if (out.blocks.length === 0 && out.skipped.length === 0) {
    fail('no-pem-block', 'no PEM block found');
  }
  return out;
}

function split_lines(text) {
  // ⚠ BYTES ARE READ AS BYTES. String(x) gave the text for a node Buffer -
  // its toString is UTF-8 - and "45,45,45,..." for any other Uint8Array,
  // so the same file worked from fs.readFileSync and failed from fetch().
  if (text instanceof Uint8Array) {
    text = latin1(text);
  } else if (typeof text !== 'string') {
    text = String(text);
  }

  // CRLF, LF and bare CR all appear in the wild, often mixed in one file
  // after it has been through a Windows editor.
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
}

// Where the block opening at line `at` ends: its END line - matching or
// not, which read_block judges - or, with none, the next BEGIN or the end of
// the file. `next` is where reading resumes.
function block_extent(lines, at) {
  var j;
  for (j = at + 1; j < lines.length; j++) {
    if (END.exec(lines[j]) !== null) {
      return { end: j, closed: true, next: j + 1 };
    }
    if (BEGIN.exec(lines[j]) !== null) {
      return { end: j, closed: false, next: j };
    }
  }
  return { end: lines.length, closed: false, next: lines.length };
}

function read_block(lines, at, extent) {
  var label = BEGIN.exec(lines[at])[1];
  var start = at + 1;
  var i = start;

  var headers = null;
  var body = '';

  // Legacy encrypted PEM headers, RFC 1421. They appear immediately after
  // BEGIN and end with a blank line.
  while (i < extent.end) {
    var h = HEADER.exec(lines[i]);
    if (h === null) {
      break;
    }
    if (headers === null) {
      headers = {};
    }
    headers[h[1]] = h[2];
    i += 1;
  }

  if (headers !== null) {
    if (i < extent.end && lines[i].replace(/[ \t]/g, '') === '') {
      i += 1;
    } else {
      fail('bad-pem-headers',
        'headers must be followed by a blank line', i + 1);
    }
  }

  if (!extent.closed) {
    // Running into the next BEGIN is the same fault as running off the end:
    // this block was never closed. (It was read as body once - and failed
    // as bad base64, on the dashes.)
    fail('unterminated-block',
      'block "' + label + '" has no matching END', start);
  }

  // A file saying BEGIN CERTIFICATE and END PRIVATE KEY is claiming to be
  // two things. Reading only the BEGIN accepts it.
  var closing = END.exec(lines[extent.end])[1];
  if (closing !== label) {
    fail('label-mismatch',
      'block opens as "' + label + '" and closes as "' + closing + '"',
      extent.end + 1);
  }

  for (; i < extent.end; i++) {
    body += lines[i].replace(/[ \t]/g, '');
  }

  var block = {
    label: label,
    der:   base64_decode(body, start),
    headers: headers
  };

  if (headers !== null &&
      headers['Proc-Type'] !== undefined &&
      /ENCRYPTED/.test(headers['Proc-Type'])) {
    // RFC 1421 encryption: the IV is a hex string in DEK-Info and the key
    // comes from an MD5-based KDF. It predates PBES2, it is weak, and some
    // versions of `openssl rsa -aes256` still write it. Surfaced so a
    // caller knows it cannot simply parse the body as DER.
    block.encrypted = parse_dek_info(headers['DEK-Info'], start);
  } else {
    block.encrypted = null;
  }

  return block;
}

function parse_dek_info(value, line) {
  if (value === undefined) {
    fail('bad-pem-headers',
      'Proc-Type says ENCRYPTED but DEK-Info is missing', line);
  }

  var parts = value.split(',');
  if (parts.length !== 2) {
    fail('bad-pem-headers', 'DEK-Info should be "algorithm,IV"', line);
  }

  var iv_hex = parts[1].replace(/\s/g, '');
  if (!/^[0-9A-Fa-f]+$/.test(iv_hex) || iv_hex.length % 2 !== 0) {
    fail('bad-pem-headers', 'DEK-Info IV is not hex', line);
  }

  var iv = new Uint8Array(iv_hex.length / 2);
  var i;
  for (i = 0; i < iv.length; i++) {
    iv[i] = parseInt(iv_hex.substr(i * 2, 2), 16);
  }

  return {
    legacy: true,
    algorithm: parts[0].trim(),
    iv: iv
  };
}

// The single-block convenience. Refuses a file with more than one block
// rather than picking one, because picking is a guess and the caller is in a
// better position to make it.
function decode_one(text, expected_label) {
  var blocks = decode(text);

  if (blocks.length !== 1) {
    fail('multiple-blocks',
      'expected one PEM block, found ' + blocks.length);
  }

  if (expected_label !== undefined && blocks[0].label !== expected_label) {
    fail('wrong-label',
      'expected "' + expected_label + '", got "' + blocks[0].label + '"');
  }

  if (blocks[0].encrypted !== null) {
    fail('encrypted-pem',
      'this block uses legacy RFC 1421 encryption; decrypt it before parsing');
  }

  // The block, as decode() returns each one - { label, der, ... } - so the
  // two give the same shape. `.der` is the bytes.
  return blocks[0];
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

// RFC 7468 section 2 requires lines of at most 64 characters. Enforced on
// write and accepted loosely on read: being strict about our own output costs
// nothing, and being strict about other people's breaks files that work
// everywhere else.
// `width` is the line length: 64, RFC 7468's - or what another armour
// writes, as OpenSSH's SSH SIGNATURE does at 70.
function encode(der, label, width) {
  var w = width === undefined ? 64 : width;

  if (typeof w !== 'number' || w % 1 !== 0 || w < 4 || w > 76) {
    fail('bad-width', 'the line width is a whole number from 4 to 76');
  }
  if (typeof label !== 'string' || label.length === 0) {
    fail('bad-label', 'a PEM block needs a label');
  }
  if (!/^[A-Za-z0-9 .-]+$/.test(label)) {
    fail('bad-label', 'label "' + label + '" has characters RFC 7468 forbids');
  }

  var body = base64_encode(to_bytes(der));
  var out = '-----BEGIN ' + label + '-----\n';
  var i;

  for (i = 0; i < body.length; i += w) {
    out += body.substr(i, w) + '\n';
  }

  out += '-----END ' + label + '-----\n';
  return out;
}

// Legacy encrypted PEM is deliberately absent from this module's exports.
// The brief's position is: support it for reading, refuse to write it, and
// say why. This function is the "say why".
function encode_legacy_encrypted() {
  fail('write-refused',
    'RFC 1421 encrypted PEM uses an MD5-based KDF and is not written by ' +
    'this library. Use PKCS#8 with PBES2 instead.');
}

// ---------------------------------------------------------------------------


export {
  decode_skipping,
  decode,
  decode_one,
  encode,
  encode_legacy_encrypted
};
