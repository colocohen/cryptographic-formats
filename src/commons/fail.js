// Every module had its own three-line `fail` wrapper differing only in the
// family string. This is that wrapper, made once.
//
//   var fail = make_fail('der');
//   fail(offset, 'non-minimal-integer', 'superfluous leading 0x00');
//
// Sharing this is safe because it constructs an error rather than encoding or
// decoding anything: a mistake here makes every refusal report the wrong
// thing, which is loud, rather than making a reader and a writer agree on
// something wrong, which is silent.

import { FormatError } from '../error.js';

// For binary formats, where a refusal has a byte offset.
function make_fail(family) {
  return function (offset, code, detail) {
    throw new FormatError(family, offset, code, detail);
  };
}

// For formats where there is no offset to report - a JWK member, a bech32
// string, a key object being written. The signature drops the first argument
// rather than making every call pass null, because a null that is always
// null is noise at every call site.
function make_fail_here(family) {
  return function (code, detail) {
    throw new FormatError(family, null, code, detail);
  };
}

// For text formats, where a refusal has a LINE rather than a byte offset.
// PEM is the only one so far: telling somebody "line 14" about a file they
// can open in an editor is more use than a byte offset into its base64.
function make_fail_line(family) {
  return function (code, detail, line) {
    throw new FormatError(family, line === undefined ? null : 'line ' + line,
      code, detail);
  };
}

export {
  make_fail,
  make_fail_here,
  make_fail_line
};
