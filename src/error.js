// A parser whose entire job is refusal has to be able to say what it refused
// and where. A bare Error with a formatted string cannot be asserted on
// without matching message text, and message text is the thing most likely to
// be reworded later - so the refusal tests would break on edits that changed
// nothing. The fields carry the meaning; the message is for humans.
//
// family   which encoding family    'der' | 'ber' | 'cbor' | 'jwk' | 'bech32'
// offset   byte offset, or null for text formats
// code     stable identifier, safe to assert on

function FormatError(family, offset, code, detail) {
  var where = offset === null || offset === undefined
    ? ''
    : 'offset ' + offset + ': ';

  this.name    = 'FormatError';
  this.family  = family;
  this.offset  = offset === undefined ? null : offset;
  this.code    = code;
  this.message = 'cryptographic-formats: ' + family + ': ' + where + detail;

  // Error.captureStackTrace is V8-only; the guard keeps this working in
  // browsers, where the stack is simply absent.
  if (Error.captureStackTrace) {
    Error.captureStackTrace(this, FormatError);
  }
}

FormatError.prototype = Object.create(Error.prototype);
FormatError.prototype.constructor = FormatError;

export { FormatError };
