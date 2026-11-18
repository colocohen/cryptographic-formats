// Any ASN.1 structure, not only the ones this library describes - here a
// made-up record. Strict DER both ways, and a refusal says exactly why.
//
//   Record ::= SEQUENCE {
//     id     INTEGER,
//     name   UTF8String,
//     tags   [0] IMPLICIT SEQUENCE OF UTF8String OPTIONAL }
import { der, der_writer as W, FormatError } from 'cryptographic-formats';

const bytes = W.to_bytes(W.sequence([
  W.integer([42]),
  W.utf8_string('example'),
  W.implicit(0, W.sequence([W.utf8_string('a'), W.utf8_string('b')]))
]));

const record = der.read(bytes, (r) => {
  const seq = r.read_sequence();
  const out = { id: seq.read_unsigned()[0], name: seq.read_utf8_string(),
                tags: [] };
  if (seq.peek_tag() === 0xA0) {
    const tags = seq.read_implicit(0, 0x30);
    while (tags.remaining() > 0) out.tags.push(tags.read_utf8_string());
  }
  seq.expect_end();
  return out;
});
console.log(record);                  // { id: 42, name: 'example', tags: [ 'a', 'b' ] }

// The same INTEGER with its length written in two bytes: valid BER, not DER.
try {
  der.read(new Uint8Array([0x02, 0x81, 0x01, 0x2A]), (r) => r.read_integer());
} catch (e) {
  console.log(e instanceof FormatError, e.code, e.offset);  // true non-minimal-length 1
}
