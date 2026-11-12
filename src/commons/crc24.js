// CRC-24, RFC 9580 6.1 - the optional checksum on OpenPGP's ASCII armour.
//
// Shared by the armour's reader and writer. That is what commons/README.md
// says to avoid, and it is allowed here for the reason limits.js is: this
// is a checksum over bytes, not one half of an encode/decode pair. A wrong
// CRC computed the same way in both directions would round-trip - and is
// caught by the armour from gpg and from the RFC's own appendix A, which
// the tests read and check.

var INIT = 0xB704CE;
var GENERATOR = 0x864CFB;

function crc24(bytes) {
  var crc = INIT;
  var i;
  var j;
  for (i = 0; i < bytes.length; i++) {
    crc ^= bytes[i] << 16;
    for (j = 0; j < 8; j++) {
      crc <<= 1;
      if (crc & 0x1000000) {
        crc &= 0xFFFFFF;
        crc ^= GENERATOR;
      }
    }
  }
  return crc & 0xFFFFFF;
}

export { crc24 };
