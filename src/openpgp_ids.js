// OpenPGP's registries, RFC 9580 sections 5, 9 and 3.7 - the numbers the
// packets carry, and what each means. Tables only: openpgp.js reads with
// them and openpgp_build.js writes with them, and neither direction holds
// code here. Internal - no declarations.

// Packet Type IDs, RFC 9580 table 3. 0-39 are critical (4.3).
var PACKET = {
  1: 'pkesk', 2: 'signature', 3: 'skesk', 4: 'one-pass-signature',
  5: 'secret-key', 6: 'public-key', 7: 'secret-subkey', 8: 'compressed',
  9: 'sed', 10: 'marker', 11: 'literal', 12: 'trust', 13: 'user-id',
  14: 'public-subkey', 17: 'user-attribute', 18: 'seipd', 19: 'mdc',
  21: 'padding'
};

// Public key algorithms, table 18 - with what each key carries.
//   mpi      RSA, DSA, Elgamal: MPIs, in order
//   curve    ECDSA, ECDH, EdDSALegacy: an OID, then an MPI point
//   native   X25519...Ed448: a fixed number of octets
var PUBLIC_KEY = {
  1:  { name: 'rsa', fields: ['n', 'e'], secret: ['d', 'p', 'q', 'u'], sign: true, encrypt: true },
  2:  { name: 'rsa-encrypt-only', fields: ['n', 'e'], secret: ['d', 'p', 'q', 'u'], encrypt: true },
  3:  { name: 'rsa-sign-only', fields: ['n', 'e'], secret: ['d', 'p', 'q', 'u'], sign: true },
  16: { name: 'elgamal', fields: ['p', 'g', 'y'], secret: ['x'], encrypt: true },
  17: { name: 'dsa', fields: ['p', 'q', 'g', 'y'], secret: ['x'], sign: true },
  18: { name: 'ecdh', curve: true, kdf: true, secret: ['scalar'], encrypt: true },
  19: { name: 'ecdsa', curve: true, secret: ['scalar'], sign: true },
  22: { name: 'eddsa-legacy', curve: true, secret: ['scalar'], sign: true },
  25: { name: 'x25519', native: 32, encrypt: true },
  26: { name: 'x448', native: 56, encrypt: true },
  27: { name: 'ed25519', native: 32, signature: 64, sign: true },
  28: { name: 'ed448', native: 57, signature: 114, sign: true }
};

// Symmetric ciphers, table 21: key and block sizes in octets.
var CIPHER = {
  0:  { name: 'plaintext', key: 0, block: 0 },
  1:  { name: 'idea', key: 16, block: 8 },
  2:  { name: 'tripledes', key: 24, block: 8 },
  3:  { name: 'cast5', key: 16, block: 8 },
  4:  { name: 'blowfish', key: 16, block: 8 },
  7:  { name: 'aes128', key: 16, block: 16 },
  8:  { name: 'aes192', key: 24, block: 16 },
  9:  { name: 'aes256', key: 32, block: 16 },
  10: { name: 'twofish', key: 32, block: 16 },
  11: { name: 'camellia128', key: 16, block: 16 },
  12: { name: 'camellia192', key: 24, block: 16 },
  13: { name: 'camellia256', key: 32, block: 16 }
};

// Hashes, table 23: the library's names, the armour's "Hash:" names, and
// the v6 signature salt size.
var HASH = {
  1:  { name: 'md5', text: 'MD5', size: 16, weak: true },
  2:  { name: 'sha1', text: 'SHA1', size: 20, weak: true },
  3:  { name: 'ripemd160', text: 'RIPEMD160', size: 20, weak: true },
  8:  { name: 'sha256', text: 'SHA256', size: 32, salt: 16 },
  9:  { name: 'sha384', text: 'SHA384', size: 48, salt: 24 },
  10: { name: 'sha512', text: 'SHA512', size: 64, salt: 32 },
  11: { name: 'sha224', text: 'SHA224', size: 28, salt: 16 },
  12: { name: 'sha3_256', text: 'SHA3-256', size: 32, salt: 16 },
  14: { name: 'sha3_512', text: 'SHA3-512', size: 64, salt: 32 }
};

// AEAD modes, table 25: nonce and tag sizes.
var AEAD = {
  1: { name: 'eax', nonce: 16, tag: 16 },
  2: { name: 'ocb', nonce: 15, tag: 16 },
  3: { name: 'gcm', nonce: 12, tag: 16 }
};

var COMPRESSION = { 0: 'uncompressed', 1: 'zip', 2: 'zlib', 3: 'bzip2' };

// Curves, table 19 - by the library's OID names, with fsize.
var CURVE = {
  '1.2.840.10045.3.1.7':   { name: 'secp256r1', size: 32, wire: 'sec1' },
  '1.3.132.0.34':          { name: 'secp384r1', size: 48, wire: 'sec1' },
  '1.3.132.0.35':          { name: 'secp521r1', size: 66, wire: 'sec1' },
  '1.3.36.3.3.2.8.1.1.7':  { name: 'brainpoolP256r1', size: 32, wire: 'sec1' },
  '1.3.36.3.3.2.8.1.1.11': { name: 'brainpoolP384r1', size: 48, wire: 'sec1' },
  '1.3.36.3.3.2.8.1.1.13': { name: 'brainpoolP512r1', size: 64, wire: 'sec1' },
  // 11.2.2: "prefixed native" - 0x40 then the native 32 octets.
  '1.3.6.1.4.1.11591.15.1': { name: 'ed25519Legacy', size: 32, wire: 'prefixed' },
  '1.3.6.1.4.1.3029.1.5.1': { name: 'curve25519Legacy', size: 32, wire: 'prefixed' }
};

// Signature types, 5.2.1.
var SIGNATURE_TYPE = {
  0x00: 'binary', 0x01: 'text', 0x02: 'standalone',
  0x10: 'generic-certification', 0x11: 'persona-certification',
  0x12: 'casual-certification', 0x13: 'positive-certification',
  0x18: 'subkey-binding', 0x19: 'primary-key-binding', 0x1F: 'direct-key',
  0x20: 'key-revocation', 0x28: 'subkey-revocation',
  0x30: 'certification-revocation', 0x40: 'timestamp',
  0x50: 'third-party-confirmation'
};

// Signature subpackets, table 5 - with how each value reads.
var SUBPACKET = {
  2:  { name: 'created', as: 'time' },
  3:  { name: 'signature_expires', as: 'seconds' },
  4:  { name: 'exportable', as: 'bool' },
  5:  { name: 'trust', as: 'raw' },
  6:  { name: 'regular_expression', as: 'raw' },
  7:  { name: 'revocable', as: 'bool' },
  9:  { name: 'key_expires', as: 'seconds' },
  11: { name: 'preferred_ciphers', as: 'list' },
  12: { name: 'revocation_key', as: 'raw' },
  16: { name: 'issuer_key_id', as: 'raw' },
  20: { name: 'notation', as: 'notation' },
  21: { name: 'preferred_hashes', as: 'list' },
  22: { name: 'preferred_compression', as: 'list' },
  23: { name: 'key_server_preferences', as: 'raw' },
  24: { name: 'preferred_key_server', as: 'text' },
  25: { name: 'primary_user_id', as: 'bool' },
  26: { name: 'policy_uri', as: 'text' },
  27: { name: 'key_flags', as: 'raw' },
  28: { name: 'signers_user_id', as: 'text' },
  29: { name: 'revocation_reason', as: 'reason' },
  30: { name: 'features', as: 'raw' },
  31: { name: 'signature_target', as: 'raw' },
  32: { name: 'embedded_signature', as: 'signature' },
  33: { name: 'issuer_fingerprint', as: 'fingerprint' },
  35: { name: 'intended_recipient', as: 'fingerprint' },
  39: { name: 'preferred_aead', as: 'pairs' }
};

// Key flags, 5.2.3.29 - the first octet's bits, and the second's.
var KEY_FLAGS = [
  [0x01, 'certify'], [0x02, 'sign'], [0x04, 'encrypt-communications'],
  [0x08, 'encrypt-storage'], [0x10, 'split'], [0x20, 'authenticate'],
  [0x80, 'group']
];
var KEY_FLAGS_2 = [[0x04, 'adsk'], [0x08, 'timestamping']];

// The reverse of a table: name -> id.
function id_of(table, name) {
  var k;
  for (k in table) {
    if (Object.prototype.hasOwnProperty.call(table, k)) {
      var v = table[k];
      if (v === name || (v && v.name === name)) { return +k; }
    }
  }
  return null;
}

export {
  PACKET, PUBLIC_KEY, CIPHER, HASH, AEAD, COMPRESSION, CURVE,
  SIGNATURE_TYPE, SUBPACKET, KEY_FLAGS, KEY_FLAGS_2, id_of
};
