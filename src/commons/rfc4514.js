// RFC 4514 3's short names for attribute types: CN, C, ST and the rest.
//
// One table for both directions of the same text: x509.js prints a Name with
// it and looks attributes up by it, and pkix.js accepts it in a Name a
// builder is given. It maps a name to an OID - neither half of an
// encode/decode pair - and the DER it leads to is checked against OpenSSL,
// which prints these names itself (test/x509_build.test.js).

var SHORT_NAMES = {
  '2.5.4.3': 'CN', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O',
  '2.5.4.11': 'OU', '2.5.4.6': 'C', '2.5.4.9': 'STREET',
  '0.9.2342.19200300.100.1.25': 'DC', '0.9.2342.19200300.100.1.1': 'UID'
};

// The short name for a dotted OID, or undefined.
function short_name(dotted) {
  return Object.prototype.hasOwnProperty.call(SHORT_NAMES, dotted)
    ? SHORT_NAMES[dotted] : undefined;
}

// The dotted OID for a short name, or null. Exact case: RFC 4514 compares
// these case-insensitively, but a builder taking "cn" would also take "Cn",
// and the names this library prints are upper case.
function short_name_oid(name) {
  var k;
  for (k in SHORT_NAMES) {
    if (Object.prototype.hasOwnProperty.call(SHORT_NAMES, k) &&
        SHORT_NAMES[k] === name) {
      return k;
    }
  }
  return null;
}

export { short_name, short_name_oid };
