// The ASN.1 structures that PKIX defines once and every format reuses.
//
// ⚠ WHY THIS EXISTS: SEVEN COPIES AND A GUARD THAT ADMITTED IT.
//
// `AlgorithmIdentifier` was defined in seven modules, each wrapped in
//
//     if (!F.defined('AlgorithmIdentifier')) { F.define(...); }
//
// which is not a solution - it is a note saying "somebody else may have
// already done this, and I do not know who". Whichever module loaded first
// won, and if two copies had ever drifted apart the behaviour would depend on
// import order.
//
// Defining them here, once, in a module every consumer imports for the side
// effect, makes the order irrelevant and the guard unnecessary.
//
// SAFE TO SHARE: these are DECLARATIONS, not logic. A mistake here is a
// structure every module reads the same wrong way, which shows up
// immediately against a real file - not a reader and a writer agreeing on
// something wrong, which is the failure the sharing rule exists to prevent.
// See src/commons/README.md.

import * as F from './fields.js';

// ---------------------------------------------------------------------------
// The universal one
// ---------------------------------------------------------------------------

//   AlgorithmIdentifier ::= SEQUENCE {
//        algorithm   OBJECT IDENTIFIER,
//        parameters  ANY DEFINED BY algorithm OPTIONAL }
//
// The parameters are captured whole rather than typed, because what they
// contain depends on the OID - the ANY DEFINED BY pattern - and each format
// resolves that differently: an EC key's parameters are a curve, an RSA
// key's are NULL, an Ed25519 key's must be absent.
F.define('AlgorithmIdentifier', [
  { name: 'algorithm',  type: 'oid' },
  { name: 'parameters', type: 'any', optional: true }
]);

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

//   AttributeTypeAndValue ::= SEQUENCE {
//        type   OBJECT IDENTIFIER,
//        value  ANY DEFINED BY type }
F.define('AttributeTypeAndValue', [
  { name: 'type',  type: 'oid' },
  { name: 'value', type: 'any' }
]);

// A SET OF, and the ordering matters: two RDNs with the same members in a
// different order are the same name, and DER makes them the same bytes.
F.define('RelativeDistinguishedName',
  { kind: 'set_of', of: 'AttributeTypeAndValue', min: 1 });

F.define('RDNSequence',
  { kind: 'sequence_of', of: 'RelativeDistinguishedName' });

// ⚠ HOW A STRUCTURE NAMES A CERTIFICATE IT DOES NOT CARRY.
//
//   IssuerAndSerialNumber ::= SEQUENCE {
//        issuer  Name,
//        serial  CertificateSerialNumber }
//
// A serial number is unique only WITHIN an issuer, which is why both halves
// travel together and why comparing on serial alone would accept an answer
// about an entirely different certificate.
//
// It lived in cms.js, so cms_enveloped.js could not see it - the same
// `if (!F.defined(...))` situation that put AlgorithmIdentifier here.
F.define('IssuerAndSerialNumber', [
  { name: 'issuer', type: 'RDNSequence' },
  { name: 'serial', type: 'integer' }
]);

// In a name constraint: CIDR text, "10.0.0.0/8", or the address-and-mask
// bytes. A bare address is refused - written as 4 bytes, it is a constraint
// x509.js (and OpenSSL) refuse to read.
function ip_range_to_bytes(value) {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (typeof value !== 'string') {
    fail_pkix('bad-ip', 'an IP range is CIDR text ("10.0.0.0/8") or address-and-mask bytes');
  }
  var bytes = parse_cidr(value);
  if (bytes === null) {
    fail_pkix('bad-ip', '"' + value + '" is not a CIDR range - an address, "/", and a prefix ' +
      'length, with no address bits set past the prefix: "10.0.0.0/8", "2001:db8::/32"');
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

//   Extension ::= SEQUENCE {
//        extnID     OBJECT IDENTIFIER,
//        critical   BOOLEAN DEFAULT FALSE,
//        extnValue  OCTET STRING }
//
// `critical` carries its DEFAULT, so the field engine refuses an explicitly
// encoded FALSE - X.690 11.5. That check used to be written by hand in
// x509.js and covered only this one field.
F.define('Extension', [
  { name: 'extnID',    type: 'oid' },
  { name: 'critical',  type: 'boolean', optional: true, def: false },
  { name: 'extnValue', type: 'octet_string' }
]);

// RFC 5280 4.2: "A certificate MUST NOT include more than one instance of a
// particular extension" - and the same Extensions type is used by CRLs,
// OCSP, TSP, CRMF and attribute certificates. Declared here, it applies to
// all of them.
var UNIQUE_EXTENSION = { field: 'extnID', code: 'duplicate-extension',
                         what: 'extension' };

F.define('Extensions', { kind: 'sequence_of', of: 'Extension', min: 1,
  unique: UNIQUE_EXTENSION });

// ⚠ A CERTIFICATE'S, WHICH MAY BE EMPTY - AND x509.js SAYS SO.
//
// `openssl x509 -req` (3.0) writes `[3] { SEQUENCE {} }` when every line of
// the extension file is `=none`, and OpenSSL and node accept the result.
// RFC 5280's SIZE (1..MAX) refused it here, whole certificate and all
// (reported from lemon). An empty list means one thing - no extensions - so
// x509.js reads it and puts `empty-extensions` in the warnings, as for the
// other violations OpenSSL accepts (DECISIONS 25). Only certificates: the
// other formats keep the minimum until one is shown to need otherwise.
F.define('CertificateExtensions', { kind: 'sequence_of', of: 'Extension',
  unique: UNIQUE_EXTENSION });

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

//   Validity ::= SEQUENCE {
//        notBefore  Time,
//        notAfter   Time }
F.define('Validity', [
  { name: 'notBefore', type: 'time' },
  { name: 'notAfter',  type: 'time' }
]);

export { };

// ---------------------------------------------------------------------------
// Writers the PKIX formats share
// ---------------------------------------------------------------------------
//
// ⚠ THREE RULES THAT ARE THE SAME EVERYWHERE THEY APPEAR, AND WERE WRITTEN
//    TWICE.
//
// x509_build.js and cms_build.js each carried a copy, and jscpd did not
// report it - the bodies differ by a variable name and a comment, which is
// exactly the drift the structural analysis exists to catch and which slipped
// past because the modules were written an hour apart.
//
// SAFE TO SHARE: these encode a rule from a document, and a mistake makes
// every module produce the same wrong bytes - which openssl rejects on the
// first file. That is loud, and it is not a reader and a writer agreeing on
// something wrong. See src/commons/README.md.

import * as W from './der_writer.js';
import * as OID from './oid.js';
import * as ALG from './algorithm.js';
import { make_fail_here } from './commons/fail.js';
import { int_bytes, to_bytes } from './commons/bytes.js';
import { parse_ip, parse_cidr } from './commons/ip.js';
import { short_name_oid } from './commons/rfc4514.js';
import { encode_utf8 } from './commons/encode_text.js';

var fail_pkix = make_fail_here('pkix');

// ⚠ UTCTime BEFORE 2050, GeneralizedTime FROM 2050 ONWARD.
//
// RFC 5280 4.1.2.5, and RFC 5652 11.3 says the same for CMS. It is not a
// preference: UTCTime carries two digits of year and the profile fixes the
// pivot at 2050, so writing a 2060 date as UTCTime makes it 1960.
// A Date, or the time a reader returned.
function time_to_der(value) {
  var date = as_date(value);

  if (date === null || isNaN(date.getTime())) {
    fail_pkix('bad-time', 'expected a Date, or a time a reader returned');
  }

  return date.getUTCFullYear() < 2050
    ? W.utc_time(date)
    : W.generalized_time(date);
}

// ⚠ RSA CARRIES NULL PARAMETERS AND ECDSA CARRIES NONE.
//
// RFC 4055 3.2 and RFC 5758 3.2. Writing the wrong one produces a structure
// SOME verifiers reject and others accept, which is worse than one everybody
// rejects - the failure appears only in somebody else's deployment.
//
// And RSA-PSS and RSA-OAEP carry PARAMETERS, written by algorithm.js: pass
// { name: 'rsassaPss', hash: 'sha256', salt_length: 32 } where a name would
// go. One home for the rule, so every builder writes PSS the same way.
function algorithm_to_der(name) {
  return ALG.to_der(name);
}

// ⚠ DIGEST ALGORITHMS IN CMS CARRY NULL, and that is a different rule.
//
// RFC 5754 section 2 says the parameters SHOULD be absent, and the world
// writes NULL - openssl does, and so does every message this library was
// tested against. Writing absent produces something some verifiers reject,
// so the deployed behaviour wins over the document here and the divergence
// is stated rather than silent.
//
// Two exceptions write the parameters absent, as their RFCs say they MUST
// be: SHA-3 and SHAKE (RFC 8702 2, RFC 9688 2), which never had a NULL
// tradition to keep; and every digest beside a post-quantum signer (RFC
// 9882 3.3, RFC 9814 4), where `absent` is passed - the verifiers for those
// are new, and written to the new RFCs.
function digest_algorithm_to_der(name, absent) {
  if (absent === true || /^(sha3_|shake)/.test(name)) {
    return W.sequence([W.oid(OID.by_name(name))]);
  }
  return W.sequence([W.oid(OID.by_name(name)), W.null()]);
}

//   EncapsulatedContentInfo ::= SEQUENCE {
//        eContentType  ContentType,
//        eContent  [0] EXPLICIT OCTET STRING OPTIONAL }
//
// SignedData and AuthenticatedData carry the content this way; null
// content is a detached message, and the field is left out.
function encapsulated_to_der(content_oid, content) {
  var fields = [W.oid(OID.from_string(content_oid))];

  if (content !== null && content !== undefined) {
    fields.push(W.explicit(0, W.octet_string(content)));
  }
  return W.sequence(fields);
}

// ⚠ A Name IS PASSED THROUGH AS ENCODED BYTES WHEN IT CAME FROM A READER.
//
// The issuer in a child certificate has to match the subject in the parent
// EXACTLY - that is how a verifier finds the issuer, and how a CMS
// SignerInfo names its certificate. Any re-encoding risks a different byte
// sequence for the same name, and then nothing matches.
//
// So the parsed form - [[{ type: <oid bytes>, value: <der bytes> }]] - goes
// through untouched, and only a name written by hand is encoded.
function name_to_der(name, encode_attribute) {
  if (!Array.isArray(name)) {
    fail_pkix('bad-name',
      'a name is an array of RDNs: [{ commonName: "x" }]');
  }

  var rdns = [];
  var i, j, key;

  for (i = 0; i < name.length; i++) {
    var members = Array.isArray(name[i]) ? name[i] : [name[i]];
    var attributes = [];

    for (j = 0; j < members.length; j++) {
      var member = members[j];

      if (member && member.type instanceof Uint8Array &&
          member.value instanceof Uint8Array) {
        attributes.push(W.sequence([W.oid(member.type), member.value]));
        continue;
      }

      if (encode_attribute === undefined) {
        fail_pkix('bad-name',
          'this name has attributes to encode and no encoder was given - ' +
          'pass one, or hand over a name a reader produced');
      }

      for (key in member) {
        if (Object.prototype.hasOwnProperty.call(member, key)) {
          attributes.push(encode_attribute(key, member[key]));
        }
      }
    }

    if (attributes.length === 0) {
      fail_pkix('empty-rdn', 'an RDN with no attributes names nothing');
    }

    // SET OF, so the writer sorts by encoding - X.690 11.6. Two names with
    // the same members in a different order become the same bytes.
    rdns.push(W.set_of(attributes));
  }

  return W.sequence(rdns);
}

// ⚠ THE STRING TYPE IS NOT A FREE CHOICE.
//
// RFC 5280 4.1.2.4 requires UTF8String for new certificates, with exceptions
// that are not stylistic:
//
//   countryName        PrintableString, always. Two letters from a fixed
//                      list, and a UTF8String there is refused by some
//                      verifiers.
//   emailAddress       IA5String - it comes from PKCS#9 rather than X.520
//                      and that arc specifies IA5.
//   domainComponent    IA5String, RFC 4519.
//
// Picking the wrong one produces a name that encodes, parses, and compares
// UNEQUAL to the same name written correctly - so a CRL whose issuer is
// spelled like the CA's subject but typed differently is a CRL nothing
// associates with its issuer.
//
// x509_build.js and crl_build.js each had a copy, written an hour apart and
// differing only in comments. Neither jscpd nor the structural budget saw
// it.
var STRING_TYPES = {
  countryName:     'printable',
  emailAddress:    'ia5',
  domainComponent: 'ia5',
  dnQualifier:     'printable',
  serialNumber:    'printable'
};

// An attribute is named three ways, on the way IN: this library's names,
// the X.520 / RFC 5280 spellings stateOrProvinceName and
// organizationalUnitName (oid.js's aliases), and RFC 4514's short names CN,
// C, ST, OU... (commons/rfc4514.js). What a reader returns stays this
// library's. The string type goes by the OID, not the key, so "C" and a
// dotted 2.5.4.6 are PrintableStrings as RFC 5280 4.1.2.4 requires.

function attribute_to_der(key, value) {
  var oid;
  var short = short_name_oid(key);

  try {
    oid = short !== null ? OID.from_string(short) : OID.by_name(key);
  } catch (e) {
    // A dotted string is accepted for attributes this library does not name.
    if (/^\d+(\.\d+)+$/.test(key)) {
      oid = OID.from_string(key);
    } else {
      fail_pkix('unknown-attribute',
        'no known name attribute called "' + key + '". Pass a dotted OID ' +
        'if you mean one this library does not name.');
    }
  }

  if (typeof value !== 'string') {
    fail_pkix('bad-attribute-value',
      'the value of "' + key + '" must be a string');
  }

  // By the attribute itself, so a dotted 2.5.4.6 is a PrintableString too.
  var kind = STRING_TYPES[OID.name_of(oid)] || 'utf8';

  return W.sequence([
    W.oid(oid),
    kind === 'printable' ? W.printable_string(value)
      : kind === 'ia5' ? W.ia5_string(value)
      : W.utf8_string(value)
  ]);
}

// ⚠ THE THREE SIGNED PKIX STRUCTURES ASSEMBLE IDENTICALLY.
//
//   SEQUENCE { tbs, AlgorithmIdentifier, BIT STRING }
//
// A certificate, a CRL and an attribute certificate all end this way, and
// x509_build, crl_build and attrcert_build each had a copy - measured at
// 100% identical by the structural analysis, which is what caught it.
//
// The tbs goes in AS IT WAS SIGNED, never rebuilt: a re-encode differing by
// one byte produces a structure whose signature covers something else, and
// it looks correct.
function assemble_signed(tbs, signature, family_fail) {
  if (tbs === null || typeof tbs !== 'object' ||
      !(tbs.bytes instanceof Uint8Array)) {
    family_fail('bad-tbs',
      'assemble takes what prepare() returned: assemble(prepared, signature)');
  }

  if (!(signature instanceof Uint8Array)) {
    family_fail('bad-signature',
      'the signature is the bytes over tbs.bytes, as your crypto library ' +
      'produced them');
  }

  // ⚠ ECDSA SIGNATURES GO IN AS DER, NOT AS r||s.
  //
  // A caller holding a 64-byte value from a JOSE library would produce a
  // structure nothing verifies. A DER signature starts 0x30, and that is
  // the only signal available here.
  if (signature.length > 0 && signature[0] !== 0x30 &&
      /ecdsa/i.test(tbs.signature_algorithm || '')) {
    family_fail('raw-signature',
      'this looks like a raw r||s signature. PKIX carries ECDSA signatures ' +
      'as SEQUENCE { r, s } - convert it with signature.raw_to_der({ raw: ' +
      'sig, curve: ... }).');
  }

  // A post-quantum signature has one length for its parameter set: one of
  // another is a truncated buffer, or another set's key.
  ALG.check_signature_length({ name: tbs.signature_algorithm,
    signature_length: ALG.signature_length(tbs.signature_algorithm) },
    signature, family_fail);

  return W.to_bytes(W.sequence([
    tbs.bytes,
    algorithm_to_der(tbs.signature_algorithm),
    W.bit_string(signature, 0)
  ]));
}

// ---------------------------------------------------------------------------
// Extensions, validity, small numbers - the rest of what four builders wrote
// four times
// ---------------------------------------------------------------------------
//
// jscpd found these across x509_build, crl_build, crmf_build and
// attrcert_build: the name-to-OID lookup for an extension, the Extension
// SEQUENCE with its DEFAULT FALSE critical, the loop over raw extension
// bytes, the Validity pair, and a whole number turned into INTEGER content.
// The original .jscpd.json said the only clones left were the deliberate
// ones; there were 54. These are writers shared by writers, which is the
// safe direction.

// "subjectAltName", "ext_subjectAltName" or a dotted OID.
function extension_oid(name, fail) {
  try {
    return /^\d+(\.\d+)+$/.test(name)
      ? OID.from_string(name)
      : OID.by_name(name.indexOf('ext_') === 0 ? name : 'ext_' + name);
  } catch (e) {
    fail('unknown-extension',
      '"' + name + '" is not a known extension. Pass a dotted OID.');
  }
}

//   Extension ::= SEQUENCE {
//      extnID     OBJECT IDENTIFIER,
//      critical   BOOLEAN DEFAULT FALSE,
//      extnValue  OCTET STRING }
//
// ⚠ critical HAS DEFAULT FALSE, so false is OMITTED - X.690 11.5. Writing
// BOOLEAN FALSE produces a structure this library's own reader refuses.
function extension_to_der(oid_or_name, critical, value, fail) {
  var oid = typeof oid_or_name === 'string'
    ? extension_oid(oid_or_name, fail) : oid_or_name;
  var fields = [W.oid(oid)];

  if (critical) {
    fields.push(W.boolean(true));
  }

  fields.push(W.octet_string(value));
  return W.sequence(fields);
}

// A map of extension name -> ENCODED value, for the builders that take
// extensions as bytes. Returns the Extension SEQUENCEs, in map order;
// `what` names the structure in the refusal.
function raw_extensions_to_der(map, fail, what) {
  var out = [];

  if (map === undefined || map === null) {
    return out;
  }

  var name;
  for (name in map) {
    if (!Object.prototype.hasOwnProperty.call(map, name)) {
      continue;
    }
    if (!(map[name] instanceof Uint8Array)) {
      fail('unknown-extension',
        'no writer for ' + what + ' extension "' + name + '". Pass the ' +
        'encoded value as bytes if you have it.');
    }
    out.push(extension_to_der(name, false, map[name], fail));
  }

  return out;
}

//   Validity ::= SEQUENCE { notBefore Time, notAfter Time }
//
// `encode_time` is the format's rule: time_to_der for X.509 (UTCTime before
// 2050), W.generalized_time for attribute certificates (always).
//
// { not_before, not_after } - the names every reader here returns, so a
// validity read from one certificate can be handed to a builder. Each is a
// Date, or the time object a reader returned (which carries `.date`).
function validity_to_der(validity, encode_time, fail) {
  var nb = validity ? as_date(validity.not_before) : null;
  var na = validity ? as_date(validity.not_after) : null;

  if (nb === null || na === null) {
    fail('bad-validity', 'validity is { not_before, not_after }, each a Date ' +
      'or a time a reader returned');
  }
  if (na.getTime() <= nb.getTime()) {
    fail('backwards-validity', 'not_after is not after not_before');
  }

  return W.sequence([encode_time(nb), encode_time(na)]);
}

// How many days a { not_before, not_after } validity spans, or null when
// either end is missing - for the builders' check() warnings.
function validity_days(validity) {
  var nb = validity ? as_date(validity.not_before) : null;
  var na = validity ? as_date(validity.not_after) : null;
  return nb === null || na === null ? null : (na - nb) / 86400000;
}

// A Date, or a parsed time ({ year, ..., date }) - or null.
function as_date(t) {
  if (t instanceof Date) {
    return t;
  }
  if (t && t.date instanceof Date) {
    return t.date;
  }
  return null;
}

// A non-negative whole number - or bytes, passed through - as INTEGER
// content. `code` is the caller's refusal code.
function number_bytes(n, code, what, fail) {
  if (n instanceof Uint8Array) {
    return n;
  }
  if (typeof n !== 'number' || n < 0 || Math.floor(n) !== n) {
    fail(code, what + ' is a non-negative whole number or bytes');
  }
  return new Uint8Array(int_bytes(n));
}

// ---------------------------------------------------------------------------
// PKIStatusInfo - CMP (RFC 4210) and TSP (RFC 3161), which imports it
// ---------------------------------------------------------------------------

//   PKIStatusInfo ::= SEQUENCE {
//      status        PKIStatus,                      -- INTEGER
//      statusString  PKIFreeText OPTIONAL,           -- SEQUENCE OF UTF8String
//      failInfo      PKIFailureInfo OPTIONAL }       -- named BIT STRING
//
// `status` the number, `text` a string or null, `bits` the failInfo bit
// POSITIONS - each caller names them from its own table (RFC 3161 uses a
// subset of RFC 4210's, at the same positions).
//
// failInfo is a named BIT STRING: DER drops trailing zero bits (X.690
// 11.2.2), so its length is set by the highest bit in use.
function status_info_to_der(status, text, bits) {
  var info = [W.integer([status])];

  if (text !== undefined && text !== null && text !== '') {
    info.push(W.sequence([W.utf8_string(String(text))]));
  }

  if (bits && bits.length > 0) {
    var max = Math.max.apply(null, bits);
    var bytes = new Uint8Array(Math.floor(max / 8) + 1);
    var i;
    for (i = 0; i < bits.length; i++) {
      bytes[bits[i] >> 3] |= 0x80 >> (bits[i] & 7);
    }
    info.push(W.bit_string(bytes, 7 - (max & 7)));
  }

  return W.sequence(info);
}

// ---------------------------------------------------------------------------
// Names, GeneralNames, public keys and certificate extensions, written
// ---------------------------------------------------------------------------
//
// Moved from x509_build.js, where csr_build, ocsp_build, tsp_build and
// cmp_build were importing them from - a builder depending on another
// builder for writers that belong to neither. They are the shared PKIX
// writers, and this is where those live.
// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

// ⚠ A Name IS A SEQUENCE OF SETS, NOT A LIST OF PAIRS.
//
//   RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
//   RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
//
// Each SET may hold several attributes - `CN=x + OU=y` is ONE RDN with two
// members, and `CN=x, OU=y` is two RDNs. They are different names, and the
// difference matters for matching.
//
// This takes the common form - an array of objects, each becoming one RDN -
// and takes an array-of-arrays for the multi-valued case, so both are
// expressible and neither is the accidental one.
// name_to_der above walks the SEQUENCE of SETs and passes a reader's name
// through untouched; this adds the X.509 profile's string types (RFC 5280
// 4.1.2.4) for a name written by hand. Every builder writing a Name it may
// be handed by a person uses this one.
function x509_name_to_der(name) {
  return name_to_der(name, attribute_to_der);
}



// ---------------------------------------------------------------------------
// GeneralName
// ---------------------------------------------------------------------------

// The nine-way CHOICE, written. Each arm has its own tag and its own content
// type, and the tags are IMPLICIT except where the content is itself a
// CHOICE - directoryName is [4] EXPLICIT for exactly that reason.
// `in_constraint`: the name is a nameConstraints subtree base, where an
// iPAddress is a range - x509.js's general_name reads it with the same flag.
function general_name_to_der(entry, in_constraint) {
  if (entry === null || typeof entry !== 'object') {
    fail_pkix('bad-general-name',
      'a GeneralName is an object: { dns: "example.com" }');
  }

  if (typeof entry.type === 'string') {
    entry = from_read_form(entry);
  }

  if (entry.dns !== undefined) {
    return W.implicit(2, W.ia5_string(entry.dns));
  }
  if (entry.email !== undefined) {
    return W.implicit(1, W.ia5_string(entry.email));
  }
  if (entry.uri !== undefined) {
    return W.implicit(6, W.ia5_string(entry.uri));
  }
  if (entry.ip !== undefined) {
    return W.implicit(7, W.octet_string(in_constraint === true
      ? ip_range_to_bytes(entry.ip) : ip_to_bytes(entry.ip)));
  }
  if (entry.directory !== undefined) {
    // ⚠ [4] EXPLICIT, because Name is a CHOICE - X.680 31.2.7. An implicit
    // tag would replace the RDNSequence's own and nothing would say what is
    // inside.
    return W.explicit(4, x509_name_to_der(entry.directory));
  }
  if (entry.registered_id !== undefined) {
    return W.implicit(8, W.oid(oid_of(entry.registered_id)));
  }
  // The two device identities x509.js decodes (DECISIONS 31), written as
  // the otherName they are.
  if (entry.permanent_identifier !== undefined) {
    var pi = entry.permanent_identifier;
    var fields = [];
    if (pi.value !== undefined && pi.value !== null) {
      fields.push(W.utf8_string(pi.value));
    }
    if (pi.assigner !== undefined && pi.assigner !== null) {
      fields.push(W.oid(oid_of(pi.assigner)));
    }
    return other_name_to_der('1.3.6.1.5.5.7.8.3', W.sequence(fields));
  }
  if (entry.hardware_module_name !== undefined) {
    var hw = entry.hardware_module_name;
    if (hw.type === undefined || hw.serial === undefined) {
      fail_pkix('bad-general-name', 'a HardwareModuleName has both hwType ' +
        'and hwSerialNum (RFC 4108 5)');
    }
    return other_name_to_der('1.3.6.1.5.5.7.8.4', W.sequence([
      W.oid(oid_of(hw.type)), W.octet_string(to_bytes(hw.serial))]));
  }
  if (entry.other !== undefined) {
    return other_name_to_der(entry.other.id, to_bytes(entry.other.value));
  }


  if (entry.raw !== undefined) {
    // An x400Address or ediPartyName as the reader kept it: its whole TLV.
    var raw = to_bytes(entry.raw);
    if (raw[0] !== 0xA3 && raw[0] !== 0xA5) {
      fail_pkix('bad-general-name', 'a kept GeneralName is [3] x400Address or ' +
        '[5] ediPartyName, whole');
    }
    return raw;
  }

  fail_pkix('bad-general-name',
    'a GeneralName needs one of: dns, email, uri, ip, directory, ' +
    'registered_id, other - or { type, value } as x509.js reads it');
}

// The dotted form or a name from oid.js.
function oid_of(id) {
  return /^\d+(\.\d+)+$/.test(id) ? OID.from_string(id) : OID.by_name(id);
}

function other_name_to_der(id, value) {
  //   OtherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
  //
  // ⚠ otherName IS [0] IMPLICIT - the module is IMPLICIT TAGS, and OtherName
  // is a SEQUENCE, not a CHOICE, so its tag is replaced, not wrapped. This
  // wrote [0] EXPLICIT around the SEQUENCE, and OpenSSL printed the SAN as
  // garbage; x509.js read it correctly and so could not read back what
  // this wrote. Found by round-tripping the read form (DECISIONS 29).
  return W.implicit(0, W.sequence([W.oid(oid_of(id)), W.explicit(0, value)]));
}

// ⚠ A GeneralName AS x509.js READ IT - { type: 'directory', value } - IS
// WRITTEN AS THE NAME IT IS.
//
// A server answers to the request's sender, so the name it writes is the
// one it read: cmp's `sender`, a CMS signer's, a certificate's SAN. The
// writer took only { directory: ... }, and the read form was refused with
// "a GeneralName needs one of..." (reported from ca-manager's CMP server,
// which converted it by hand). Every form the reader returns is taken back,
// as extension names and EKU purposes already are; 'other-tag' -
// x400Address, ediPartyName - is kept whole by the reader, and goes back
// whole.
function from_read_form(g) {
  switch (g.type) {
  case 'dns': return { dns: g.value };
  case 'email': return { email: g.value };
  case 'uri': return { uri: g.value };
  case 'ip': return { ip: g.value };
  case 'directory': return { directory: g.value };
  case 'registered-id': return { registered_id: g.value };
  case 'other': return { other: { id: g.id, value: g.value } };
  case 'other-tag': return { raw: g.value };
  default:
    fail_pkix('bad-general-name', 'a GeneralName of type "' + g.type + '" is not one ' +
      'x509.js reads');
  }
}

// ⚠ AN IP ADDRESS IN A CERTIFICATE IS BYTES, NOT TEXT.
//
// Four bytes for IPv4, sixteen for IPv6 - and in a nameConstraints extension
// it is DOUBLE that, address then mask. Writing "192.0.2.1" as a string
// produces an extension that parses and matches nothing.
function ip_to_bytes(value) {
  if (value instanceof Uint8Array) {
    return value;
  }

  if (typeof value !== 'string') {
    fail_pkix('bad-ip', 'an IP address is a string or bytes');
  }

  // IPv4, or IPv6 with "::" and an IPv4 tail (RFC 4291 2.2) - parsed by the
  // code x509.js matches hosts with, so a name written is a name matched.
  var bytes = parse_ip(value);

  if (bytes === null) {
    fail_pkix('bad-ip', '"' + value + '" is not an IPv4 or IPv6 address');
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

// ⚠ WHICH EXTENSIONS ARE CRITICAL IS NOT A PREFERENCE.
//
// RFC 5280 states it per extension, and getting it wrong has two different
// failure modes: marking one critical that should not be makes conforming
// verifiers refuse the certificate; leaving one non-critical that should be
// makes them ignore a constraint the CA meant to impose.
//
// So the default comes from the RFC and a caller overriding it is doing so
// explicitly.
var CRITICAL_BY_DEFAULT = {
  basicConstraints:  true,      // 4.2.1.9, when ca is true
  keyUsage:          true,      // 4.2.1.3
  nameConstraints:   true,      // 4.2.1.10 - MUST be critical
  policyConstraints: true,      // 4.2.1.11 - MUST be critical
  inhibitAnyPolicy:  true,      // 4.2.1.14 - MUST be critical
  subjectAltName:    false,     // unless the subject is empty
  extKeyUsage:       false,
  subjectKeyId:      false,     // 4.2.1.2 - MUST NOT be critical
  authorityKeyId:    false,     // 4.2.1.1 - MUST NOT be critical
  certificatePolicy: false,
  crlDistribution:   false,
  authorityInfoAccess: false    // 4.2.2.1 - MUST NOT be critical
};

// RFC 5280 4.2.1.3, in bit order. The order IS the encoding.
var KEY_USAGE_ORDER = [
  'digitalSignature', 'nonRepudiation', 'keyEncipherment',
  'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign',
  'encipherOnly', 'decipherOnly'
];

// The purposes by name, from the OID table - which the reader names them by
// too, so what is read is written back under the same name. ocspSigning, the
// spelling this table used, is still taken (oid.js's alias).
var EKU_NAMES = {};
['serverAuth', 'clientAuth', 'codeSigning', 'emailProtection', 'timeStamping',
  'OCSPSigning', 'anyExtendedKeyUsage'].forEach(function (n) {
  EKU_NAMES[n] = OID.to_string(OID.by_name('eku_' + n));
});

var WRITERS = {
  basicConstraints: function (v) {
    var parts = [];

    if (v.ca === true) {
      parts.push(W.boolean(true));

      // ⚠ pathLenConstraint ONLY MEANS ANYTHING WITH ca TRUE, and RFC 5280
      // 4.2.1.9 additionally requires keyCertSign. A path length on a leaf
      // is a constraint on a chain that cannot exist.
      if (v.path_length !== undefined && v.path_length !== null) {
        if (v.path_length < 0) {
          fail_pkix('bad-path-length', 'a path length constraint is not negative');
        }
        parts.push(W.unsigned(count_bytes(v.path_length)));
      }
    } else if (v.path_length !== undefined && v.path_length !== null) {
      fail_pkix('path-length-without-ca',
        'pathLenConstraint constrains a chain below this certificate, and ' +
        'a certificate that is not a CA has nothing below it');
    }

    // ⚠ `ca: false` IS ENCODED AS AN EMPTY SEQUENCE, not as BOOLEAN FALSE.
    // The field has DEFAULT FALSE and X.690 11.5 forbids encoding a value
    // equal to its default.
    return W.sequence(parts);
  },

  keyUsage: function (v) {
    if (!Array.isArray(v) || v.length === 0) {
      fail_pkix('bad-key-usage',
        'keyUsage is a non-empty array of names: ["digitalSignature"]');
    }

    var highest = -1;
    var bits = [];
    var i;

    for (i = 0; i < v.length; i++) {
      var at = KEY_USAGE_ORDER.indexOf(v[i]);

      if (at === -1) {
        fail_pkix('unknown-key-usage',
          '"' + v[i] + '" is not a key usage. The nine are: ' +
          KEY_USAGE_ORDER.join(', '));
      }

      bits[at] = true;
      if (at > highest) { highest = at; }
    }

    // ⚠ THE BIT STRING IS TRIMMED TO THE HIGHEST SET BIT, and `unused` says
    // how many trailing bits are absent. DER requires the minimal form here,
    // so a fixed two-byte encoding would be refused by a strict reader -
    // including this library's own.
    var bytes = new Uint8Array(Math.floor(highest / 8) + 1);

    for (i = 0; i <= highest; i++) {
      if (bits[i] === true) {
        bytes[Math.floor(i / 8)] |= 1 << (7 - (i % 8));
      }
    }

    return W.bit_string(bytes, 7 - (highest % 8));
  },

  extKeyUsage: function (v) {
    if (!Array.isArray(v) || v.length === 0) {
      fail_pkix('bad-eku', 'extKeyUsage is a non-empty array');
    }

    return W.sequence(v.map(function (purpose) {
      // A name, a dotted OID, or { id, name } as x509.from_der returns it.
      var name = purpose !== null && typeof purpose === 'object' ? purpose.id : purpose;
      if (typeof name === 'string' && /^\d+(\.\d+)+$/.test(name)) {
        return W.oid(OID.from_string(name));
      }
      try {
        return W.oid(OID.by_name('eku_' + name));
      } catch (e) {
        fail_pkix('unknown-eku',
          '"' + name + '" is not a known extended key usage. Pass a dotted ' +
          'OID for one this library does not name.');
      }
    }));
  },

  subjectAltName: function (v) {
    if (!Array.isArray(v) || v.length === 0) {
      fail_pkix('empty-alt-name', 'subjectAltName needs at least one name');
    }
    return W.sequence(v.map(general_name_to_der));
  },

  issuerAltName: function (v) {
    return W.sequence(v.map(general_name_to_der));
  },

  subjectKeyId: function (v) {
    // ⚠ RFC 5280 4.2.1.2 suggests the SHA-1 of the public key BIT STRING,
    // and this library computes no hashes - so the caller supplies it. That
    // is the boundary, not an omission.
    return W.octet_string(to_bytes(v));
  },

  authorityKeyId: function (v) {
    var parts = [];

    if (v.key_id !== undefined && v.key_id !== null) {
      parts.push(W.implicit(0, W.octet_string(to_bytes(v.key_id))));
    }

    // ⚠ issuer AND serial TRAVEL TOGETHER OR NOT AT ALL - RFC 5280 4.2.1.1.
    // One without the other identifies nothing.
    var has_issuer = v.issuer !== undefined && v.issuer !== null;
    var has_serial = v.serial !== undefined && v.serial !== null;

    if (has_issuer !== has_serial) {
      fail_pkix('incomplete-authority-key-id',
        'authorityCertIssuer and authorityCertSerialNumber are both ' +
        'present or both absent');
    }

    if (has_issuer) {
      parts.push(W.implicit(1, W.sequence(
        v.issuer.map(general_name_to_der))));
      parts.push(W.implicit(2, W.unsigned(to_bytes(v.serial))));
    }

    if (parts.length === 0) {
      fail_pkix('empty-authority-key-id',
        'an authorityKeyIdentifier with no fields identifies nothing');
    }

    return W.sequence(parts);
  },

  nameConstraints: function (v) {
    var parts = [];

    if (v.permitted !== undefined) {
      parts.push(W.implicit(0, W.sequence(v.permitted.map(subtree))));
    }
    if (v.excluded !== undefined) {
      parts.push(W.implicit(1, W.sequence(v.excluded.map(subtree))));
    }

    if (parts.length === 0) {
      fail_pkix('empty-name-constraints',
        'a nameConstraints extension with neither tree constrains nothing, ' +
        'and RFC 5280 4.2.1.10 forbids it');
    }

    return W.sequence(parts);
  },

  authorityInfoAccess: function (v) {
    return W.sequence(v.map(function (d) {
      var method = d.method === 'ocsp' ? '1.3.6.1.5.5.7.48.1'
        : d.method === 'caIssuers' ? '1.3.6.1.5.5.7.48.2'
        : d.method;

      if (!/^\d+(\.\d+)+$/.test(method)) {
        fail_pkix('unknown-access-method',
          '"' + d.method + '" is not an access method. Use ocsp, ' +
          'caIssuers, or a dotted OID.');
      }

      return W.sequence([
        W.oid(OID.from_string(method)),
        general_name_to_der(d.location)
      ]);
    }));
  },

  crlDistribution: function (v) {
    return W.sequence(v.map(function (point) {
      var names = Array.isArray(point) ? point : point.names;

      return W.sequence([
        W.explicit(0, W.implicit(0, W.sequence(
          names.map(general_name_to_der))))
      ]);
    }));
  },

  certificatePolicy: function (v) {
    return W.sequence(v.map(function (p) {
      var id = typeof p === 'string' ? p : p.id;
      var fields = [W.oid(oid_of(id))];

      if (typeof p === 'object' && p.cps !== undefined) {
        fields.push(W.sequence([
          W.sequence([
            W.oid(OID.from_string('1.3.6.1.5.5.7.2.1')),
            W.ia5_string(p.cps)
          ])
        ]));
      }

      return W.sequence(fields);
    }));
  },

  inhibitAnyPolicy: function (v) {
    return W.unsigned(count_bytes(v));
  },

  // Device attestation, as x509.js reads it (device_attestation.js) - for
  // test certificates and test authorities; a device writes the real ones.
  // SEQUENCE { [1] EXPLICIT OCTET STRING nonce }, as read: { nonce }.
  appleNonce: function (v) {
    var nonce = v instanceof Uint8Array ? v : v && v.nonce;
    return W.sequence([W.explicit(1, W.octet_string(to_bytes(nonce)))]);
  },
  // ⚠ Managed Device Attestation's values are the text itself - no ASN.1
  // inside extnValue.
  appleSerialNumber: apple_text,
  appleUdid: apple_text,
  appleOsVersion: apple_text,
  appleSepOsVersion: apple_text,
  appleLlbVersion: apple_text,
  appleFreshnessCode: function (v) { return to_bytes(v); }
};

function apple_text(v) {
  if (typeof v !== 'string') {
    fail_pkix('bad-extension', 'a Managed Device Attestation value is text');
  }
  return encode_utf8(v);
}

//   GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0] DEFAULT 0,
//                                 maximum [1] OPTIONAL }
//
// ⚠ minimum AND maximum ARE NOT USED BY ANYTHING, and RFC 5280 4.2.1.10 says
// so outright - minimum MUST be zero and maximum MUST be absent. Writing
// either produces a constraint conforming verifiers reject.
function subtree(base) {
  return W.sequence([general_name_to_der(base, true)]);
}

// ⚠ commons/bytes.js ALREADY HAD THIS, and I wrote it again.
//
// The commons version returns an ARRAY and takes anything; this needed a
// Uint8Array and a check that the input is a non-negative whole number,
// because a path length or a skipCerts count arriving as -1 or as 1.5 is a
// caller mistake worth naming.
//
// So the conversion is shared and the validation is not - the same split as
// checked_digest_size in tsp.js, where the table is shared and each module
// turns the null into its own refusal.
function count_bytes(n) {
  if (typeof n !== 'number' || n < 0 || Math.floor(n) !== n) {
    fail_pkix('bad-integer', 'expected a non-negative whole number, got ' + n);
  }

  return new Uint8Array(int_bytes(n));
}

function public_key_to_der(key) {
  if (key instanceof Uint8Array) {
    // Already an encoded SubjectPublicKeyInfo.
    return key;
  }

  if (key && key.der instanceof Uint8Array) {
    // What spki.from_der returned - use the bytes it kept.
    return key.der;
  }

  fail_pkix('bad-public-key',
    'the public key is a SubjectPublicKeyInfo: pass the DER, or the object ' +
    'spki.from_der returned');
}

function certificate_extensions_to_der(extensions, parts) {
  if (extensions === undefined || extensions === null) {
    return null;
  }

  var out = [];
  var name;

  for (name in extensions) {
    if (!Object.prototype.hasOwnProperty.call(extensions, name)) {
      continue;
    }

    var value = extensions[name];

    if (value === null || value === undefined) {
      continue;
    }

    // A caller may pass { critical, value } to override the default.
    var explicit_critical = null;
    var payload = value;

    if (value && typeof value === 'object' && !Array.isArray(value) &&
        value.value !== undefined && value.critical !== undefined) {
      explicit_critical = value.critical === true;
      payload = value.value;
    }

    out.push(named_extension_to_der(name, payload, explicit_critical, parts));
  }

  if (out.length === 0) {
    return null;
  }

  return W.sequence(out);
}

function named_extension_to_der(name, value, explicit_critical, parts) {
  var writer = WRITERS[name];

  if (writer === undefined) {
    // ⚠ RAW BYTES ARE ACCEPTED FOR EXTENSIONS THIS MODULE DOES NOT WRITE.
    //
    // There are more extensions than any library will implement, and a
    // caller who has the encoding should not be blocked. What is refused is
    // a NAME with no writer and no bytes, which is a typo.
    if (value instanceof Uint8Array) {
      return raw_extension(name, value, explicit_critical === true);
    }

    fail_pkix('unknown-extension',
      'no writer for extension "' + name + '". Pass the encoded value as ' +
      'bytes if you have it.');
  }

  var critical = explicit_critical === null
    ? default_critical(name, value, parts)
    : explicit_critical;

  return build_extension('ext_' + name, critical, W.to_bytes(writer(value)));
}

// ⚠ basicConstraints IS CRITICAL FOR A CA AND NEED NOT BE FOR A LEAF, and
// subjectAltName becomes critical when the subject is empty - because then
// it is the only name the certificate has.
function default_critical(name, value, parts) {
  if (name === 'basicConstraints') {
    return value.ca === true;
  }

  if (name === 'subjectAltName') {
    return Array.isArray(parts.subject) && parts.subject.length === 0;
  }

  return CRITICAL_BY_DEFAULT[name] === true;
}

// The Extension SEQUENCE, given an already-resolved OID.
//
//   Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
//                            extnValue OCTET STRING }
//
// There were two of these - one taking a name and one taking bytes - and they
// differed only in how the OID was found. The duplication analysis flagged it
// while the module was still being written, which is the earliest it has ever
// fired.
function extension_sequence(oid, critical, value) {
  return extension_to_der(oid, critical, value, fail_pkix);
}

function build_extension(oid_name, critical, value) {
  return extension_sequence(OID.by_name(oid_name), critical, value);
}

function raw_extension(name, value, critical) {
  return extension_to_der(name, critical, value, fail_pkix);
}


// CRLReason, RFC 5280 5.3.1 - the codes a CRL entry and an OCSP response
// both write. (crl.js reads them; its table is the reader's own.)
// RFC 5280 5.3.1. The numbers are the encoding, and 7 is unassigned - a gap
// left when removeFromCRL was renumbered, which is why this is a table
// rather than an index into an array.
var REASONS = {
  unspecified:          0,
  keyCompromise:        1,
  cACompromise:         2,
  affiliationChanged:   3,
  superseded:           4,
  cessationOfOperation: 5,
  certificateHold:      6,
  removeFromCRL:        8,
  privilegeWithdrawn:   9,
  aACompromise:         10
};

// IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }
//
// How CMS names a signer or recipient (RFC 5652 10.2.4), and an attribute
// certificate its holder's base certificate. `cert` is what x509.from_der
// returned: the issuer passes through as its original bytes - a verifier
// matches them byte for byte - and the serial is its INTEGER content,
// unchanged. Three builders wrote this, one with a different INTEGER writer.
function issuer_and_serial_to_der(cert, fail) {
  if (!cert || !cert.issuer || !(cert.serial instanceof Uint8Array)) {
    fail('bad-certificate',
      'a certificate is named by its issuer and serial - hand over what ' +
      'x509.from_der returned');
  }
  // A Name as a reader returned it or as a builder takes it - SCEP's
  // GetCert names a certificate the caller describes, not one it read.
  return W.sequence([x509_name_to_der(cert.issuer),
                     W.integer(cert.serial)]);
}

export {
  status_info_to_der,
  x509_name_to_der,
  general_name_to_der,
  public_key_to_der,
  certificate_extensions_to_der,
  issuer_and_serial_to_der,
  KEY_USAGE_ORDER,
  EKU_NAMES,
  REASONS,
  as_date,
  validity_days,
  extension_oid,
  extension_to_der,
  raw_extensions_to_der,
  validity_to_der,
  number_bytes,
  assemble_signed,
  attribute_to_der,
  STRING_TYPES,
  time_to_der,
  algorithm_to_der,
  digest_algorithm_to_der,
  encapsulated_to_der,
  name_to_der
};
