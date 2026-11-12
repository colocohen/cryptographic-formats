// The FIDO Metadata Service BLOB, MDS3 (FIDO Metadata Service v3.0,
// 2021-05-18): what the FIDO Alliance publishes about every certified
// authenticator - its attestation roots, and its status reports.
//
// The BLOB is a JWT (section 3.1.7): a JWS whose header carries the signing
// chain in x5c (or points to it with x5u), and whose payload is
//
//   MetadataBLOBPayload       { legalHeader?, no, nextUpdate, entries }
//   MetadataBLOBPayloadEntry  { aaid?, aaguid?, attestationCertificateKeyIdentifiers?,
//                               metadataStatement?, biometricStatusReports?,
//                               statusReports, timeOfLastStatusChange,
//                               rogueListURL?, rogueListHash? }
//   StatusReport              { status, effectiveDate?, authenticatorVersion?,
//                               certificate?, url?, certificationDescriptor?,
//                               certificateNumber?, certificationPolicyVersion?,
//                               certificationRequirementsVersion? }
//
// The order is jwt.js's: decode (structure only) - verify, the caller's -
// payload (only with `verified` true and an accepted algorithm). Section 3.2
// is the caller's too: the chain to the MDS root, its CRLs, x5u's origin,
// and `no` above the one cached. The plan says so; nothing here decides it.
//
// ⚠ STATUSES ARE REPORTED, NOT GROUPED. Which of them a relying party
// accepts is its policy (3.2: "It is up to the relying party to specify
// behavior for authenticators with status reports that indicate a lack of
// certification, or known security issues"). An unknown status is kept,
// `known: false` - 3.1.4 says to ignore unknown values silently, so it is
// not refused, and the caller sees it.

import * as JWS from './jws.js';
import * as JWT from './jwt.js';
import * as JSON_ from './json.js';
import * as B from './base.js';
import { make_fail_here } from './commons/fail.js';
import { hex } from './commons/bytes.js';

var fail = make_fail_here('fido_mds');

// 3.1.4, AuthenticatorStatus.
var STATUSES = [
  'NOT_FIDO_CERTIFIED', 'FIDO_CERTIFIED', 'USER_VERIFICATION_BYPASS',
  'ATTESTATION_KEY_COMPROMISE', 'USER_KEY_REMOTE_COMPROMISE',
  'USER_KEY_PHYSICAL_COMPROMISE', 'UPDATE_AVAILABLE', 'REVOKED',
  'SELF_ASSERTION_SUBMITTED', 'FIDO_CERTIFIED_L1', 'FIDO_CERTIFIED_L1plus',
  'FIDO_CERTIFIED_L2', 'FIDO_CERTIFIED_L2plus', 'FIDO_CERTIFIED_L3',
  'FIDO_CERTIFIED_L3plus'
];

// Structure only: the header, the signing chain, what the signature covers.
function decode(token) {
  // jwt.js's checks: compact, three parts, a header it can read.
  var t = JWT.decode(token);
  var header = t.header;
  var x5c = JSON_.member(header, 'x5c');
  var x5u = JSON_.member(header, 'x5u');
  var certificates = [];
  if (x5c !== undefined) {
    if (!Array.isArray(x5c) || x5c.length === 0) {
      fail('bad-mds-blob', 'x5c is a non-empty array of certificates');
    }
    certificates = x5c.map(function (c) {
      if (typeof c !== 'string') {
        fail('bad-mds-blob', 'an x5c certificate is base64 text');
      }
      // RFC 7515 4.1.6: base64, not base64url.
      return B.from_base64(c);
    });
  }
  return {
    jws: t.jws,
    alg: t.alg,
    header: header,
    // Leaf first (RFC 7515 4.1.6). Empty when the header has none - then
    // x5u, or the MDS root itself, is the chain (3.2).
    certificates: certificates,
    x5u: typeof x5u === 'string' ? x5u : null,
    signing_input: t.signing_input,
    signature: t.signature,
    note: 'verify the signature with certificates[0] (or the chain at x5u, ' +
      'same origin as the BLOB - section 3.2), the chain to the MDS root and ' +
      'its CRLs; then payload(). Ignore a BLOB whose `no` is not above the ' +
      'one cached'
  };
}

// The payload, once the caller says the signature verified with an
// algorithm it accepts - JWS.read_verified's rule.
function payload(decoded, accepted, verified) {
  var bytes = JWS.read_verified(decoded.jws, accepted, verified);
  var p = JSON_.parse(bytes);
  if (p === null || typeof p !== 'object' || Array.isArray(p)) {
    fail('bad-mds-blob', 'the payload is a MetadataBLOBPayload object');
  }
  var no = required(p, 'no', 'number', 'MetadataBLOBPayload');
  if (no !== Math.floor(no) || no < 0) {
    fail('bad-mds-blob', 'no is a serial number, a whole number');
  }
  var entries = required(p, 'entries', 'array', 'MetadataBLOBPayload');
  return {
    no: no,
    next_update: date(required(p, 'nextUpdate', 'string', 'MetadataBLOBPayload'), 'nextUpdate'),
    legal_header: optional(p, 'legalHeader', 'string'),
    entries: entries.map(entry)
  };
}

function entry(e, i) {
  var where = 'entries[' + i + ']';
  if (e === null || typeof e !== 'object' || Array.isArray(e)) {
    fail('bad-mds-entry', where + ' is an object');
  }
  var aaguid = optional(e, 'aaguid', 'string');
  if (aaguid !== null && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(aaguid)) {
    fail('bad-mds-entry', where + ': aaguid is 8-4-4-4-12 hex');
  }
  var aaid = optional(e, 'aaid', 'string');
  if (aaid !== null && !/^[0-9a-f]{4}#[0-9a-f]{4}$/i.test(aaid)) {
    fail('bad-mds-entry', where + ': aaid is "V#M", four hex digits each (UAF)');
  }
  var kids = optional(e, 'attestationCertificateKeyIdentifiers', 'array');
  if (kids !== null) {
    kids.forEach(function (k) {
      if (typeof k !== 'string' || !/^[0-9a-f]+$/i.test(k)) {
        fail('bad-mds-entry', where + ': a key identifier is hex');
      }
    });
  }
  return {
    aaguid: aaguid === null ? null : aaguid.toLowerCase(),
    aaid: aaid === null ? null : aaid.toLowerCase(),
    attestation_certificate_key_identifiers: kids === null ? null
      : kids.map(function (k) { return k.toLowerCase(); }),
    // The MetadataStatement as published: a large JSON object whose shape
    // is its own specification's. attestation_roots() reads the part
    // attestations need.
    metadata_statement: optional(e, 'metadataStatement', 'object'),
    biometric_status_reports: optional(e, 'biometricStatusReports', 'array'),
    status_reports: required(e, 'statusReports', 'array', where).map(function (r, j) {
      return status_report(r, where + '.statusReports[' + j + ']');
    }),
    time_of_last_status_change: date(required(e, 'timeOfLastStatusChange', 'string', where),
      where + '.timeOfLastStatusChange'),
    rogue_list_url: optional(e, 'rogueListURL', 'string'),
    rogue_list_hash: optional(e, 'rogueListHash', 'string')
  };
}

function status_report(r, where) {
  if (r === null || typeof r !== 'object' || Array.isArray(r)) {
    fail('bad-mds-entry', where + ' is an object');
  }
  var status = required(r, 'status', 'string', where);
  var effective = optional(r, 'effectiveDate', 'string');
  var cert = optional(r, 'certificate', 'string');
  return {
    status: status,
    known: STATUSES.indexOf(status) !== -1,
    effective_date: effective === null ? null : date(effective, where + '.effectiveDate'),
    authenticator_version: optional(r, 'authenticatorVersion', 'number'),
    // 3.1.3: "Base64-encoded [RFC4648] (not base64url!) DER [ITU-X690-2008]
    // PKIX certificate".
    certificate: cert === null ? null : B.from_base64(cert),
    url: optional(r, 'url', 'string'),
    certification_descriptor: optional(r, 'certificationDescriptor', 'string'),
    certificate_number: optional(r, 'certificateNumber', 'string'),
    certification_policy_version: optional(r, 'certificationPolicyVersion', 'string'),
    certification_requirements_version: optional(r, 'certificationRequirementsVersion', 'string')
  };
}

// The entry for an authenticator: by AAGUID (FIDO2 - 16 bytes, or text with
// or without dashes), AAID (UAF - "V#M"), or attestation certificate key
// identifier (U2F - the 20-byte SHA-1 of the certificate's public key, as
// hex or bytes). Which one is read off the form, and none is like another.
// null when none matches; two entries matching is refused - a BLOB that
// answers twice does not answer.
function entry_for(blob, id) {
  var key = identifier(id);
  var found = blob.entries.filter(function (e) {
    if (key.kind === 'aaguid') { return e.aaguid !== null && e.aaguid.replace(/-/g, '') === key.value; }
    if (key.kind === 'aaid') { return e.aaid === key.value; }
    return e.attestation_certificate_key_identifiers !== null &&
      e.attestation_certificate_key_identifiers.indexOf(key.value) !== -1;
  });
  if (found.length > 1) {
    fail('duplicate-mds-entry', found.length + ' entries for ' + key.kind + ' ' + key.value);
  }
  return found.length === 0 ? null : found[0];
}

function identifier(id) {
  if (id instanceof Uint8Array) {
    if (id.length === 16) { return { kind: 'aaguid', value: hex(id) }; }
    if (id.length === 20) { return { kind: 'key_identifier', value: hex(id) }; }
    fail('bad-mds-identifier', 'an AAGUID is 16 bytes and a key identifier 20; got ' + id.length);
  }
  var s = String(id).toLowerCase();
  if (/^[0-9a-f]{4}#[0-9a-f]{4}$/.test(s)) { return { kind: 'aaid', value: s }; }
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s) ||
      /^[0-9a-f]{32}$/.test(s)) {
    return { kind: 'aaguid', value: s.replace(/-/g, '') };
  }
  if (/^[0-9a-f]{40}$/.test(s)) { return { kind: 'key_identifier', value: s }; }
  fail('bad-mds-identifier', 'an AAGUID (32 hex digits, dashes allowed), an ' +
    'AAID ("V#M") or a key identifier (40 hex digits)');
}

// The metadata statement's attestationRootCertificates, DER - the trust
// anchors an attestation from this model chains to (FIDO Metadata Statement
// 4, "base64-encoded (not base64url!) DER"). Empty when the statement has
// none, or there is no statement.
function attestation_roots(e) {
  var ms = e.metadata_statement;
  if (ms === null) { return []; }
  var roots = JSON_.member(ms, 'attestationRootCertificates');
  if (roots === undefined) { return []; }
  if (!Array.isArray(roots)) {
    fail('bad-mds-entry', 'attestationRootCertificates is an array');
  }
  return roots.map(function (c) {
    if (typeof c !== 'string') {
      fail('bad-mds-entry', 'an attestation root is base64 text');
    }
    return B.from_base64(c);
  });
}

// ---------------------------------------------------------------------------

function type_of(v) {
  return v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v;
}

function required(obj, name, type, where) {
  var v = JSON_.member(obj, name);
  if (v === undefined) {
    fail('missing-mds-member', where + ' has no ' + name);
  }
  if (type_of(v) !== type) {
    fail('bad-mds-member', where + '.' + name + ' is a ' + type + ', not a ' + type_of(v));
  }
  return v;
}

function optional(obj, name, type) {
  var v = JSON_.member(obj, name);
  if (v === undefined) { return null; }
  if (type_of(v) !== type) {
    fail('bad-mds-member', name + ' is a ' + type + ', not a ' + type_of(v));
  }
  return v;
}

// ISO-8601 dates as the spec's examples write them, "2014-01-04": a date,
// checked as one, kept as text - a day has no time zone to guess.
function date(s, where) {
  var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  var d = m === null ? null : new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
  if (d === null || d.getUTCMonth() !== +m[2] - 1 || d.getUTCDate() !== +m[3]) {
    fail('bad-mds-date', where + ' is YYYY-MM-DD, not "' + s + '"');
  }
  return s;
}

export {
  decode,
  payload,
  entry_for,
  attestation_roots,
  STATUSES
};
