// X.509 certificates (RFC 5280): reading, names, extensions, and the checks
// a verifier needs from the format - hostnames, name constraints, critical
// extensions. Building is x509_build.

import type {
  AlgorithmDescription, BytesInput, Extension, ExtensionEntry, GeneralName,
  Name, PublicKey, Time
} from './types.js';
import type { Reader } from './der_reader.js';
import type { Sct } from './sct.js';
import type { KeyDescription } from './device_attestation.js';

export type { Extension, GeneralName, Name };

export interface KeyUsage {
  digitalSignature: boolean;
  nonRepudiation: boolean;
  keyEncipherment: boolean;
  dataEncipherment: boolean;
  keyAgreement: boolean;
  keyCertSign: boolean;
  cRLSign: boolean;
  encipherOnly: boolean;
  decipherOnly: boolean;
}

export interface BasicConstraints {
  ca: boolean;
  path_len: number | null;
}

/** A subtree: its base, and - forbidden by RFC 5280, refused by the checks - a minimum or maximum. */
export type GeneralSubtree = GeneralName & { minimum?: number; maximum?: number };

export interface NameConstraints {
  permitted: GeneralSubtree[];
  excluded: GeneralSubtree[];
}

/** Constraints as the checks take them: parsed, or written by hand. */
export interface NameConstraintsInput {
  permitted: Array<{ type: string; value?: unknown; minimum?: number; maximum?: number }>;
  excluded: Array<{ type: string; value?: unknown; minimum?: number; maximum?: number }>;
}

export interface AuthorityKeyId {
  key_id: Uint8Array | null;
  issuer: GeneralName[] | null;
  serial: Uint8Array | null;
}

export interface AccessDescription {
  /** 'ad_ocsp', 'ad_caIssuers'..., or the dotted OID. */
  method: string;
  method_oid: Uint8Array;
  location: GeneralName;
}

export interface DistributionPoint {
  names: GeneralName[];
  /** REASON_FLAGS names; null when the point covers every reason. */
  reasons: string[] | null;
  issuer: GeneralName[] | null;
  /** True when the point covers only some reasons. */
  partial: boolean;
  relative?: null;
  /** nameRelativeToCRLIssuer, kept whole. */
  relative_raw?: Uint8Array;
}

export interface PolicyInformation {
  id: string;
  name: string | null;
  /** anyPolicy, 2.5.29.32.0. */
  any: boolean;
  qualifiers: Array<{ id: string; name: string | null; value: string | Uint8Array | null }>;
}

/** The parsed value of each extension this module reads, by builder name. */
export interface ParsedExtensions {
  basicConstraints: BasicConstraints;
  keyUsage: KeyUsage;
  /** Each purpose: the dotted OID, and the name the builder takes ('serverAuth') or null. */
  extKeyUsage: Array<{ id: string; name: string | null }>;
  subjectAltName: GeneralName[];
  issuerAltName: GeneralName[];
  subjectKeyId: Uint8Array;
  authorityKeyId: AuthorityKeyId;
  nameConstraints: NameConstraints;
  authorityInfoAccess: AccessDescription[];
  subjectInfoAccess: AccessDescription[];
  crlDistribution: DistributionPoint[];
  freshestCRL: DistributionPoint[];
  certificatePolicy: PolicyInformation[];
  policyConstraints: { require_explicit: number | null; inhibit_mapping: number | null };
  policyMappings: Array<{ issuer: string; subject: string }>;
  inhibitAnyPolicy: number;
  sct_list: Sct[];
  precert_poison: { poison: true; note: string };
  /** Apple WebAuthn / App Attest: SHA-256(authData || clientDataHash). */
  appleNonce: { nonce: Uint8Array };
  /** Managed Device Attestation: the extension's bytes are the text. */
  appleSerialNumber: string;
  appleUdid: string;
  appleOsVersion: string;
  appleSepOsVersion: string;
  appleLlbVersion: string;
  /** SHA-256 of the device-attest-01 token, or the DeviceAttestationNonce. */
  appleFreshnessCode: Uint8Array;
  androidKeyDescription: KeyDescription;
}

export interface Certificate {
  /** 1, 2 or 3. */
  version: number;
  /** The serial's content bytes (positive). */
  serial: Uint8Array;
  issuer: Name;
  subject: Name;
  validity: { not_before: Time; not_after: Time };
  public_key: PublicKey;
  signature: Uint8Array;
  /** By OID-table name, or 'name (dotted)' when the table has none. */
  signature_algorithm: string;
  signature_params: AlgorithmDescription;
  /** The TBSCertificate exactly as it arrived - what the signature covers. */
  tbs_bytes: Uint8Array;
  der: Uint8Array;
  extensions: Extension[];
  /** Dotted OIDs (with names) of critical extensions this module cannot read. */
  unhandled_critical: string[];
  /** Profile violations read anyway, e.g. GeneralizedTime before 2050. */
  /**
   * Violations read rather than refused - those OpenSSL accepts and that
   * cannot be read two ways - each with its code, and the extension it was in.
   */
  warnings: Array<{ code: string; detail: string; extension?: string }>;
}

export const KEY_USAGE_BITS: readonly string[];
export const REASON_FLAGS: readonly string[];
/** OpenSSL's NAME_CHECK_MAX, 2^20. */
export const NAME_CHECK_MAX: number;
/** The dotted OIDs OpenSSL accepts as critical (X509_supported_extension). */
export const OPENSSL_SUPPORTED: readonly string[];

export function from_der(input: BytesInput): Certificate;

/**
 * An extension by builder name ('subjectAltName'), table name
 * ('ext_subjectAltName') or dotted OID; null when absent.
 */
export function extension<K extends keyof ParsedExtensions>(cert: { extensions: Extension[] }, name: K): Extension<ParsedExtensions[K]> | null;
export function extension(cert: { extensions: Extension[] }, name: string): Extension | null;

/** notBefore <= when <= notAfter (inclusive, RFC 5280 4.1.2.5). Default now. */
export function validity_contains(cert: { validity: { not_before: Time; not_after: Time } }, when?: Date): boolean;

/** RFC 5280 7.1 comparison: case and whitespace folded, RDNs as sets. */
export function name_matches(a: Name, b: Name): boolean;

/** One name against one constraint, by type (default 'dns'). */
export function constraint_permits(constraint: unknown, name: unknown, type?: GeneralName['type']): boolean;

/**
 * One name against a nameConstraints value: false when excluded or outside
 * the permitted subtrees of its type; null for a constrained type with no
 * rule here.
 */
export function name_constraints_permit(constraints: NameConstraintsInput, name: GeneralName | { type: string; value?: unknown }): boolean | null;

export interface NameConstraintsResult {
  /** true; false when a name is refused; null when only unknown remain. */
  ok: boolean | null;
  /** names x subtrees, as OpenSSL counts. */
  checks: number;
  /** Each refused name, and which half refused it: 'excluded' (OpenSSL's 48) or 'not-permitted' (47). */
  refused: Array<{ type: string; value: unknown; reason: 'excluded' | 'not-permitted' }>;
  unknown: Array<GeneralName | { type: string; value: unknown }>;
}

/**
 * The whole certificate against one CA's constraints, with OpenSSL's 2^20
 * ceiling ('name-constraints-too-costly'). `common_name` also checks a
 * hostname-like CN when there is no DNS SAN.
 */
export function name_constraints_check(
  cert: { subject: Name; extensions: Extension[] },
  constraints: NameConstraintsInput,
  options?: { max_checks?: number; common_name?: boolean }
): NameConstraintsResult;

/** The critical extensions OpenSSL would refuse (error 34). */
/**
 * The critical extensions OpenSSL would refuse as unhandled (error 34). Not
 * "nothing left unchecked": OpenSSL enforces nsCertType, RFC 3779 and
 * proxyCertInfo by rules this library does not read - see unenforced_critical.
 */
export function openssl_unsupported_critical(cert: { extensions: Extension[] }): Array<{ id: string; name: string | null }>;
/** RFC 5280 5.3.1's reasons by code - null for the unused 7. */
export const CRL_REASONS: ReadonlyArray<string | null>;

/** Names or dotted OIDs resolved once, for unenforced_critical. */
export interface EnforcedSet { enforced_ids: Record<string, true> }
export function enforced_set(enforced: string[]): EnforcedSet;
/** The critical extensions not in `enforced` - the ones the caller enforces, by name or dotted OID, or an enforced_set. */
export function unenforced_critical(cert: { extensions: Extension[] }, enforced: string[] | EnforcedSet): Array<{ id: string; name: string | null }>;
/** A string per name, equal exactly when name_matches says two names match - for an index. */
export function name_key(name: Name): string;

/**
 * RFC 9525: SAN only (CN only with `common_name`), `*` only as a whole
 * left-most label, IP literals against iPAddress SANs only.
 */
export function hostname_matches(cert: { subject: Name; extensions: Extension[] }, host: string, options?: { common_name?: boolean }): boolean;

/** An IPv4 or IPv6 literal (brackets optional) as bytes, or null. */
export function parse_ip(text: string): Uint8Array | null;

export function has_unhandled_critical(cert: { unhandled_critical: string[] }): boolean;

/** The first commonName, for display - not for verification. */
export function common_name(name: Name): string | null;

/** RFC 4514; `readable` puts it in reading order, for display only. */
export function name_to_string(name: Name, options?: { readable?: boolean }): string;

/** Every value of an attribute: 'CN', 'commonName', 'stateOrProvinceName' or a dotted OID. */
export function name_attribute(name: Name, type: string): string[];

/** Reads one GeneralName from a cursor (exported for attrcert). */
export function read_general_name(r: Reader, in_constraint?: boolean): GeneralName;

/** The entry every reader returns for an Extension, as the field tables read it. */
export function extension_entry(ext: { extnID: Uint8Array; critical?: boolean; extnValue: Uint8Array }): ExtensionEntry;

/** The entry with its value decoded - what certificates, CSRs and CRMF templates return. */
export function read_extension(ext: { extnID: Uint8Array; critical?: boolean; extnValue: Uint8Array }): Extension;

export function is_precertificate(cert: { extensions: Extension[] }): boolean;

/** The OCSP responder URLs from AIA. */
export function ocsp_urls(cert: { extensions: Extension[] }): string[];
/** The caIssuers URLs from AIA. */
export function issuer_urls(cert: { extensions: Extension[] }): string[];
/** CRL distribution point URLs; points covering only some reasons with `partial`. */
export function crl_urls(cert: { extensions: Extension[] }, options?: { partial?: boolean }): string[];
