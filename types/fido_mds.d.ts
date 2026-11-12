// The FIDO Metadata Service BLOB, MDS3 (FIDO Metadata Service v3.0).
// decode (structure) -> the caller verifies -> payload (only when verified).

import type { JsonObject, JsonValue } from './json.js';
import type { JwsSignature } from './jws.js';

export interface DecodedMdsBlob {
  jws: JwsSignature;
  alg: string;
  header: JsonObject;
  /** x5c, DER, leaf first; empty when the header has none (then x5u, or the MDS root, is the chain). */
  certificates: Uint8Array[];
  x5u: string | null;
  signing_input: Uint8Array;
  signature: Uint8Array;
  note: string;
}

export interface MdsStatusReport {
  status: string;
  /** One of STATUSES; an unknown status is kept (3.1.4: ignore silently). */
  known: boolean;
  /** YYYY-MM-DD. */
  effective_date: string | null;
  authenticator_version: number | null;
  /** DER. */
  certificate: Uint8Array | null;
  url: string | null;
  certification_descriptor: string | null;
  certificate_number: string | null;
  certification_policy_version: string | null;
  certification_requirements_version: string | null;
}

export interface MdsEntry {
  /** Lower case, 8-4-4-4-12. */
  aaguid: string | null;
  /** Lower case, "v#m". */
  aaid: string | null;
  /** Lower-case hex. */
  attestation_certificate_key_identifiers: string[] | null;
  /** As published. */
  metadata_statement: JsonObject | null;
  biometric_status_reports: JsonValue[] | null;
  status_reports: MdsStatusReport[];
  time_of_last_status_change: string;
  rogue_list_url: string | null;
  rogue_list_hash: string | null;
}

export interface MdsBlob {
  /** Serial: ignore a BLOB whose no is not above the cached one (3.2). */
  no: number;
  /** YYYY-MM-DD. */
  next_update: string;
  legal_header: string | null;
  entries: MdsEntry[];
}

export function decode(token: string): DecodedMdsBlob;
export function payload(decoded: DecodedMdsBlob, accepted: string[], verified: boolean): MdsBlob;
/** By AAGUID (text or 16 bytes), AAID ("v#m"), or attestation key identifier (40 hex digits or 20 bytes). */
export function entry_for(blob: MdsBlob, id: string | Uint8Array): MdsEntry | null;
/** The statement's attestationRootCertificates, DER. */
export function attestation_roots(entry: MdsEntry): Uint8Array[];
/** AuthenticatorStatus (3.1.4), all fifteen. */
export const STATUSES: readonly string[];
