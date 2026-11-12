// OCSP (RFC 6960): requests and responses, read. Building is ocsp_build.

import type { AlgorithmDescription, BytesInput, Name, Time } from './types.js';

export interface CertId {
  /** The hash of name_hash and key_hash, by OID-table name. */
  hash: string;
  name_hash: Uint8Array;
  key_hash: Uint8Array;
  serial: Uint8Array;
  serial_hex: string;
}

export interface SingleResponse {
  cert_id: CertId;
  status: 'good' | 'revoked' | 'unknown';
  revoked_at: Time | null;
  reason: string | null;
  this_update: Time;
  next_update: Time | null;
}

export interface BasicResponse {
  responder: { by: 'name'; name: Name } | { by: 'key'; key_hash: Uint8Array };
  produced_at: Time;
  responses: SingleResponse[];
  nonce: Uint8Array | null;
  /** DER certificates - a delegated responder's, usually. */
  certificates: Uint8Array[];
  signature: Uint8Array;
  signature_algorithm: string;
  signature_params: AlgorithmDescription;
  /** The ResponseData as it arrived - what the signature covers. */
  tbs_bytes: Uint8Array;
}

export interface OcspResponse {
  status: 'successful' | 'malformedRequest' | 'internalError' | 'tryLater' | 'sigRequired' | 'unauthorized';
  /** Null for every status but successful - those are unsigned. */
  basic: BasicResponse | null;
  der: Uint8Array;
}

export interface OcspRequest {
  requests: CertId[];
  nonce: Uint8Array | null;
  /** Whether the request carries a signature (rare; not read further). */
  signed: boolean;
  der: Uint8Array;
}

/** Status names by number; 4 is unassigned (null). */
export const RESPONSE_STATUS: ReadonlyArray<string | null>;

export function request_from_der(input: BytesInput): OcspRequest;
export function response_from_der(input: BytesInput): OcspResponse;

/** What two CertIDs are compared on: the hash, both hashes, the serial. */
export type CertIdKey = Pick<CertId, 'hash' | 'name_hash' | 'key_hash' | 'serial_hex'>;

export function cert_id_matches(a: CertIdKey, b: CertIdKey): boolean;
/** The SingleResponse for a CertID, or null. */
export function find(response: { basic: BasicResponse | null }, cert_id: CertIdKey): SingleResponse | null;
/** thisUpdate <= when, and when <= nextUpdate if there is one. */
export function is_current(single: { this_update: Time; next_update: Time | null }, when?: Date): boolean;
