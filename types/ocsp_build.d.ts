// Building OCSP requests and responses.

import type { BytesInput, Name, NameInput } from './types.js';

/** A CertID: its DER, or the parts - the hashes computed by the caller. */
export type CertIdInput =
  | Uint8Array
  | { der: Uint8Array }
  | { hash?: string; name_hash: BytesInput; key_hash: BytesInput; serial: BytesInput };

export interface SingleResponseInput {
  cert_id: CertIdInput;
  status: 'good' | 'revoked' | 'unknown';
  revoked_at?: Date;
  reason?: string;
  this_update: Date;
  next_update?: Date | null;
}

export interface ResponseParts {
  /** By name, or by key_hash (SHA-1 of the responder key's BIT STRING content). */
  responder: { name: NameInput } | { key_hash: BytesInput };
  produced_at: Date;
  responses: SingleResponseInput[];
  /** The request's nonce, to echo. */
  nonce?: BytesInput | null;
  signature_algorithm: string;
  /** DER certificates to include - a delegated responder's. */
  certificates?: BytesInput[];
}

export interface PreparedResponse {
  /** The ResponseData: sign exactly these bytes. */
  bytes: Uint8Array;
  signature_algorithm: string;
  certificates: BytesInput[];
}

/** Response status numbers by name. */
export const STATUS: Readonly<Record<string, number>>;

export function prepare(parts: ResponseParts): PreparedResponse;
/** A successful OCSPResponse around the BasicOCSPResponse. */
export function assemble(tbs: PreparedResponse, signature: BytesInput): Uint8Array;
/** An unsigned error response: the status alone. */
export function error_response(status: string): Uint8Array;

/** An unsigned OCSPRequest. */
export function request(parts: { requests: CertIdInput[]; nonce?: BytesInput | null }): Uint8Array;

/**
 * The bytes a CertID's hashes cover: `name` for name_hash (the issuer's
 * DER Name), `key` for key_hash (its SPKI BIT STRING content), and the
 * serial.
 */
export function cert_id_inputs(
  issuer: { public_key: { point: Uint8Array } },
  cert: { issuer: Name; serial: Uint8Array }
): { name: Uint8Array; key: Uint8Array; serial: Uint8Array };
