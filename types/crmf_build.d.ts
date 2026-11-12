// Building CRMF CertReqMessages: prepare -> the key being certified signs
// -> assemble.

import type { BytesInput, NameInput, PublicKeyInput, TimeInput } from './types.js';

export interface CertRequestParts {
  /** certReqId; default 0. */
  id?: number;
  public_key: PublicKeyInput;
  subject?: NameInput;
  issuer?: NameInput;
  serial?: BytesInput;
  validity?: { not_before?: TimeInput; not_after?: TimeInput };
  /** By name or dotted OID, as encoded extnValue bytes. */
  extensions?: Record<string, Uint8Array> | null;
  /** By CONTROLS name or dotted OID: encoded bytes, or a string for the text ones. */
  controls?: Record<string, Uint8Array | string> | null;
  /** For a signature proof. */
  signature_algorithm?: string;
}

export interface PreparedCertRequest {
  /** The CertRequest: what a signature proof covers. */
  bytes: Uint8Array;
  signature_algorithm: string | null;
  parts: CertRequestParts;
  proof: null;
}

export const CONTROLS: Readonly<Record<string, string>>;

export function prepare(parts: CertRequestParts): PreparedCertRequest;
/**
 * The CertReqMessages DER. With a signature: a signature proof. Without:
 * pass ra_verified, or no_proof to say a request with none is meant.
 */
export function assemble(req: PreparedCertRequest, signature?: BytesInput | null, options?: { ra_verified?: boolean; no_proof?: boolean }): Uint8Array;
