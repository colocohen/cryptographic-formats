// Building CRLs: prepare -> the caller signs -> assemble.

import type { BytesInput, NameInput, TimeInput } from './types.js';

export interface RevokedInput {
  serial: BytesInput;
  date: TimeInput;
  /** A REASONS key: 'keyCompromise'... */
  reason?: string;
  invalidity_date?: Date;
}

export interface CrlParts {
  issuer: NameInput;
  signature_algorithm: string;
  this_update: TimeInput;
  next_update?: TimeInput | null;
  crl_number?: number | Uint8Array | null;
  authority_key_id?: BytesInput | null;
  revoked?: RevokedInput[];
  /** Other CRL extensions by name or dotted OID, as encoded extnValue bytes. */
  extensions?: Record<string, Uint8Array> | null;
}

export interface PreparedCrl {
  /** The TBSCertList: sign exactly these bytes. */
  bytes: Uint8Array;
  signature_algorithm: string;
  parts: CrlParts;
}

/** reasonCode numbers by name. */
export const REASONS: Readonly<Record<string, number>>;

export function prepare(parts: CrlParts): PreparedCrl;
export function assemble(tbs: PreparedCrl, signature: BytesInput): Uint8Array;
/** RFC 5280 problems that are legal to write: no nextUpdate, no crlNumber... */
export function check(parts: Partial<CrlParts>): Array<{ code: string; detail: string }>;
