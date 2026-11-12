// Building attribute certificates: prepare -> the caller signs -> assemble.

import type { BytesInput, GeneralNameInput, NameInput, TimeInput } from './types.js';
import type { Certificate } from './x509.js';

export type HolderInput =
  /** Bound to the holder's certificate: its issuer and serial. */
  | { certificate: Pick<Certificate, 'issuer' | 'serial'> }
  /** Bound to a name alone - weaker, so it must be acknowledged. */
  | { name: NameInput | GeneralNameInput[]; i_understand_entity_name: true }
  /** Bound to a digest of a key or certificate. */
  | { digest: { of: 'publicKey' | 'publicKeyCert' | 'other'; type_id?: string; algorithm: string; value: BytesInput } };

export interface AttributeCertificateParts {
  holder: HolderInput;
  /** The Attribute Authority: a Name, or GeneralNames. */
  issuer: NameInput | GeneralNameInput[];
  serial: BytesInput;
  validity: { not_before: TimeInput; not_after: TimeInput };
  signature_algorithm: string;
  /** type: an ATTRIBUTES name or dotted OID; values: each value's DER. */
  attributes: Array<{ type: string; values: Uint8Array | Uint8Array[] }>;
  /** By name or dotted OID, as encoded extnValue bytes. */
  extensions?: Record<string, Uint8Array> | null;
}

export interface PreparedAttributeCertificate {
  bytes: Uint8Array;
  signature_algorithm: string;
  parts: AttributeCertificateParts;
}

export const ATTRIBUTES: Readonly<Record<string, string>>;

export function prepare(parts: AttributeCertificateParts): PreparedAttributeCertificate;
export function assemble(tbs: PreparedAttributeCertificate, signature: BytesInput): Uint8Array;
export function check(parts: Partial<AttributeCertificateParts>): Array<{ code: string; detail: string }>;
