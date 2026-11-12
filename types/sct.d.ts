// Signed Certificate Timestamps (RFC 6962): the TLS-encoded list in the
// certificate extension, the TLS extension and OCSP.

import type { BytesInput } from './types.js';

export interface Sct {
  version: 1;
  log_id: Uint8Array;
  log_id_hex: string;
  /** Milliseconds since the epoch. */
  timestamp: number;
  date: Date;
  extensions: Uint8Array | null;
  /** 'sha256', or the number when unknown. */
  hash_algorithm: string | number;
  /** 'ecdsa', 'rsa', or the number when unknown. */
  signature_algorithm: string | number;
  /** The combined name: 'ecdsaWithSHA256'... */
  algorithm: string;
  signature: Uint8Array;
}

/** What to_tls takes: an Sct, or these fields by hand. */
export interface SctInput {
  log_id: BytesInput;
  timestamp: number;
  /** 'ecdsaWithSHA256' - or hash_algorithm and signature_algorithm. */
  algorithm?: string;
  hash_algorithm?: string | number;
  signature_algorithm?: string | number;
  signature: BytesInput;
  extensions?: BytesInput | null;
}

export const HASH_ALGORITHMS: Readonly<Record<number, string>>;
export const SIGNATURE_ALGORITHMS: Readonly<Record<number, string>>;

/** The extnValue content of the SCT list extension (an OCTET STRING inside). */
export function from_extension(input: BytesInput): Sct[];
export function to_extension(list: SctInput[]): Uint8Array;
/** The bare SignedCertificateTimestampList (TLS extension, OCSP). */
export function from_tls(input: BytesInput): Sct[];
export function to_tls(list: SctInput[]): Uint8Array;

/**
 * Why `bytes` is null: the signed structure is the precertificate - this
 * certificate re-encoded without the SCT extension - which this library
 * does not build. `needs` and `also` say what does.
 */
export function verification_plan(sct: Sct): {
  algorithm: string;
  signature: Uint8Array;
  log_id: Uint8Array;
  bytes: null;
  needs: string;
  also: string;
};

export function present_in(cert: { extensions: Array<{ name: string | null }> }): boolean;
export function in_certificate(cert: { extensions: Array<{ name: string | null; parsed: unknown }> }): Sct[];
