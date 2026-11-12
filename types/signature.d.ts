// Signature encodings: ECDSA and DSA between r||s (JOSE, COSE, WebAuthn,
// SSH) and SEQUENCE { r, s } (X.509, CMS and the rest). EdDSA and RSA need
// no conversion, and describe() says so.

import type { BytesInput } from './types.js';

/** The width of r and s: a curve name, or `size` in bytes (DSA: from q). */
export interface Width {
  curve?: string;
  size?: number;
}

export function describe(algorithm: string): { converts: boolean; raw: string; der: string; note: string };

export function der_to_raw(options: Width & { der: BytesInput }): Uint8Array;
export function raw_to_der(options: Width & { raw: BytesInput }): Uint8Array;
export function parse_der(options: { der: BytesInput }): { r: Uint8Array; s: Uint8Array };
export function from_pair(options: { r: BytesInput; s: BytesInput }): Uint8Array;

/** By family ('ecdsa', 'eddsa', 'rsa', 'dsa'): what describe() returns. */
export const ALGORITHMS: Readonly<Record<string, { converts: boolean; raw: string; der: string; note: string }>>;
