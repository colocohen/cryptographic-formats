// The PBES2 pieces PKCS#8, PKCS#12 and CMS share (RFC 8018): PBKDF2 and the
// CBC ciphers.

import type { AlgorithmIdentifier, DerNode } from './types.js';

export const CIPHERS: Readonly<Record<string, { key: number; iv: number }>>;
export const PRFS: Readonly<Record<string, { hash: string; size: number }>>;

export interface Pbkdf2Params {
  salt: Uint8Array;
  iterations: number;
  /** Absent from the parameters: the cipher decides. */
  key_length: number | null;
  /** By OID-table name. */
  prf: string;
  weak: boolean;
}

/** The PBES2 AlgorithmIdentifier: PBKDF2 and a cipher. */
export function scheme_to_der(parts: {
  cipher: string;
  iv: Uint8Array;
  salt: Uint8Array;
  iterations: number;
  prf?: string;
  key_length?: number | null;
}): DerNode;
export function pbkdf2_to_der(parts: { salt: Uint8Array; iterations: number; prf?: string }, key_length?: number): DerNode;
export function cipher_to_der(cipher: string, iv: Uint8Array): DerNode;

export function read_pbkdf2(alg: AlgorithmIdentifier, options?: { max_iterations?: number }): Pbkdf2Params;
export function read_cipher(alg: AlgorithmIdentifier): { cipher: string; key_length: number; iv: Uint8Array };

/** Fewer than 1,000 iterations, or the SHA-1 PRF. */
export function is_weak(p: { iterations: number; prf: string }): boolean;
