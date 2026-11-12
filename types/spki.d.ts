// SubjectPublicKeyInfo (RFC 5280 4.1.2.7) - public keys of every algorithm
// this library reads.

import type { BytesInput, DerNode, PublicKey } from './types.js';

export type { PublicKey };

export const CURVES: readonly string[];

export function from_der(input: BytesInput): PublicKey;

/**
 * A key - as spki, pkcs8, jwk or ssh return it - to SPKI DER. `point` is
 * the subjectPublicKey: the EC point, RSAPublicKey DER, or raw OKP bytes;
 * an RSA key may give rsa { n, e } instead.
 */
export function to_der(key: {
  algorithm: string;
  curve?: string | null;
  point?: Uint8Array | null;
  rsa?: { n: BytesInput; e: BytesInput };
  parameters?: Uint8Array | null;
}): Uint8Array;

/**
 * The key's AlgorithmIdentifier alone - shared with pkcs8.to_der. Refusals
 * go through `fail_(code, detail)`.
 */
export function key_algorithm_to_der(
  key: { algorithm: string; curve?: string | null; parameters?: Uint8Array | null },
  fail_: (code: string, detail: string) => never
): DerNode;
