// AlgorithmIdentifier, including the two whose parameters are the algorithm
// (RSASSA-PSS, RSAES-OAEP), and the two spellings of algorithm names.

import type { AlgorithmIdentifier, AlgorithmDescription, DerNode, PssLimits, BytesInput } from './types.js';

export type { AlgorithmDescription };

/** What an AlgorithmIdentifier says: scheme, hash, PSS/OAEP parameters, weak. */
export function describe(alg: AlgorithmIdentifier): AlgorithmDescription;

/**
 * An AlgorithmIdentifier: a name ('ecdsaWithSHA256'; NULL parameters are
 * added for RSA), or PSS / OAEP with their parameters.
 */
export function to_der(spec: string | {
  /** 'rsassaPss' or 'rsaOAEP' take the rest; any other name is to_der(name). */
  name: string;
  /** Default sha1, as RFC 4055 defaults. */
  hash?: string;
  mgf_hash?: string;
  /** PSS: default the hash's size. */
  salt_length?: number;
  /** OAEP: the pSourceFunc label. */
  label?: Uint8Array;
}): DerNode;

/** RSASSA-PSS-params, with RFC 4055's defaults - as an RSA-PSS key's parameters are read. */
export function read_pss_params(params: BytesInput): PssLimits;

/** 'aes-256-cbc' -> 'aes256CBC', 'hmac-sha256' -> 'hmacWithSHA256'. */
export function canonical_name(name: string): string;

/** The node:crypto / OpenSSL spelling. RC2 needs the key length. */
export function node_name(name: string, key_length?: number): string;

/** The hash a PKCS#1 / ECDSA / DSA signature algorithm name implies. */
export function implied_hash(name: string): string | null;

/** describe(), refusing a signature whose length the algorithm fixes otherwise. */
export function describe_signature(
  alg: AlgorithmIdentifier,
  signature: Uint8Array,
  fail: (code: string, detail: string) => never
): AlgorithmDescription;

/** The fixed signature length of an ML-DSA / SLH-DSA name; undefined for others. */
export function signature_length(name: string): number | undefined;

/** Calls fail('bad-signature-length', ...) when `signature_length` is set and differs. */
export function check_signature_length(
  params: { name: string; signature_length?: number } | null | undefined,
  signature: Uint8Array,
  fail: (code: string, detail: string) => never
): void;

/** MD2, MD4, MD5 or SHA-1, by OID-table name - the rule `weak` applies. */
export function is_weak_hash(name: string | null | undefined): boolean;
