// Bech32 and Bech32m (BIP 173, BIP 350).

import type { BytesInput } from './types.js';

export type Variant = 'bech32' | 'bech32m';

export interface Options {
  /** Default 'bech32'. Decoding refuses the other variant's checksum. */
  variant?: Variant;
  /** The maximum length; default DEFAULT_LIMIT (90). null for none. */
  limit?: number | null;
}

export const CHARSET: string;
export const DEFAULT_LIMIT: number;

/** `data` is 5-bit words; see to_words. */
export function encode(hrp: string, data: readonly number[], options?: Options | null): string;
export function decode(text: string, options?: Options | null): { hrp: string; data: number[]; variant: Variant };

export function encode_bytes(hrp: string, data: BytesInput, options?: Options | null): string;
export function decode_bytes(text: string, options?: Options | null): { hrp: string; bytes: Uint8Array; variant: Variant };

/** 8-bit bytes -> 5-bit words. */
export function to_words(input: BytesInput): number[];
/** 5-bit words -> bytes; refuses non-zero padding. */
export function from_words(words: readonly number[]): Uint8Array;
