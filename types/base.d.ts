// The text encodings of bytes: RFC 4648 (base16, base32, base32hex, base64,
// base64url) strictly, and base58 / base58check.

import type { BytesInput } from './types.js';

export type Alphabet = 'base16' | 'base32' | 'base32hex' | 'base64' | 'base64url';

export const ALPHABETS: Readonly<Record<Alphabet, unknown>>;

export function encode(name: Alphabet, input: BytesInput): string;
/** Strict: padding, alphabet and trailing bits are all checked. */
export function decode(name: Alphabet, text: string): Uint8Array;

export function to_hex(b: BytesInput): string;
export function from_hex(s: string): Uint8Array;
export function to_base32(b: BytesInput): string;
export function from_base32(s: string): Uint8Array;
export function to_base64(b: BytesInput): string;
export function from_base64(s: string): Uint8Array;
export function to_base64url(b: BytesInput): string;
export function from_base64url(s: string): Uint8Array;

export function base58_encode(input: BytesInput): string;
export function base58_decode(text: string): Uint8Array;

/** A SHA-256 the caller supplies - this library performs no cryptography. */
export type Sha256 = (data: Uint8Array) => Uint8Array | ArrayLike<number>;

export function base58check_encode(payload: BytesInput, sha256: Sha256): string;
/** The payload, after the four-byte checksum is checked. */
export function base58check_decode(text: string, sha256: Sha256): Uint8Array;
