// PEM (RFC 7468), and the legacy RFC 1421 encrypted form - read, never
// written.

import type { BytesInput } from './types.js';

export interface PemBlock {
  label: string;
  der: Uint8Array;
  /** RFC 1421 headers ('Proc-Type', 'DEK-Info'), or null when there are none. */
  headers: Record<string, string> | null;
  /** For a legacy encrypted block: what DEK-Info says. Otherwise null. */
  encrypted: { legacy: true; algorithm: string; iv: Uint8Array } | null;
}

/** Every block, in order - from text, or the file's bytes. */
export function decode(text: string | Uint8Array): PemBlock[];
/** Exactly one block, optionally with this label; anything else is refused. */
export function decode_one(text: string | Uint8Array, expected_label?: string): PemBlock;
/** 64-character lines, as RFC 7468 2 requires. */
/** width: the base64 line length - 64 (RFC 7468) by default. */
export function encode(der: BytesInput, label: string, width?: number): string;
/** Always refuses: the RFC 1421 encrypted form is not written (DECISIONS). */
export function encode_legacy_encrypted(): never;

/**
 * The good blocks, and each bad one named - for a trust store that should
 * survive one corrupt entry. decode() refuses the whole file instead.
 */
export function decode_skipping(text: string | Uint8Array): {
  blocks: PemBlock[];
  skipped: Array<{ label: string; line: number; code: string; detail: string }>;
};

