// Domain parameters: DH ('DH PARAMETERS', PKCS#3) and EC ('EC PARAMETERS').

import type { BytesInput } from './types.js';

export interface DhParams {
  prime: Uint8Array;
  base: Uint8Array;
  bits: number;
  /** The generator as a number, when it fits. */
  base_value: number | null;
  private_length: number | null;
  /** Under 2048 bits. */
  weak: boolean;
  note: string;
  /** What was NOT checked: primality is cryptography. */
  unchecked: string;
  der: Uint8Array;
}

export function dh_from_der(input: BytesInput): DhParams;
export function dh_from_pem(text: string): DhParams;
/** Refuses a group under 2048 bits unless allow_weak. */
export function dh_to_der(parts: { prime: BytesInput; base: BytesInput; private_length?: number; allow_weak?: boolean }): Uint8Array;

/** A named curve only - explicit curve equations are refused. */
export function ec_from_der(input: BytesInput): { curve: string; oid: Uint8Array; der: Uint8Array };
export function ec_from_pem(text: string): { curve: string; oid: Uint8Array; der: Uint8Array };
export function ec_to_der(curve: string): Uint8Array;
export function ec_to_pem(curve: string): string;

/** The bit length of a big-endian magnitude. */
export function bit_length(bytes: Uint8Array): number;
