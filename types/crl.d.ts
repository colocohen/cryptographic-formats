// Certificate revocation lists (RFC 5280 5), read. Building is crl_build.

import type { AlgorithmDescription, BytesInput, ExtensionEntry, Name, Time } from './types.js';

export interface RevokedEntry {
  serial: Uint8Array;
  /** Lower-case hex of the serial - what find() compares. */
  serial_hex: string;
  date: Time;
  /** The reasonCode by name, or null when absent. */
  reason: string | null;
}

export interface CertificateList {
  /** 1 or 2. */
  version: number;
  issuer: Name;
  this_update: Time;
  next_update: Time | null;
  revoked: RevokedEntry[];
  extensions: ExtensionEntry[];
  signature: Uint8Array;
  signature_algorithm: string;
  signature_params: AlgorithmDescription;
  tbs_bytes: Uint8Array;
  der: Uint8Array;
}

/** reasonCode values by number; index 7 is unassigned (null). */
export const REASONS: ReadonlyArray<string | null>;

export function from_der(input: BytesInput): CertificateList;

/**
 * The entry for a serial (bytes, or hex text), or null. Null means "not in
 * THIS list" - whether the list is current is is_current's question.
 */
export function find(crl: { revoked: RevokedEntry[] }, serial: Uint8Array | string): RevokedEntry | null;

/** thisUpdate <= when <= nextUpdate; false when there is no nextUpdate. */
export function is_current(crl: { this_update: Time; next_update: Time | null }, when?: Date): boolean;
