// WebAuthn: attestation objects, authenticator data, the bytes signatures
// cover, and registration options (W3C Web Authentication Level 3).

import type { BytesInput } from './types.js';
import type { CborValue } from './cbor_reader.js';
import type { CoseKey } from './cose.js';

export interface AuthenticatorData {
  rp_id_hash: Uint8Array;
  flags: number;
  user_present: boolean;
  user_verified: boolean;
  backup_eligible: boolean;
  backup_state: boolean;
  /** AT: attested credential data follows. */
  has_credential: boolean;
  /** ED: extensions follow. */
  has_extensions: boolean;
  sign_count: number;
  credential: {
    aaguid: Uint8Array;
    aaguid_hex: string;
    id: Uint8Array;
    id_hex: string;
    /** The credential public key, read from its COSE_Key. */
    key: CoseKey;
    /** The COSE_Key as it appeared. */
    key_bytes: Uint8Array;
  } | null;
  /** The extensions map's pairs. */
  extensions: Array<[CborValue, CborValue]> | null;
  raw: Uint8Array;
}

export interface AttestationObject {
  /** 'packed', 'tpm', 'android-key', 'android-safetynet', 'fido-u2f', 'apple', 'none'. */
  fmt: string;
  /** False for 'none'. */
  attested: boolean;
  /** The attStmt map by its text / number keys: alg, sig, x5c... */
  att_stmt: Record<string, CborValue>;
  auth_data: AuthenticatorData;
  auth_data_bytes: Uint8Array;
  der: Uint8Array;
}

/** The authenticator-data flag bits. */
export const FLAG: Readonly<{ UP: 1; UV: 4; BE: 8; BS: 16; AT: 64; ED: 128 }>;
/** The attestation formats this module knows. */
export const FORMATS: Readonly<Record<string, true>>;

export function from_cbor(input: BytesInput): AttestationObject;
export function auth_data_from_bytes(input: BytesInput): AuthenticatorData;

/**
 * What the attestation signature covers: authData || SHA-256(clientDataJSON),
 * the hash computed by the caller - and for fmt 'fido-u2f', the U2F layout
 * (W3C 8.6): 0x00 || rpIdHash || hash || credentialId || publicKeyU2F.
 */
export function signing_input(att: Pick<AttestationObject, 'auth_data_bytes' | 'auth_data' | 'fmt'>, client_data_hash: BytesInput): Uint8Array;
/** The fido-u2f layout alone. The credential must be a P-256 key. */
export function u2f_signing_input(auth: AuthenticatorData, client_data_hash: Uint8Array): Uint8Array;
/** The same concatenation for an assertion. */
export function assertion_signing_input(auth_data_bytes: BytesInput, client_data_hash: BytesInput): Uint8Array;

/** Signed by the credential key itself: proves possession, nothing about the authenticator. */
export function is_self_attested(att: AttestationObject): boolean;
/** The attestation certificates (x5c), as DER; empty when none. */
export function certificates(att: AttestationObject): Uint8Array[];
/** Whether rpIdHash equals SHA-256(rp id), computed by the caller. */
export function rp_id_matches(auth: Pick<AuthenticatorData, 'rp_id_hash'>, rp_id_hash: BytesInput): boolean;

/** pubKeyCredParams entries, in the server's order of preference. */
export function algorithm_params(names: string[]): Array<{ type: 'public-key'; alg: number }>;
/** The COSE algorithm's name, or null. */
export function algorithm_name(alg: number): string | null;
/** What is wrong with registration options before they are sent; empty when nothing. */
export function check_options(options: {
  challenge?: BytesInput | string;
  rp?: { id?: string; name?: string };
  user?: { id?: BytesInput | string; name?: string; displayName?: string };
  pubKeyCredParams?: Array<{ type?: string; alg: number }>;
  [other: string]: unknown;
}): Array<{ code: string; detail: string }>;
