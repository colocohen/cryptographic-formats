// COSE (RFC 9052 / 9053): Sign1, Sign, Mac0, Mac, Encrypt0 and Encrypt
// with nested recipients, and COSE_Key. Header maps are lists of
// [label, value] pairs - CBOR keys need not be strings.

import type { BytesInput } from './types.js';
import type { CborValue } from './cbor_reader.js';
import type { CborInput } from './cbor_writer.js';

/** A header map: [label, value] pairs. Labels are numbers (HEADER_LABEL) or text. */
export type HeaderPairs = Array<[CborValue, CborValue]>;
/** A header map to write. */
export type HeaderInput = Array<[CborInput, CborInput]>;

/** An algorithm: the registry's name ('ES256'), or the number when unknown. */
export type CoseAlg = string | number | null;

interface Head {
  tagged: boolean;
  /** As received: what every structure covers. */
  protected_bytes: Uint8Array;
  protected: HeaderPairs;
  unprotected: HeaderPairs;
}

export interface Sign1 extends Head {
  /** Null when detached. */
  payload: Uint8Array | null;
  signature: Uint8Array;
  alg: CoseAlg;
}

export interface Sign extends Head {
  payload: Uint8Array | null;
  signatures: Array<{ protected_bytes: Uint8Array; protected: HeaderPairs; unprotected: HeaderPairs; signature: Uint8Array; alg: CoseAlg }>;
}

export interface Mac0 extends Head {
  payload: Uint8Array | null;
  tag: Uint8Array;
  alg: CoseAlg;
  hash: string | null;
  key_length: number | null;
  tag_length: number | null;
}

export interface Recipient {
  protected_bytes: Uint8Array;
  protected: HeaderPairs;
  unprotected: HeaderPairs;
  ciphertext: Uint8Array | null;
  alg: CoseAlg;
  /** 'direct', 'key-wrap', 'key-agreement'...; null when unknown. */
  kind: string | null;
  kid: CborValue | null;
  recipients: Recipient[] | null;
}

export interface Mac extends Mac0 {
  recipients: Recipient[];
}

export interface Encrypt0 extends Head {
  ciphertext: Uint8Array | null;
  iv: Uint8Array | null;
  partial_iv: Uint8Array | null;
  alg: CoseAlg;
  key_length: number | null;
  tag_length: number | null;
}

export interface Encrypt extends Encrypt0 {
  recipients: Recipient[];
}

/** A COSE_Key as the shared key shape: { algorithm, curve, point, scalar }. */
export interface CoseKey {
  algorithm: string;
  curve: string | null;
  cose_curve: number;
  point: Uint8Array;
  scalar: Uint8Array | null;
  kid: CborValue | null;
  alg: CoseAlg;
  private: boolean;
}

/** What the writers' first step takes. */
export interface HeadInput {
  /** Pairs to encode - or protected_bytes, as received. */
  protected?: HeaderInput;
  protected_bytes?: BytesInput;
  unprotected?: HeaderInput;
  external_aad?: BytesInput;
  /** Default true. */
  tagged?: boolean;
}

export interface PayloadInput extends HeadInput {
  payload: BytesInput;
  /** Leave the payload out of the message; it is still covered. */
  detached?: boolean;
}

export interface RecipientInput {
  protected?: HeaderInput;
  protected_bytes?: BytesInput;
  unprotected?: HeaderInput;
  ciphertext?: BytesInput | null;
  recipients?: RecipientInput[] | null;
}

export interface PreparedHead {
  protected_bytes: Uint8Array;
  unprotected: HeaderInput;
  alg: CoseAlg;
  alg_id: number | string | null;
  external_aad: Uint8Array;
  tagged: boolean;
  payload?: Uint8Array;
  detached?: boolean;
  recipients?: RecipientInput[];
}

/** What each prepare returns: `bytes` is what to sign, MAC or use as AAD. */
export interface Prepared extends PreparedHead {
  bytes: Uint8Array;
}

/** COSE_Sign: each signer has its own `bytes`. */
export interface PreparedSign extends PreparedHead {
  signers: Prepared[];
}

export const HEADER_LABEL: Readonly<Record<string, number>>;
export const KEY_LABEL: Readonly<Record<string, number>>;
export const KTY: Readonly<Record<string, number>>;
export const CRV: Readonly<Record<number, { name: string; oid: string; kty: number; size: number }>>;
export const ALG: Readonly<Record<number, { name: string; kind: string; [k: string]: unknown }>>;
export const TAG_SIGN1: 18;
export const TAG_SIGN: 98;
export const TAG_MAC0: 17;
export const TAG_MAC: 97;
export const TAG_ENCRYPT0: 16;
export const TAG_ENCRYPT: 96;

/** `understood`: crit labels the caller implements. */
export type DecodeOptions = { understood?: Array<string | number> };

export function sign1_decode(input: BytesInput, options?: DecodeOptions): Sign1;
/** Sig_structure "Signature1": what the signature covers. A detached payload goes here. */
export function sign1_signing_input(message: Pick<Sign1, 'protected_bytes' | 'payload'>, payload?: BytesInput | null, external_aad?: BytesInput): Uint8Array;
export function sign1_prepare(parts: PayloadInput): Prepared;
export function sign1_assemble(p: Prepared, signature: BytesInput): Uint8Array;

export function sign_decode(input: BytesInput, options?: DecodeOptions): Sign;
/** For signer i. */
export function sign_signing_input(message: Sign, i: number, payload?: BytesInput | null, external_aad?: BytesInput): Uint8Array;
export function sign_prepare(parts: PayloadInput & { signers: HeadInput[] }): PreparedSign;
/** One signature per signer, in order. */
export function sign_assemble(p: PreparedSign, signatures: BytesInput[]): Uint8Array;

export function mac0_decode(input: BytesInput, options?: DecodeOptions): Mac0;
/** MAC_structure "MAC0". */
export function mac0_input(message: Pick<Mac0, 'protected_bytes' | 'payload'>, payload?: BytesInput | null, external_aad?: BytesInput): Uint8Array;
export function mac0_prepare(parts: PayloadInput): Prepared;
/** The tag, truncated to the algorithm's length. */
export function mac0_assemble(p: Prepared, tag: Uint8Array): Uint8Array;

export function mac_decode(input: BytesInput, options?: DecodeOptions): Mac;
export function mac_input(message: Pick<Mac, 'protected_bytes' | 'payload'>, payload?: BytesInput | null, external_aad?: BytesInput): Uint8Array;
export function mac_prepare(parts: PayloadInput & { recipients: RecipientInput[] }): Prepared;
export function mac_assemble(p: Prepared, tag: Uint8Array): Uint8Array;

export function encrypt0_decode(input: BytesInput, options?: DecodeOptions): Encrypt0;
/** Enc_structure "Encrypt0": the AAD. */
export function encrypt0_aad(message: Pick<Encrypt0, 'protected_bytes'>, external_aad?: BytesInput): Uint8Array;
export function encrypt0_prepare(parts: HeadInput): Prepared;
/** The ciphertext with its tag; null for detached. */
export function encrypt0_assemble(p: Prepared, ciphertext: BytesInput | null): Uint8Array;

export function encrypt_decode(input: BytesInput, options?: DecodeOptions): Encrypt;
export function encrypt_aad(message: Pick<Encrypt, 'protected_bytes'>, external_aad?: BytesInput): Uint8Array;
export function encrypt_prepare(parts: HeadInput & { recipients: RecipientInput[] }): Prepared;
export function encrypt_assemble(p: Prepared, ciphertext: BytesInput | null): Uint8Array;

/** Enc_structure for a recipient's own encryption ('Enc_Recipient', 'Mac_Recipient'...). */
export function recipient_aad(recipient: Pick<Recipient, 'protected_bytes'>, context: string, external_aad?: BytesInput): Uint8Array;

/** A COSE_Key - CBOR bytes, or the map's pairs. */
export function key_from_cbor(input: BytesInput | Array<[CborValue, CborValue]>): CoseKey;
export function key_to_cbor(key: { algorithm: string; curve?: string | null; point: Uint8Array; scalar?: Uint8Array | null; kid?: BytesInput | string | null }): Uint8Array;

/** The protected header's bytes for these pairs - empty for none, as RFC 9052 requires. */
export function protected_header(pairs: HeaderInput): Uint8Array;
