// SCEP (RFC 8894): a pkiMessage read - its attributes checked against the
// message type, its envelope handed back - and what the decrypted envelope
// holds. Building is scep_build.

import type { BytesInput, Name } from './types.js';
import type { SignedData, SignerInfo } from './cms.js';
import type { CertificationRequest } from './csr.js';

export type ScepMessageType = 'PKCSReq' | 'RenewalReq' | 'CertPoll' | 'GetCert' | 'GetCRL' | 'CertRep';

export interface ScepMessage {
  /** The outer SignedData, as cms.from_der read it. */
  signed: SignedData;
  /** Its one signer. */
  signer: SignerInfo;
  /** null for a number RFC 8894 does not define (then warned). */
  message_type: ScepMessageType | null;
  message_type_code: number;
  transaction_id: string;
  sender_nonce: Uint8Array;
  recipient_nonce: Uint8Array | null;
  /** CertRep only. */
  pki_status: 'SUCCESS' | 'FAILURE' | 'PENDING' | null;
  fail_info: 'badAlg' | 'badMessageCheck' | 'badRequest' | 'badTime' | 'badCertId' | null;
  /** As written, also when fail_info does not name it. */
  fail_info_code: string | null;
  fail_info_text: string | null;
  /** The pkcsPKIEnvelope - EnvelopedData ContentInfo DER, for cms_enveloped.from_der - or null where SCEP omits it. */
  enveloped: Uint8Array | null;
  /** 'unknown-message-type', 'nonce-length', 'unknown-fail-info'. */
  warnings: Array<{ code: string; detail: string }>;
  note: string;
}

export type ScepInner =
  | { kind: 'csr'; csr: CertificationRequest }
  | { kind: 'issuer-and-subject'; issuer: Name; subject: Name }
  | { kind: 'issuer-and-serial'; issuer: Name; serial: Uint8Array; serial_hex: string }
  | { kind: 'certificates'; certificates: Uint8Array[]; crls: Uint8Array[] };

export function from_der(input: BytesInput): ScepMessage;
/** The decrypted envelope, by message type (name or number). */
export function inner(message_type: ScepMessageType | number, bytes: BytesInput): ScepInner;
/** A GetCACaps answer: the keywords RFC 8894 names, and the rest. */
export function capabilities_from_text(text: string): { known: string[]; unknown: string[] };

export const CAPABILITIES: readonly string[];
export const MESSAGE_TYPES: Readonly<Record<number, ScepMessageType>>;
export const PKI_STATUS: Readonly<Record<number, string>>;
export const FAIL_INFO: Readonly<Record<number, string>>;
