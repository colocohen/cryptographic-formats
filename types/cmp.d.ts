// CMP messages (RFC 4210 / RFC 9480): requests, responses, errors and
// confirmations - their protection, and the bytes it covers. Building is
// cmp_build.

import type { BytesInput, GeneralName, Time, Name, Extension } from './types.js';
import type { Certificate } from './x509.js';
import type { CertReqMessage, CertTemplate as CertTemplateRead } from './crmf.js';

export interface PkiStatusInfo {
  value: number;
  /** STATUS name, e.g. 'accepted', 'rejection'; null for a value it lacks. */
  name: string | null;
  text: string[] | null;
  /** FAILURE_BITS names set in failInfo. */
  failures: string[];
}

export interface CertResponse {
  cert_req_id: number;
  status: PkiStatusInfo;
  certificate: Uint8Array | null;
  encrypted_certificate: Uint8Array | null;
  private_key: Uint8Array | null;
  rsp_info: Uint8Array | null;
}

/** The PKIBody: `name` says which arm; the fields for it are filled. */
export interface PkiBody {
  /** The context tag: 0 ir, 1 ip, ... 23 error, 24 certConf. */
  tag: number;
  name: string;
  detail: string;
  /** ir, cr, kur, ccr: the CRMF messages. */
  requests: { messages: CertReqMessage[]; der: Uint8Array } | null;
  /** error: the PKIStatusInfo. */
  status: PkiStatusInfo | null;
  /** ip, cp, kup, ccp: the responses' certificates, those that carry one. */
  certificates: Uint8Array[] | null;
  /** p10cr: the PKCS#10 request DER. */
  csr_der?: Uint8Array;
  /** ip, cp, kup, ccp. */
  ca_pubs?: Uint8Array[] | null;
  responses?: CertResponse[];
  /** certConf. */
  confirmations?: Array<{ cert_hash: Uint8Array; cert_req_id: number; status: PkiStatusInfo | null }>;
  /** error. */
  error_code?: number | null;
  error_details?: string[] | null;
  /** rr: each certificate to revoke - named by issuer and serial - and why. */
  revocations?: Array<{
    template: CertTemplateRead;
    issuer: Name | null;
    serial: Uint8Array | null;
    serial_hex: string | null;
    /** crlReason by name: 'keyCompromise'... */
    reason: string | null;
    invalidity_date: Time | null;
    extensions: Extension[];
  }>;
  /** rp: a status per revocation, the certificates revoked, any CRLs (DER). */
  revocation_statuses?: PkiStatusInfo[];
  rev_certs?: Array<{ issuer: GeneralName; serial: Uint8Array; serial_hex: string }> | null;
  crls?: Uint8Array[] | null;
  /** genm, genp. */
  infos?: InfoTypeAndValue[];
  /** pollReq: -1 polls an rr or genm (RFC 9483 4.4). */
  poll_requests?: Array<{ cert_req_id: number }>;
  /** pollRep: check_after in seconds. */
  poll_responses?: Array<{ cert_req_id: number; check_after: number; reason: string[] | null }>;
  /** Every other arm: its content, whole. */
  raw?: Uint8Array;
}

/**
 * An InfoTypeAndValue: name without the table's it_ prefix, or null; value
 * the infoValue's DER or null. `parsed` for confirmWaitTime (a Time),
 * certProfile (strings), caCerts (DER each), rootCaCert (DER), rootCaKeyUpdate.
 */
export interface InfoTypeAndValue {
  id: string;
  name: string | null;
  value: Uint8Array | null;
  parsed?: unknown;
}

export type ProtectionAlgorithm =
  | { kind: 'signature'; algorithm: string; note: string }
  | {
      kind: 'password-mac';
      algorithm: string;
      salt: Uint8Array;
      iterations: number;
      /** The one-way function: 'sha256'... */
      owf: string;
      mac: string;
      /** How the key is derived: NOT PBKDF2 - secret || salt, iterated. */
      note: string;
    }
  | { kind: 'password-mac'; algorithm: string; parameters: null };

export interface PkiMessage {
  version: number;
  sender: GeneralName;
  recipient: GeneralName;
  message_time: Time | null;
  transaction_id: Uint8Array | null;
  sender_nonce: Uint8Array | null;
  recip_nonce: Uint8Array | null;
  sender_kid: Uint8Array | null;
  /** The header's generalInfo, or null. */
  general_info: InfoTypeAndValue[] | null;
  /** The client asks for implicit confirmation; granting it is the server's (it echoes it). */
  implicit_confirm: boolean;
  confirm_wait_time: Time | null;
  /** RFC 9480's certProfile. */
  cert_profile: string[] | null;
  body: PkiBody;
  protection: Uint8Array | null;
  protection_algorithm: ProtectionAlgorithm | null;
  /**
   * The certificates, read - each a Certificate with its `der`. It was
   * declared as DER and returned read; the return was kept, as the more useful
   * form, and the declaration corrected.
   */
  extra_certs: Certificate[] | null;
  header_bytes: Uint8Array;
  body_bytes: Uint8Array;
  /** What is legal but wrong: 'unprotected', 'weak-iteration-count'... */
  problems: Array<{ code: string; detail: string }>;
  der: Uint8Array;
}

/** By arm number: the body's name and meaning. */
export const BODY_TYPES: Readonly<Record<number, { name: string; detail: string }>>;
export const STATUS: Readonly<Record<number, string>>;
export const FAILURE_BITS: readonly string[];

export function from_der(input: BytesInput): PkiMessage;

/** ProtectedPart: SEQUENCE { header, body } - assembled, since it is not in the file. */
export function protected_bytes(message: Pick<PkiMessage, 'header_bytes' | 'body_bytes'>): Uint8Array;

export function verification_plan(message: PkiMessage):
  | {
      verifiable: true;
      kind: 'signature';
      bytes: Uint8Array;
      signature: Uint8Array;
      covers: string;
      algorithm: string;
      key_from: string;
    }
  | {
      verifiable: true;
      kind: 'password-mac';
      bytes: Uint8Array;
      signature: Uint8Array;
      covers: string;
      algorithm: string;
      owf: string;
      salt: Uint8Array;
      iterations: number;
      derivation: string;
    }
  | { verifiable: false; reason: string };

/** Whether a response answers a request: recipNonce and transactionID. */
export function answers(
  response: Pick<PkiMessage, 'recip_nonce' | 'transaction_id'>,
  request: Pick<PkiMessage, 'sender_nonce' | 'transaction_id'>
): {
  matches: boolean;
  nonce_matches?: boolean;
  transaction_matches?: boolean;
  reason: string | null;
};
