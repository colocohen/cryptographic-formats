// Building CMP messages. The envelope - prepare (the ProtectedPart bytes)
// -> the caller MACs or signs -> assemble - and the bodies a server answers
// with: cert_rep, error, pkiconf, cert_conf.

import type { BytesInput, GeneralNameInput, NameInput } from './types.js';

export type CmpProtectionInput =
  | { kind: 'signature'; algorithm: string }
  | {
      kind: 'password-mac';
      /** At least 8 bytes. */
      salt: BytesInput;
      /** Default 100,000; under 1,000 is refused. */
      iterations?: number;
      /** Default 'sha256'. */
      owf?: string;
      /** Default 'hmacSHA'. */
      mac?: string;
    };

export interface CmpMessageParts {
  /** The BODY_TYPES name: 'ir', 'ip', 'certConf', 'error'... */
  body: string;
  /** The arm's content DER: crmf_build's output, cert_rep's... */
  content: BytesInput;
  /** A Name (directoryName), or any GeneralName. */
  sender: NameInput | GeneralNameInput;
  recipient: NameInput | GeneralNameInput;
  message_time?: Date | null;
  protection?: CmpProtectionInput | null;
  /** Text (openssl cmp -ref) as its UTF-8, or bytes. */
  sender_kid?: string | BytesInput | null;
  transaction_id?: BytesInput | null;
  sender_nonce?: BytesInput | null;
  /** In a response: the request's sender_nonce. */
  recip_nonce?: BytesInput | null;
  /** generalInfo: implicitConfirm echoed to grant it, confirmWaitTime, certProfile... */
  general_info?: InfoInput[] | null;
}

/**
 * { type, value }: implicitConfirm (no value), confirmWaitTime (a Date),
 * certProfile (strings), caCerts (certificates; none: absent),
 * rootCaCert (a certificate, or none: absent - the request), rootCaKeyUpdate
 * ({ new_with_new, new_with_old, old_with_new? }, or none: no update), or a
 * dotted OID with the value's DER.
 */
export interface InfoInput {
  type: string;
  value?: unknown;
}

type CertInput = BytesInput | { der: Uint8Array };

export interface PreparedMessage {
  /** ProtectedPart: what the protection covers. */
  bytes: Uint8Array;
  header: Uint8Array;
  body: Uint8Array;
  parts: CmpMessageParts;
}

export interface StatusInput {
  /** A STATUS name. */
  status?: string;
  text?: string;
  /** FAILURE_BITS names. */
  failure?: string[];
}

export const STATUS: Readonly<Record<string, number>>;
export const FAILURE_BITS: Readonly<Record<string, number>>;

export function prepare(parts: CmpMessageParts): PreparedMessage;
/** The PKIMessage. No protection must be asked for with unprotected: true. */
/** extra_certs: DER or read Certificates, written in the order given. */
export function assemble(msg: PreparedMessage, protection: Uint8Array | null, options?: { extra_certs?: Array<BytesInput | { der: Uint8Array }>; unprotected?: boolean }): Uint8Array;

/** ip, cp, kup, ccp content: a certificate with accepted, none otherwise. */
export function cert_rep(parts: {
  responses: Array<StatusInput & { cert_req_id?: number; certificate?: BytesInput | null; rsp_info?: BytesInput | null }>;
  ca_pubs?: BytesInput[];
}): Uint8Array;
/** error content: status defaults to rejection; accepted is refused. */
export function error(parts?: StatusInput & { error_code?: number | null; error_details?: string[] | null }): Uint8Array;
/** pkiconf content: NULL. */
export function pkiconf(): Uint8Array;
/** certConf content: each certificate's hash (with its own signature's hash), and a status to refuse one. */
export function cert_conf(list: Array<StatusInput & { cert_hash: BytesInput; cert_req_id?: number }>): Uint8Array;

/** rp content: a status per revocation (default accepted), and optionally the certificates revoked and CRLs. */
export function rev_rep(parts: {
  responses: StatusInput[];
  rev_certs?: Array<{ issuer: NameInput | GeneralNameInput; serial: BytesInput }>;
  crls?: CertInput[];
}): Uint8Array;
/** pollRep content: check_after in seconds; cert_req_id -1 for an rr or genm. */
export function poll_rep(list: Array<{ cert_req_id?: number; check_after: number; reason?: string | string[] }>): Uint8Array;
/** pollReq content - the client's. */
export function poll_req(ids: number[]): Uint8Array;
export function genm(infos: InfoInput[]): Uint8Array;
export function genp(infos: InfoInput[]): Uint8Array;
/** genp answering caCerts: the certificates, or none (the value absent). */
export function genp_ca_certs(certs: CertInput[]): Uint8Array;
/** genp answering rootCaCert (RFC 9483 4.3.2): the new root and its links to the old - or, with nothing, "no update". */
export function genp_root_ca_key_update(parts?: { new_with_new: CertInput; new_with_old: CertInput; old_with_new?: CertInput | null } | null): Uint8Array;

