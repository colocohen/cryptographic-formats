// Building SCEP messages (RFC 8894): the CA's CertRep, a client's request,
// what the envelopes hold, and the GetCACaps text. Two steps, as cms_build:
// prepare -> sign `bytes` -> assemble.

import type { BytesInput, NameInput, Name } from './types.js';
import type { Certificate } from './x509.js';
import type { PreparedSigner, CertificateInput } from './cms_build.js';

interface CommonParts {
  /** The signer: the CA or RA for a CertRep; for a request, the client's. DER or read. */
  certificate: Certificate | Uint8Array;
  digest: string;
  signature_algorithm: string;
  /** For a CertRep, the request's. */
  transaction_id: string;
  /** 16 random bytes - the caller's. */
  sender_nonce: Uint8Array;
  /** Of `enveloped` - or of the empty string when there is none. */
  content_digest: Uint8Array;
  signing_time?: Date;
}

export function cert_rep_prepare(parts: CommonParts & {
  pki_status: 'SUCCESS' | 'FAILURE' | 'PENDING';
  /** The request's sender_nonce. */
  recipient_nonce: Uint8Array;
  /** FAILURE only, and required with it. */
  fail_info?: 'badAlg' | 'badMessageCheck' | 'badRequest' | 'badTime' | 'badCertId';
  fail_info_text?: string;
  /** SUCCESS only, and required with it: the pkcsPKIEnvelope's DER. */
  enveloped?: BytesInput;
}): PreparedSigner;

export function request_prepare(parts: CommonParts & {
  message_type: 'PKCSReq' | 'RenewalReq' | 'CertPoll' | 'GetCert' | 'GetCRL';
  enveloped: BytesInput;
}): PreparedSigner;

/** cms_build.assemble, for a cert_rep_prepare. */
export function cert_rep_assemble(si: PreparedSigner, signature: BytesInput, options?: { certificates?: CertificateInput[] }): Uint8Array;
/** cms_build.assemble, for a request_prepare. */
export function request_assemble(si: PreparedSigner, signature: BytesInput, options?: { certificates?: CertificateInput[] }): Uint8Array;
/** A SUCCESS's certificates - and a CA-plus-RA GetCACert answer: cms_build.bundle. */
export function cert_rep_content(certificates: CertificateInput[]): Uint8Array;
/** CertPoll's envelope content. */
export function issuer_and_subject(issuer: NameInput | Name, subject: NameInput | Name): Uint8Array;
/** GetCert's and GetCRL's. */
export function issuer_and_serial(issuer: NameInput | Name, serial: BytesInput): Uint8Array;
/** The GetCACaps answer; a keyword RFC 8894 does not name is refused. */
export function capabilities_text(list: string[]): string;

export const CAPABILITIES: readonly string[];
