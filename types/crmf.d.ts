// CRMF certificate request messages (RFC 4211), read. Building is
// crmf_build; CMP carries them.

import type { BytesInput, Extension, Name, PublicKey, Time } from './types.js';

export interface CertTemplate {
  version: number | null;
  serial: Uint8Array | null;
  signing_algorithm: string | null;
  issuer: Name | null;
  subject: Name | null;
  validity: { not_before: Time | null; not_after: Time | null } | null;
  public_key: PublicKey | null;
  extensions: Extension[];
  /** The fields the requester filled in... */
  supplied: string[];
  /** ...and the ones it left to the CA. */
  left_to_ca: string[];
}

export type ProofOfPossession =
  | {
      form: 'signature';
      proves: string;
      algorithm: string;
      signature: Uint8Array;
      /** The POPOSigningKeyInput, when the signature covers that instead. */
      input: Uint8Array | null;
      note: string;
    }
  | { form: 'ra-verified'; proves: null; note: string }
  | { form: 'key-encipherment' | 'key-agreement'; proves: string; note: string; value: Uint8Array };

export interface CertReqMessage {
  /** certReqId. */
  id: number;
  template: CertTemplate;
  controls: Array<{ id: string; name: string | null; detail: string | null; value: Uint8Array }>;
  proof_of_possession: ProofOfPossession | null;
  /** How the POP was tagged, as found in the wild. */
  popo_encoding: 'wrapped' | 'collapsed' | null;
  reg_info: Array<{ id: string; name: string | null; value: Uint8Array }> | null;
  /** The CertRequest as encoded - what a signature POP covers. */
  request_bytes: Uint8Array;
}

/** By dotted OID: each RFC 4211 control's name and meaning. */
export const CONTROLS: Readonly<Record<string, { name: string; detail: string }>>;

export function from_der(input: BytesInput): { messages: CertReqMessage[]; der: Uint8Array };
/** A CertTemplate's fields as the field engine read them, turned into a CertTemplate - for CMP's rr. */
export function read_template(fields: Record<string, unknown>): CertTemplate;

/** What a proof of possession lets you check - and why, when it cannot. */
export function verification_plan(message: CertReqMessage):
  | {
      verifiable: true;
      algorithm: string;
      bytes: Uint8Array;
      covers: 'CertRequest' | 'POPOSigningKeyInput';
      signature: Uint8Array;
      key: PublicKey | null;
      note: string;
    }
  | { verifiable: false; reason: string };
