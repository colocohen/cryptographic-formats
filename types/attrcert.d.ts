// Attribute certificates (RFC 5755), read. Building is attrcert_build.

import type { AlgorithmDescription, BytesInput, ExtensionEntry, GeneralName, Time, VerificationPlanBase } from './types.js';
import type { Certificate } from './x509.js';

export interface Holder {
  base_certificate: { issuer: GeneralName[]; serial: Uint8Array; serial_hex: string } | null;
  entity_names: GeneralName[] | null;
  object_digest: Record<string, unknown> | null;
  /** How the holder is named: 'base-certificate-id', 'entity-name', 'object-digest'. */
  binding: string | null;
}

export interface AttributeCertificate {
  version: number;
  holder: Holder;
  holder_binding: string | null;
  issuer: { form: 'v1' | 'v2'; names: GeneralName[] | null; base_certificate: unknown };
  serial: Uint8Array;
  serial_hex: string;
  validity: { not_before: Time; not_after: Time };
  attributes: Array<{
    id: string;
    name: string | null;
    /** RFC 5755's grouping: 'role', 'identity', 'service', 'clearance'; null when unknown. */
    kind: string | null;
    /** The values, whole - what they hold depends on the type. */
    values: Uint8Array;
  }>;
  extensions: ExtensionEntry[];
  signature_alg_bytes: Uint8Array;
  tbs_bytes: Uint8Array;
  signature_algorithm: string;
  signature_params: AlgorithmDescription;
  signature: Uint8Array;
  der: Uint8Array;
}

/** By dotted OID: the name and kind of each attribute RFC 5755 defines. */
export const KNOWN_ATTRIBUTES: Readonly<Record<string, { name: string; kind: string }>>;

export function from_der(input: BytesInput): AttributeCertificate;

/**
 * Whether `cert` is the holder, how it is named, and how strongly that binds.
 * An object-digest holder cannot be checked here: `holder` is false.
 */
export function holder_is(ac: AttributeCertificate, cert: Pick<Certificate, 'serial' | 'issuer' | 'subject'>): {
  holder: boolean;
  by: 'base-certificate-id' | 'entity-name' | 'object-digest';
  strength: string;
};

/**
 * The signature check - and `also`, the step that is not one: confirm the
 * holder (holder_is) against the identity you authenticated.
 */
export function verification_plan(ac: AttributeCertificate): VerificationPlanBase & { also: string };

/** notBefore <= when <= notAfter. Default now. */
export function validity_contains(ac: { validity: { not_before: Time; not_after: Time } }, when?: Date): boolean;
