// Device attestation extensions - Apple's nonce and Managed Device
// Attestation values, Android's KeyDescription - as x509.js reads them.

export interface Level { code: number; name: string | null }

export interface RootOfTrust {
  verified_boot_key: Uint8Array;
  device_locked: boolean;
  verified_boot_state: Level;
  /** From attestation version 3; null before. */
  verified_boot_hash: Uint8Array | null;
}

export interface AttestationApplicationId {
  /** The OCTET STRING's content, as written. */
  der: Uint8Array;
  /** null when der does not read (then a warning says why). */
  packages: Array<{ name: string; version: number }> | null;
  signature_digests: Uint8Array[] | null;
}

/** KeyMint 4's tags, by name; any other tag under `unknown`, its content's DER. */
export interface AuthorizationList {
  unknown: Array<{ tag: number; value: Uint8Array }>;
  purpose?: number[]; algorithm?: number; key_size?: number; block_mode?: number[];
  digest?: number[]; padding?: number[]; caller_nonce?: true; min_mac_length?: number;
  ec_curve?: number; rsa_public_exponent?: number; mgf_digest?: number[];
  rollback_resistance?: true; early_boot_only?: true;
  /** Milliseconds since the epoch, as the date-time tags are. */
  active_date_time?: number; origination_expire_date_time?: number;
  usage_expire_date_time?: number; usage_count_limit?: number; user_secure_id?: number;
  no_auth_required?: true; user_auth_type?: number; auth_timeout?: number;
  allow_while_on_body?: true; trusted_user_presence_required?: true;
  trusted_confirmation_required?: true; unlocked_device_required?: true;
  creation_date_time?: number; origin?: number; root_of_trust?: RootOfTrust;
  os_version?: number; os_patch_level?: number;
  attestation_application_id?: AttestationApplicationId;
  attestation_id_brand?: Uint8Array; attestation_id_device?: Uint8Array;
  attestation_id_product?: Uint8Array; attestation_id_serial?: Uint8Array;
  attestation_id_imei?: Uint8Array; attestation_id_meid?: Uint8Array;
  attestation_id_manufacturer?: Uint8Array; attestation_id_model?: Uint8Array;
  vendor_patch_level?: number; boot_patch_level?: number; device_unique_attestation?: true;
  attestation_id_second_imei?: Uint8Array; module_hash?: Uint8Array;
}

export interface KeyDescription {
  attestation_version: number;
  attestation_security_level: Level;
  keymint_version: number;
  keymint_security_level: Level;
  attestation_challenge: Uint8Array;
  unique_id: Uint8Array;
  software_enforced: AuthorizationList;
  hardware_enforced: AuthorizationList;
}

export function apple_nonce(value: Uint8Array): { nonce: Uint8Array };
export function apple_text(value: Uint8Array): string;
export function apple_bytes(value: Uint8Array): Uint8Array;
export function key_description(value: Uint8Array, warn: (code: string, detail: string) => void): KeyDescription;
export const SECURITY_LEVELS: readonly string[];
export const BOOT_STATES: readonly string[];
