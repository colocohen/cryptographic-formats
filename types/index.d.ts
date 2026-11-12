// cryptographic-formats - container and encoding formats around cryptography.
// Each module's declarations are beside this file, in types/; this re-exports them as
// index.js does.

import type { BytesInput } from './types.js';

export type * from './types.js';

// level 0: the encodings
export * as der from './der_reader.js';
export * as der_writer from './der_writer.js';
export * as ber from './ber_reader.js';
export * as fields from './fields.js';
export * as tags from './tags.js';
export * as oid from './oid.js';
export * as real from './real.js';
export * as xml from './xml_reader.js';
export * as cbor from './cbor_reader.js';
export * as cbor_writer from './cbor_writer.js';
export * as json from './json.js';
export * as base from './base.js';
export * as bech32 from './bech32.js';
export * as multiformats from './multiformats.js';

// level 1: the formats
export * as pem from './pem.js';
export * as spki from './spki.js';
export * as pkcs8 from './pkcs8.js';
export * as pkcs12 from './pkcs12.js';
export * as pbes2 from './pbes2.js';
export * as x509 from './x509.js';
export * as csr from './csr.js';
export * as crl from './crl.js';
export * as ocsp from './ocsp.js';
export * as cms from './cms.js';
export * as cms_enveloped from './cms_enveloped.js';
export * as tsp from './tsp.js';
export * as smime from './smime.js';
export * as saml from './saml.js';
export * as attrcert from './attrcert.js';
export * as crmf from './crmf.js';
export * as cmp from './cmp.js';
export * as scep from './scep.js';
export * as sct from './sct.js';
export * as signature from './signature.js';
export * as algorithm from './algorithm.js';

export * as x509_build from './x509_build.js';
export * as csr_build from './csr_build.js';
export * as cms_build from './cms_build.js';
export * as cms_enveloped_build from './cms_enveloped_build.js';
export * as crl_build from './crl_build.js';
export * as ocsp_build from './ocsp_build.js';
export * as tsp_build from './tsp_build.js';
export * as pkcs12_build from './pkcs12_build.js';
export * as attrcert_build from './attrcert_build.js';
export * as crmf_build from './crmf_build.js';
export * as cmp_build from './cmp_build.js';
export * as scep_build from './scep_build.js';

export * as jwk from './jwk.js';
export * as jws from './jws.js';
export * as jwe from './jwe.js';
export * as jwt from './jwt.js';
export * as cose from './cose.js';
export * as cwt from './cwt.js';
export * as sd_jwt from './sd_jwt.js';
export * as openpgp from './openpgp.js';
export * as openpgp_build from './openpgp_build.js';
export * as webauthn from './webauthn.js';
export * as fido_mds from './fido_mds.js';
export * as ssh from './ssh.js';
export * as params from './params.js';

export { FormatError } from './error.js';

import type { Certificate } from './x509.js';
import type { AttributeCertificate } from './attrcert.js';
import type { CertificationRequest } from './csr.js';
import type { CertificateList } from './crl.js';
import type { PrivateKey, EncryptedPrivateKey } from './pkcs8.js';
import type { Pfx } from './pkcs12.js';
import type { SignedData } from './cms.js';
import type { EnvelopedData, AuthEnvelopedData, AuthenticatedData, CompressedData, DigestedData, EncryptedData } from './cms_enveloped.js';
import type { SmimeMessage } from './smime.js';
import type { OcspRequest, OcspResponse } from './ocsp.js';
import type { TimeStampRequest, TimeStampResponse } from './tsp.js';
import type { PkiMessage } from './cmp.js';
import type { CertReqMessage } from './crmf.js';
import type { DhParams } from './params.js';
import type { SshPublicKey, SshPrivateContainer, SshSignature, SshCertificate } from './ssh.js';
import type { JwkKey } from './jwk.js';
import type { JsonObject } from './json.js';
import type { Jws } from './jws.js';
import type { Jwe, JweGeneral } from './jwe.js';
import type { CoseKey } from './cose.js';
import type { DecodedCwt } from './cwt.js';
import type { DecodedSdJwt } from './sd_jwt.js';
import type { Armor, Packet, Cleartext } from './openpgp.js';
import type { AttestationObject } from './webauthn.js';
import type { PemBlock } from './pem.js';
import type { PublicKey } from './types.js';

/** What sniff found - narrow on `format` to get `value`'s type. */
export type SniffResult = { label?: string } & (
  | { format: 'x509'; value: Certificate }
  | { format: 'trusted-certificate'; value: Certificate; trust_settings: Uint8Array | null; note: string | null }
  | { format: 'attribute-certificate'; value: AttributeCertificate }
  | { format: 'csr'; value: CertificationRequest }
  | { format: 'crl'; value: CertificateList }
  | { format: 'spki'; value: PublicKey }
  | { format: 'pkcs8' | 'sec1'; value: PrivateKey }
  | { format: 'pkcs1'; value: ReturnType<typeof import('./pkcs8.js').pkcs1_from_der> }
  | { format: 'pkcs1-public'; value: Uint8Array; note: string }
  | { format: 'pkcs8-encrypted'; value: EncryptedPrivateKey }
  | { format: 'pkcs12'; value: Pfx }
  | { format: 'cms'; value: SignedData }
  | { format: 'cms-enveloped'; value: EnvelopedData }
  | { format: 'cms-auth-enveloped'; value: AuthEnvelopedData }
  | { format: 'cms-authenticated'; value: AuthenticatedData }
  | { format: 'cms-compressed'; value: CompressedData }
  | { format: 'cms-digested'; value: DigestedData }
  | { format: 'cms-encrypted'; value: EncryptedData }
  | { format: 'smime'; value: SmimeMessage }
  | { format: 'ocsp-request'; value: OcspRequest }
  | { format: 'ocsp-response'; value: OcspResponse }
  | { format: 'tsp-request'; value: TimeStampRequest }
  | { format: 'tsp-response'; value: TimeStampResponse }
  | { format: 'cmp'; value: PkiMessage }
  | { format: 'crmf'; value: { messages: CertReqMessage[]; der: Uint8Array } }
  | { format: 'dhparam'; value: DhParams }
  | { format: 'ecparam'; value: { curve: string; oid: Uint8Array; der: Uint8Array } }
  | { format: 'ssh-public'; value: SshPublicKey }
  | { format: 'openssh-private'; value: SshPrivateContainer }
  | { format: 'ssh-signature'; value: SshSignature }
  | { format: 'openpgp'; armor: Armor; value: Packet[] }
  | { format: 'openpgp-cleartext'; value: Cleartext }
  | { format: 'ssh-certificate'; value: SshCertificate }
  | { format: 'jwk'; value: JwkKey }
  | { format: 'jwks'; value: JsonObject[] }
  | { format: 'jws'; value: Jws }
  | { format: 'jwe'; value: Jwe | JweGeneral }
  | { format: 'cose-key'; value: CoseKey }
  | { format: 'cwt'; value: DecodedCwt }
  | { format: 'sd-jwt'; value: DecodedSdJwt }
  | { format: 'webauthn'; value: AttestationObject }
  | { format: 'pem-bundle'; value: PemBlock[]; labels: string[]; note: string }
  | { format: 'legacy-encrypted-pem'; value: PemBlock; note: string }
);

export type SniffFormat = SniffResult['format'];

/**
 * Level 2: the only function that guesses - and the result says what it
 * guessed. Narrow on `format` before using `value`. `expect` limits a DER
 * guess to one format.
 */
export function sniff(input: string | BytesInput, options?: { expect?: SniffFormat }): SniffResult;
