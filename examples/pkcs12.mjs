// Write a .p12 / .pfx (a key and its certificate) and read it back.
// Every encryption, KDF and MAC is node:crypto, passed in as primitives.
// The MAC is PBMAC1 (RFC 9579) - PBKDF2 then HMAC. For importers older
// than OpenSSL 3.4, leave out `scheme` and use the PKCS#12 KDF instead.
import crypto from 'node:crypto';
import { x509_build, pkcs8, pkcs12, pkcs12_build, algorithm } from 'cryptographic-formats';

const password = 'p12 password';
const key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const tbs = x509_build.prepare({
  serial: crypto.randomBytes(16),
  issuer: [{ commonName: 'me' }], subject: [{ commonName: 'me' }],
  validity: { not_before: new Date(), not_after: new Date(Date.now() + 864e5) },
  public_key: key.publicKey.export({ type: 'spki', format: 'der' }),
  signature_algorithm: 'ecdsaWithSHA256'
});
const cert = x509_build.assemble(tbs,
  crypto.sign('sha256', tbs.bytes, key.privateKey));

// PBES2: derive, encrypt, and describe what was done.
function encrypt(data) {
  const p = { prf: 'hmacWithSHA256', salt: crypto.randomBytes(16),
              iterations: 100000, cipher: 'aes256CBC',
              iv: crypto.randomBytes(16) };
  const k = crypto.pbkdf2Sync(password, p.salt, p.iterations, 32, 'sha256');
  const c = crypto.createCipheriv('aes-256-cbc', k, p.iv);
  return { ...p, data: Buffer.concat([c.update(data), c.final()]) };
}

const id = crypto.createHash('sha1').update(cert).digest();   // ties key to cert
const keys = pkcs12_build.safe_contents([pkcs12_build.shrouded_key_bag(
  pkcs8.encrypted_to_der(encrypt(
    key.privateKey.export({ type: 'pkcs8', format: 'der' }))),
  { friendly_name: 'my key', local_key_id: id })]);
const certs = pkcs12_build.safe_contents([
  pkcs12_build.cert_bag(cert, { local_key_id: id })]);
const p12_prepared = pkcs12_build.prepare([
  pkcs12_build.data_safe(keys), pkcs12_build.encrypted_safe(encrypt(certs))]);

// The MAC covers p12_prepared.bytes - exactly those, nothing around them.
const salt = crypto.randomBytes(16);
const mac_key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
const pfx = pkcs12_build.assemble(p12_prepared, {
  scheme: 'pbmac1', hash: 'sha256', prf: 'hmacWithSHA256',
  salt, iterations: 100000,
  digest: crypto.createHmac('sha256', mac_key).update(p12_prepared.bytes).digest()
});

// Reading: the library walks the file, the primitives do the work.
const p12 = pkcs12.open(pfx, password, {
  pbkdf2: (prf, pw, s, it, len) =>
    crypto.pbkdf2Sync(pw, s, it, len, algorithm.node_name(prf)),
  decrypt: (cipher, k, iv, data) => {
    const d = crypto.createDecipheriv(algorithm.node_name(cipher), k, iv);
    return Buffer.concat([d.update(data), d.final()]);
  },
  hmac: (hash, k, data) => crypto.createHmac(hash, k).update(data).digest()
});

console.log(p12.mac_verified);                         // true
console.log(p12.keys.length, p12.certificates.length); // 1 1
