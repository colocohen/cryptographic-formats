// Open a password-protected private key (PKCS#8 + PBES2). cryptographic-formats
// says what was used; node:crypto derives the key and decrypts.
import crypto from 'node:crypto';
import { pem, pkcs8, algorithm } from 'cryptographic-formats';

const password = 'correct horse battery staple';
const text = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  .privateKey.export({ type: 'pkcs8', format: 'pem',
                       cipher: 'aes-256-cbc', passphrase: password });

// What is needed: the KDF parameters, the cipher, the IV, the ciphertext.
const enc = pkcs8.encrypted_from_der(
  pem.decode_one(text, 'ENCRYPTED PRIVATE KEY').der);
console.log(enc.prf, enc.iterations, enc.cipher);  // hmacWithSHA256 2048 aes256CBC
console.log(enc.weak);                             // false

// The caller's half. Names come back as the file states them;
// algorithm.node_name gives node:crypto's spelling ('sha256', 'aes-256-cbc').
const dk = crypto.pbkdf2Sync(password, enc.salt, enc.iterations,
  enc.key_length, algorithm.node_name(enc.prf));
const d = crypto.createDecipheriv(algorithm.node_name(enc.cipher), dk, enc.iv);
const plain = Buffer.concat([d.update(enc.data), d.final()]);

const key = pkcs8.from_der(plain);
console.log(key.algorithm, key.curve);              // ecPublicKey secp256r1
