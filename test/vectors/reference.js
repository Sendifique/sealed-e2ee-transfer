// SPDX-License-Identifier: Apache-2.0
/**
 * test/vectors/reference.js
 *
 * A second, independent implementation of format 1 — written from
 * PROTOCOL.md with Node's own crypto, sharing no code with src/.
 * It produces the test vectors (generate.js) and is the yardstick the
 * library is checked against (test/vectors.test.js). Deterministic: every
 * random value of the format (salts, IVs) is an input here.
 */

import crypto from 'node:crypto'

export const RECORD_SIZE = 65536
const TAG = 16
const CHUNK = RECORD_SIZE - TAG - 1  // 65519 plaintext bytes per record
const BLOCK = 4096

const hkdf = (ikm, salt, info, length) => Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, length))

/** Reader token R = HKDF(K, S, "authentication", 16) — PROTOCOL.md §1. */
export function readerToken (mainKey, keychainSalt) {
  return hkdf(mainKey, keychainSalt, 'authentication', 16)
}

/**
 * One file, encrypted — PROTOCOL.md §2.
 *
 * @param {Buffer} mainKey - 32 bytes
 * @param {Buffer} fileSalt - 16 bytes
 * @param {Buffer} plaintext
 * @returns {Buffer}
 */
export function encryptFile (mainKey, fileSalt, plaintext) {
  const key = hkdf(mainKey, fileSalt, 'Content-Encoding: aes256gcm\0', 32)
  const nonceBase = hkdf(mainKey, fileSalt, 'Content-Encoding: nonce\0', 12)
  const header = Buffer.alloc(21)
  fileSalt.copy(header, 0)
  header.writeUInt32BE(RECORD_SIZE, 16)
  header[20] = 0

  const parts = [header]
  const records = Math.ceil(plaintext.length / CHUNK)
  for (let seq = 0; seq < records; seq++) {
    const chunk = plaintext.subarray(seq * CHUNK, (seq + 1) * CHUNK)
    const last = seq === records - 1
    // Last record: delimiter 0x02. Every other one: 0x01, then zeros up to
    // a full record — non-final chunks are always full, so no zeros here.
    const padded = last
      ? Buffer.concat([chunk, Buffer.from([2])])
      : Buffer.concat([chunk, Buffer.from([1]), Buffer.alloc(RECORD_SIZE - TAG - chunk.length - 1)])
    const nonce = Buffer.from(nonceBase)
    nonce.writeUInt32BE((nonce.readUInt32BE(8) ^ seq) >>> 0, 8)
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce)
    parts.push(cipher.update(padded), cipher.final(), cipher.getAuthTag())
  }
  return Buffer.concat(parts)
}

/**
 * The manifest, padded and encrypted — PROTOCOL.md §3.
 *
 * @param {Buffer} mainKey
 * @param {Buffer} keychainSalt
 * @param {object} manifest - the JSON object
 * @param {Buffer} iv - 16 bytes
 * @returns {Buffer}
 */
export function sealManifest (mainKey, keychainSalt, manifest, iv) {
  const json = Buffer.from(JSON.stringify(manifest), 'utf8')
  const padded = Buffer.alloc(Math.max(1, Math.ceil(json.length / BLOCK)) * BLOCK, 0x20)
  json.copy(padded, 0)
  const key = hkdf(mainKey, keychainSalt, 'metadata', 32)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  return Buffer.concat([iv, cipher.update(padded), cipher.final(), cipher.getAuthTag()])
}

/**
 * The password block — PROTOCOL.md §5.
 *
 * @param {Buffer} mainKey
 * @param {Buffer} argon2Output - 64 bytes, Argon2id(NFC(password), kdfSalt, params)
 * @param {Buffer} iv - 12 bytes
 * @param {string} bindTo
 * @returns {{ passwordAuth: Buffer, wrappedKey: Buffer }}
 */
export function wrapKey (mainKey, argon2Output, iv, bindTo) {
  const cipher = crypto.createCipheriv('aes-256-gcm', argon2Output.subarray(0, 32), iv)
  cipher.setAAD(Buffer.from(bindTo, 'utf8'))
  const wrappedKey = Buffer.concat([iv, cipher.update(mainKey), cipher.final(), cipher.getAuthTag()])
  return { passwordAuth: Buffer.from(argon2Output.subarray(32, 64)), wrappedKey }
}

/** Deterministic filler: byte i = i mod 251 (a prime, so records differ). */
export function pattern (length) {
  const out = Buffer.alloc(length)
  for (let i = 0; i < length; i++) out[i] = i % 251
  return out
}

/** Deterministic bytes from a label — for keys, salts and IVs of the vectors. */
export function fixed (label, length) {
  return crypto.createHash('sha512').update(label).digest().subarray(0, length)
}
