// SPDX-License-Identifier: Apache-2.0
/**
 * src/server/index.js
 *
 * The server's side of format 1 (PROTOCOL.md §4), for Node: the checks a
 * server CAN make on data it cannot read.
 *
 *   - Exact ciphertext length for a plaintext length (and back), so upload
 *     limits keep working on the declared length.
 *   - Whether a finished upload is SHAPED like format 1: a 21-byte header
 *     with the record size and no key id, and a length the formula can
 *     produce. This cannot prove the data is encrypted (nothing can, without
 *     the key), but it turns "upload plaintext and call it encrypted" from
 *     trivial into something that has to be crafted on purpose.
 *   - Strict validation of what the browser sends when it finalizes a
 *     transfer (browser/sealed.js serverRecord() and passwordBlock()), returning
 *     what to store — hashes instead of the reader token and the password
 *     proof.
 *   - The constant-time comparison for a token or proof a recipient sends.
 *
 * Nothing here stores, sends or decides access; that is the application's.
 * Uses node:crypto; no other dependency.
 */

import crypto from 'node:crypto'
import {
  FORMAT_VERSION, SALT_LENGTH, READER_TOKEN_LENGTH, RECORD_SIZE, HEADER_LENGTH,
  MANIFEST_BLOCK, MANIFEST_OVERHEAD, KDF_DEFAULTS, KDF_BOUNDS, KDF_SALT_LENGTH,
  WRAPPED_KEY_LENGTH, PASSWORD_AUTH_LENGTH, ciphertextSize, plaintextSize
} from '../format.js'

export {
  FORMAT_VERSION, READER_TOKEN_LENGTH, PASSWORD_AUTH_LENGTH, RECORD_SIZE, HEADER_LENGTH,
  MANIFEST_BLOCK, KDF_DEFAULTS, KDF_BOUNDS, ciphertextSize, plaintextSize
}

/** Smallest possible encrypted manifest: one padded block. */
const MIN_MANIFEST_BYTES = MANIFEST_OVERHEAD + MANIFEST_BLOCK

/**
 * Default upper bound for an encrypted manifest. It holds a name, folder
 * path, size, type and salt per file plus the application's own fields; a
 * few hundred bytes per file. 2 MiB covers thousands of files while keeping
 * one finalize request far below anything that could tie up a server.
 */
export const MAX_MANIFEST_BYTES = 2 * 1024 * 1024

// ---------------------------------------------------------------------------
// Uploads
// ---------------------------------------------------------------------------

/**
 * Whether a finished upload looks like format 1 ciphertext: the header names
 * the record size and no key id, and the total length is one a real
 * plaintext produces.
 *
 * @param {Buffer|Uint8Array} header - the first HEADER_LENGTH bytes of the file
 * @param {number} totalLength - the file's full length in bytes
 * @returns {boolean}
 */
export function isShaped (header, totalLength) {
  if (!(header instanceof Uint8Array) || header.length !== HEADER_LENGTH) return false
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength)
  if (view.getUint32(SALT_LENGTH) !== RECORD_SIZE) return false
  if (header[SALT_LENGTH + 4] !== 0) return false
  return plaintextSize(totalLength) !== null
}

/**
 * A file index as an upload declares it (decimal string, no sign, no
 * exponent), or null.
 *
 * @param {unknown} raw
 * @param {number} [max] - highest accepted index
 * @returns {number|null}
 */
export function parseFileIndex (raw, max = 99999) {
  if (typeof raw !== 'string' || !/^\d{1,9}$/.test(raw)) return null
  const index = Number(raw)
  return index <= max ? index : null
}

// ---------------------------------------------------------------------------
// Finalize payload
// ---------------------------------------------------------------------------

/**
 * Strict base64 decode: only the canonical encoding of some byte string is
 * accepted, so the same bytes can never arrive in two spellings.
 *
 * @param {unknown} value
 * @returns {Buffer|null}
 */
export function decodeBase64Strict (value) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0) return null
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return null
  const buf = Buffer.from(value, 'base64')
  return buf.toString('base64') === value ? buf : null
}

/**
 * Validates Argon2id parameters from a browser and returns them in canonical
 * form (exactly these keys), or null. Only KDF_BOUNDS are accepted: cheaper
 * parameters would make the stored proof hash cheap to attack offline;
 * heavier ones would hang every recipient's browser — and the recipient's
 * page refuses both anyway.
 *
 * @param {unknown} raw
 * @returns {{ v: 1, alg: 'argon2id', m: number, t: number, p: number }|null}
 */
export function parseKdfParams (raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  if (raw.v !== KDF_DEFAULTS.v || raw.alg !== KDF_DEFAULTS.alg) return null
  const out = { v: KDF_DEFAULTS.v, alg: KDF_DEFAULTS.alg }
  for (const key of ['m', 't', 'p']) {
    const value = raw[key]
    const [min, max] = KDF_BOUNDS[key]
    if (!Number.isInteger(value) || value < min || value > max) return null
    out[key] = value
  }
  return out
}

/**
 * Validates a password block (browser/sealed.js passwordBlock()).
 *
 * @param {object} raw
 * @returns {{ ok: true, kdfSalt: Buffer, kdfParams: object, wrappedKey: Buffer, passwordAuthHash: Buffer }
 *          | { ok: false, error: string }}
 */
export function parsePasswordBlock (raw) {
  const kdfSalt = decodeBase64Strict(raw?.kdfSalt)
  if (!kdfSalt || kdfSalt.length !== KDF_SALT_LENGTH) return { ok: false, error: 'INVALID_KDF_SALT' }
  const kdfParams = parseKdfParams(raw?.kdfParams)
  if (!kdfParams) return { ok: false, error: 'INVALID_KDF_PARAMS' }
  const wrappedKey = decodeBase64Strict(raw?.wrappedKey)
  if (!wrappedKey || wrappedKey.length !== WRAPPED_KEY_LENGTH) return { ok: false, error: 'INVALID_WRAPPED_KEY' }
  const auth = decodeBase64Strict(raw?.passwordAuth)
  if (!auth || auth.length !== PASSWORD_AUTH_LENGTH) return { ok: false, error: 'INVALID_PASSWORD_AUTH' }
  return { ok: true, kdfSalt, kdfParams, wrappedKey, passwordAuthHash: sha256(auth) }
}

/**
 * Validates what the browser sends to finalize a transfer
 * (browser/sealed.js serverRecord(), plus an optional password block) and
 * returns what to store. Other fields of the body are ignored — the
 * application checks its own (e.g. an upload token).
 *
 * @param {object} body
 * @param {string} body.salt        - base64, the key chain's salt
 * @param {string} body.readerToken - base64
 * @param {string} body.manifest    - base64, the encrypted manifest
 * @param {object} [body.password]  - see parsePasswordBlock()
 * @param {{ maxManifestBytes?: number }} [options]
 * @returns {{ ok: true, salt: Buffer, readerTokenHash: Buffer, manifest: Buffer, password: object|null }
 *          | { ok: false, error: string }}
 */
export function parseTransferRecord (body, { maxManifestBytes = MAX_MANIFEST_BYTES } = {}) {
  const salt = decodeBase64Strict(body?.salt)
  if (!salt || salt.length !== SALT_LENGTH) return { ok: false, error: 'INVALID_SALT' }

  const token = decodeBase64Strict(body?.readerToken)
  if (!token || token.length !== READER_TOKEN_LENGTH) return { ok: false, error: 'INVALID_READER_TOKEN' }

  // Size is checked on the string first, so an oversized value is refused
  // before it is decoded into a second buffer.
  if (typeof body?.manifest !== 'string' || body.manifest.length > Math.ceil(maxManifestBytes / 3) * 4) {
    return { ok: false, error: 'INVALID_MANIFEST' }
  }
  const manifest = decodeBase64Strict(body.manifest)
  if (!manifest || manifest.length < MIN_MANIFEST_BYTES || manifest.length > maxManifestBytes ||
      (manifest.length - MANIFEST_OVERHEAD) % MANIFEST_BLOCK !== 0) {
    // An unpadded manifest would leak the length of what is inside it; a
    // client that forgot the padding is refused rather than stored.
    return { ok: false, error: 'INVALID_MANIFEST' }
  }

  let password = null
  if (body.password !== undefined && body.password !== null) {
    const parsed = parsePasswordBlock(body.password)
    if (!parsed.ok) return parsed
    password = parsed
  }

  return { ok: true, salt, readerTokenHash: sha256(token), manifest, password }
}

// ---------------------------------------------------------------------------
// Opening
// ---------------------------------------------------------------------------

/**
 * What to store instead of a reader token or password proof. Both are
 * random-looking values of 128 or 256 bits, so an unsalted SHA-256 is
 * enough — there is nothing to brute-force — and a database leak does not
 * hand out working values.
 *
 * @param {Buffer|Uint8Array} value
 * @returns {Buffer} 32 bytes
 */
export function sha256 (value) {
  return crypto.createHash('sha256').update(value).digest()
}

/**
 * Whether a base64 value from a recipient's browser hashes to the stored
 * hash — the check for both the reader token and the password proof.
 * Constant-time on the hashes; a malformed value is simply wrong.
 *
 * @param {unknown} valueB64
 * @param {number} expectedLength - READER_TOKEN_LENGTH or PASSWORD_AUTH_LENGTH
 * @param {Buffer|null} storedHash - 32 bytes
 * @returns {boolean}
 */
export function matchesStoredHash (valueB64, expectedLength, storedHash) {
  if (!Buffer.isBuffer(storedHash) || storedHash.length !== 32) return false
  const value = decodeBase64Strict(valueB64)
  if (!value || value.length !== expectedLength) return false
  return crypto.timingSafeEqual(sha256(value), storedHash)
}
