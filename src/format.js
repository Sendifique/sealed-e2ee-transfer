// SPDX-License-Identifier: Apache-2.0
/**
 * src/format.js
 *
 * The numbers of format 1 (PROTOCOL.md), in one place for the browser side
 * (browser/) and the server side (server/). Pure data — no
 * browser or Node API — so both can import it.
 */

/**
 * Version of the whole format: key length, ciphers, derivation labels,
 * manifest layout. Any change to those is a new number, never an edit here.
 */
export const FORMAT_VERSION = 1

/** Version of the decrypted manifest's JSON. */
export const MANIFEST_VERSION = 1

/** Transfer (main) key, bytes — AES-256 strength. */
export const KEY_LENGTH = 32

/** Key-chain salt and per-file header salt, bytes. */
export const SALT_LENGTH = 16

/** Reader token derived from the main key, bytes. */
export const READER_TOKEN_LENGTH = 16

/** Record size of the file encryption (RFC 8188 layout). */
export const RECORD_SIZE = 64 * 1024

/** AES-GCM tag per record, bytes. */
export const TAG_LENGTH = 16

/** File header: salt + 4-byte record size + 1-byte key-id length. */
export const HEADER_LENGTH = SALT_LENGTH + 4 + 1

/** Per-record overhead: tag plus the 1-byte padding delimiter. */
export const RECORD_OVERHEAD = TAG_LENGTH + 1

/** The plaintext manifest is padded to a multiple of this many bytes. */
export const MANIFEST_BLOCK = 4096

/** The encrypted manifest's IV (16) and tag (16) around the padded plaintext. */
export const MANIFEST_OVERHEAD = 16 + TAG_LENGTH

/** Argon2id parameters every new password transfer uses (m in KiB). */
export const KDF_DEFAULTS = Object.freeze({ v: 1, alg: 'argon2id', m: 65536, t: 3, p: 1 })

/**
 * The only Argon2id parameters accepted — by the server when a transfer is
 * created, and by the recipient's page before a password is used. The floor
 * is the defaults: cheaper parameters would make the stored password proof
 * cheap to attack offline. The ceiling keeps a server from making the
 * recipient's browser work for minutes: the defaults take about 3 s in a
 * desktop browser, the ceiling about 2.7 times that (twice the memory, one
 * more pass); a slow phone needs several times longer either way.
 */
export const KDF_BOUNDS = Object.freeze({
  m: Object.freeze([KDF_DEFAULTS.m, 131072]),
  t: Object.freeze([KDF_DEFAULTS.t, 4]),
  p: Object.freeze([KDF_DEFAULTS.p, 4])
})

/** Argon2id salt, bytes. */
export const KDF_SALT_LENGTH = 16

/** Argon2id output: wrap key (32) + password proof (32). */
export const KDF_OUTPUT_LENGTH = 64

/** Second half of the Argon2id output, sent as the password proof. */
export const PASSWORD_AUTH_LENGTH = 32

/** The wrapped main key: 12-byte IV + 32-byte key + 16-byte tag. */
export const WRAPPED_KEY_LENGTH = 12 + KEY_LENGTH + TAG_LENGTH

/** Shortest password accepted (the server never sees it — only this side can check). */
export const MIN_PASSWORD_LENGTH = 12

/**
 * Fewest different characters a password must contain: refuses repetition
 * such as "aaaaaaaaaaaa" or "abababababab", which the length alone lets
 * through. Not a strength measure — a floor below which there is none.
 */
export const MIN_PASSWORD_DISTINCT = 5

/**
 * Exact ciphertext length of a plaintext of `n` bytes.
 *
 * @param {number} n - non-negative integer
 * @returns {number}
 * @throws {TypeError} for anything but a non-negative safe integer
 */
export function ciphertextSize (n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new TypeError('plaintext length must be a non-negative integer')
  return HEADER_LENGTH + n + RECORD_OVERHEAD * Math.ceil(n / (RECORD_SIZE - RECORD_OVERHEAD))
}

/**
 * Plaintext length of a ciphertext of `length` bytes, or null when no
 * plaintext encrypts to exactly that many bytes.
 *
 * @param {number} length
 * @returns {number|null}
 */
export function plaintextSize (length) {
  if (!Number.isSafeInteger(length) || length < HEADER_LENGTH) return null
  const records = length - HEADER_LENGTH
  const plain = records - RECORD_OVERHEAD * Math.ceil(records / RECORD_SIZE)
  // The inverse is not total: some lengths fall between two valid ones.
  return plain >= 0 && ciphertextSize(plain) === length ? plain : null
}
