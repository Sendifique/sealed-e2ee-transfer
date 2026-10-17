// SPDX-License-Identifier: Apache-2.0
/**
 * src/browser/ece.js
 *
 * File encryption of format 1 (PROTOCOL.md §2): the record layout of
 * RFC 8188 ("Encrypted Content-Encoding for HTTP") with AES-256-GCM, as
 * streams — a file is encrypted and decrypted as it flows, never held in
 * memory as a whole.
 *
 *   header = salt (16) || record size (uint32 BE, 65536) || key-id length (1, = 0)
 *   record = AES-256-GCM(content key, nonce(seq), chunk || delimiter) || tag (16)
 *
 * The content key and the nonce base are derived per file from the main key
 * and the file's salt (HKDF-SHA-256, labels "Content-Encoding: aes256gcm\0"
 * and "Content-Encoding: nonce\0" — deliberately not RFC 8188's aes128gcm,
 * so this is never mistaken for, or mixed with, standard RFC 8188 output).
 * nonce(seq) is the nonce base with its last 4 bytes XORed with the record
 * number. Every record but the last is full and ends with delimiter 0x01;
 * the last one ends with 0x02 — so cutting the stream at a record boundary,
 * reordering records or flipping a byte all fail authentication.
 *
 * Checked byte for byte against the test vectors of an independent
 * implementation (test/vectors.test.js).
 */

import { SALT_LENGTH, RECORD_SIZE, TAG_LENGTH, HEADER_LENGTH } from '../format.js'

/** Plaintext bytes per record: the record minus tag and delimiter. */
const CHUNK = RECORD_SIZE - TAG_LENGTH - 1

const encoder = new TextEncoder()
const KEY_INFO = encoder.encode('Content-Encoding: aes256gcm\0')
const NONCE_INFO = encoder.encode('Content-Encoding: nonce\0')

/** Highest record number: the nonce has a 4-byte counter. */
const MAX_SEQ = 0xffffffff

/**
 * Encrypts a plaintext stream.
 *
 * @param {ReadableStream<Uint8Array>} input
 * @param {CryptoKey} mainKey - the transfer's main key, imported for HKDF
 * @param {Uint8Array} [salt] - 16 bytes; a fresh random one when omitted.
 *   FOR TEST VECTORS ONLY. The salt determines the file's AES-GCM key and
 *   nonces: the same salt twice under one main key reuses both, and the XOR
 *   of the two ciphertexts is then the XOR of the two plaintexts (NIST
 *   SP 800-38D requires unique key/IV pairs). That is why this module is not
 *   part of the package's exports — applications encrypt through
 *   Keychain.encryptStream() / createUpload(), which always draw a new salt.
 * @returns {ReadableStream<Uint8Array>} header, then the records
 */
export function encryptStream (input, mainKey, salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH))) {
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_LENGTH) throw new Error('Invalid salt length')
  const queue = new ByteQueue()
  let keys = null
  let seq = 0

  const seal = async (chunk, last) => {
    if (seq > MAX_SEQ) throw new Error('Too many records')
    const padded = new Uint8Array(chunk.length + 1)
    padded.set(chunk, 0)
    padded[chunk.length] = last ? 2 : 1
    const sealed = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonceFor(keys.nonceBase, seq++), tagLength: TAG_LENGTH * 8 }, keys.key, padded)
    return new Uint8Array(sealed)
  }
  const sealFull = async (controller) => {
    while (queue.length > CHUNK) controller.enqueue(await seal(queue.take(CHUNK), false))
  }

  return input.pipeThrough(new TransformStream({
    async start (controller) {
      keys = await recordKeys(mainKey, salt)
      const header = new Uint8Array(HEADER_LENGTH)
      header.set(salt, 0)
      new DataView(header.buffer).setUint32(SALT_LENGTH, RECORD_SIZE)
      controller.enqueue(header)
    },
    transform (chunk, controller) {
      queue.push(chunk)
      // Sealed as non-final only once at least one more byte is known to
      // follow: with exactly one chunk buffered, it may still be the last.
      // Synchronous until a record is complete — no promise per small chunk.
      if (queue.length > CHUNK) return sealFull(controller)
    },
    async flush (controller) {
      // An empty file is the header alone (PROTOCOL.md §2).
      if (queue.length > 0) controller.enqueue(await seal(queue.take(queue.length), true))
    }
  }))
}

/**
 * Decrypts a ciphertext stream, authenticating every record before its
 * plaintext is released.
 *
 * A header with no record after it carries no GCM tag, so on its own it
 * proves nothing: any file cut down to its header, under any key, would
 * "decrypt" to an empty file. It is refused unless the caller knows, from
 * the authenticated manifest, that the file is empty (`allowEmpty`) —
 * which decryptedFile() does.
 *
 * @param {ReadableStream<Uint8Array>} input
 * @param {CryptoKey} mainKey - the transfer's main key, imported for HKDF
 * @param {{ allowEmpty?: boolean }} [options]
 * @returns {ReadableStream<Uint8Array>}
 * @throws (as a stream error) on a missing or foreign header, a record that
 *   fails authentication, a wrong delimiter (truncated or reordered
 *   records), a cut-off record, or a bare header without allowEmpty
 */
export function decryptStream (input, mainKey, { allowEmpty = false } = {}) {
  const queue = new ByteQueue()
  let keys = null
  let seq = 0

  const open = async (record, last) => {
    if (seq > MAX_SEQ) throw new Error('Too many records')
    if (record.length < TAG_LENGTH + 1) throw new Error('Record too short')
    const padded = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonceFor(keys.nonceBase, seq++), tagLength: TAG_LENGTH * 8 }, keys.key, record))
    // The delimiter is the last non-zero byte; zeros after it are padding.
    let end = padded.length - 1
    while (end >= 0 && padded[end] === 0) end--
    if (end < 0) throw new Error('Record without delimiter')
    if (padded[end] !== (last ? 2 : 1)) throw new Error(last ? 'Stream ends before its last record' : 'Last record before the end of the stream')
    return padded.subarray(0, end)
  }

  const readHeader = async () => {
    const header = queue.take(HEADER_LENGTH)
    const view = new DataView(header.buffer, header.byteOffset, header.byteLength)
    if (view.getUint32(SALT_LENGTH) !== RECORD_SIZE) throw new Error('Unsupported record size')
    if (header[SALT_LENGTH + 4] !== 0) throw new Error('Key ids are not supported')
    keys = await recordKeys(mainKey, header.slice(0, SALT_LENGTH))
  }
  const openFull = async (controller) => {
    if (keys === null) await readHeader()
    // A full record with more bytes after it cannot be the last one.
    while (queue.length > RECORD_SIZE) controller.enqueue(await open(queue.take(RECORD_SIZE), false))
  }

  return input.pipeThrough(new TransformStream({
    transform (chunk, controller) {
      queue.push(chunk)
      // Synchronous until there is a header to read or a record to open —
      // no promise per small chunk.
      if ((keys === null && queue.length >= HEADER_LENGTH) || queue.length > RECORD_SIZE) return openFull(controller)
    },
    async flush (controller) {
      if (keys === null) throw new Error('Ciphertext ends before its header')
      if (queue.length > 0) return controller.enqueue(await open(queue.take(queue.length), true))
      // Records are opened only once more bytes follow, so an empty queue
      // here means no record at all: the bare header of an empty file.
      if (!allowEmpty) throw new Error('A bare header is an empty file only where the manifest says so')
    }
  }))
}

/**
 * The file's content key and nonce base.
 *
 * @param {CryptoKey} mainKey
 * @param {Uint8Array} salt
 * @returns {Promise<{ key: CryptoKey, nonceBase: Uint8Array }>}
 */
async function recordKeys (mainKey, salt) {
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: KEY_INFO }, mainKey,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  const nonceBase = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: NONCE_INFO }, mainKey, 96))
  return { key, nonceBase }
}

/**
 * The nonce of record `seq`: the base with its last 4 bytes XORed with seq.
 *
 * @param {Uint8Array} base - 12 bytes
 * @param {number} seq
 * @returns {Uint8Array}
 */
function nonceFor (base, seq) {
  const nonce = base.slice()
  const view = new DataView(nonce.buffer)
  view.setUint32(8, (view.getUint32(8) ^ seq) >>> 0)
  return nonce
}

/**
 * A FIFO of bytes: keeps incoming chunks as they are and joins them once
 * per take(), instead of copying a growing buffer on every chunk.
 */
class ByteQueue {
  constructor () {
    this.chunks = []
    this.length = 0
  }

  push (chunk) {
    const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk.buffer ?? chunk, chunk.byteOffset ?? 0, chunk.byteLength)
    if (bytes.length === 0) return
    this.chunks.push(bytes)
    this.length += bytes.length
  }

  /** Removes and returns exactly n bytes (n ≤ length), as a fresh array. */
  take (n) {
    const out = new Uint8Array(n)
    let filled = 0
    while (filled < n) {
      const head = this.chunks[0]
      const part = Math.min(head.length, n - filled)
      out.set(head.subarray(0, part), filled)
      filled += part
      if (part === head.length) this.chunks.shift()
      else this.chunks[0] = head.subarray(part)
    }
    this.length -= n
    return out
  }
}
