// SPDX-License-Identifier: Apache-2.0
/**
 * src/browser/sealed.js
 *
 * End-to-end encrypted file transfer in the browser — format 1
 * (PROTOCOL.md). Everything that touches a transfer key is here; nothing
 * here knows about a particular page, server or URL scheme.
 *
 * Key handling (PROTOCOL.md §1–3):
 *   - one random 256-bit main key and 128-bit salt per transfer, held by a
 *     Keychain;
 *   - each file is encrypted as an RFC 8188-style stream (AES-256-GCM,
 *     64 KiB records — ece.js) under a key derived from the main key with a
 *     fresh random per-file salt in the file's header, so no two files
 *     share a key;
 *   - the manifest (file names, sizes, types, folder paths, plus any
 *     metadata of the application's own) is encrypted under a separate
 *     derived key. It records each file's header salt, which binds every
 *     stored file to its entry: a server cannot swap two files, even of the
 *     same size, unnoticed. It is padded to a multiple of MANIFEST_BLOCK, so
 *     its length does not give away how long the text inside is;
 *   - the reader token is derived too: the recipient proves to the server
 *     that they hold the key without the server ever seeing it.
 *
 * Password variant: instead of putting the key in the link, the sender sets
 * a password. Argon2id(password) yields 64 bytes: the first 32 wrap the main
 * key (AES-256-GCM, bound to a context string the application chooses —
 * typically including the transfer id), the last 32 are a "password proof"
 * whose hash the server stores. The recipient's browser sends the proof;
 * only if it matches does the server hand out the wrapped key, which only
 * the first half — never sent anywhere — can open.
 *
 * Nothing the server hands back is trusted where it could weaken the
 * encryption: the recipient's side checks the Argon2id parameters against a
 * floor before using a password, the unwrapped key's length, and every
 * file's salt and size against the manifest (PROTOCOL.md §6).
 *
 * The main key leaves the browser only inside the share link's #fragment,
 * which browsers never send to a server. Nothing here logs, stores or
 * transmits it otherwise.
 */

import { argon2idAsync } from '@noble/hashes/argon2.js'
import { encryptStream, decryptStream } from './ece.js'
import {
  FORMAT_VERSION, MANIFEST_VERSION, KEY_LENGTH, SALT_LENGTH, READER_TOKEN_LENGTH, MANIFEST_BLOCK,
  KDF_DEFAULTS, KDF_BOUNDS, KDF_SALT_LENGTH, KDF_OUTPUT_LENGTH, MIN_PASSWORD_LENGTH, MIN_PASSWORD_DISTINCT,
  ciphertextSize
} from '../format.js'

export {
  FORMAT_VERSION, MANIFEST_VERSION, KEY_LENGTH, MANIFEST_BLOCK, KDF_DEFAULTS, MIN_PASSWORD_LENGTH,
  MIN_PASSWORD_DISTINCT, ciphertextSize
}

/**
 * Whether this browser has everything the encryption needs. Check before
 * starting, so an old browser gets a clear message instead of failing
 * halfway.
 *
 * @returns {boolean}
 */
export function isSupported () {
  return Boolean(
    globalThis.crypto && globalThis.crypto.subtle &&
    typeof globalThis.ReadableStream === 'function' &&
    typeof globalThis.TransformStream === 'function' &&
    typeof Blob !== 'undefined' && typeof Blob.prototype.stream === 'function'
  )
}

// ---------------------------------------------------------------------------
// Key chain
// ---------------------------------------------------------------------------

const textEncoder = new TextEncoder()

/** IV of the manifest's AES-GCM (PROTOCOL.md §3). */
const MANIFEST_IV_LENGTH = 16

/**
 * One transfer's keys: the main key K and the key-chain salt S, and what is
 * derived from them (PROTOCOL.md §1) — the metadata key and the reader
 * token. The file keys are derived per file in ece.js.
 */
class Keychain {
  /**
   * @param {string|Uint8Array|null} [key] - 32 bytes, or base64(url); random when omitted
   * @param {string|Uint8Array|null} [salt] - 16 bytes, or base64; random when omitted
   * @throws {Error} for a key or salt of the wrong length
   */
  constructor (key, salt) {
    this.key = decodeBits(key, KEY_LENGTH, 'Key')
    this.salt = decodeBits(salt, SALT_LENGTH, 'Salt')
    this.mainKeyPromise = crypto.subtle.importKey('raw', this.key, 'HKDF', false, ['deriveKey', 'deriveBits'])
    this.metaKeyPromise = this.mainKeyPromise.then(mainKey => crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: this.salt, info: textEncoder.encode('metadata') },
      mainKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']))
    this.authTokenPromise = this.mainKeyPromise.then(async mainKey => new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: this.salt, info: textEncoder.encode('authentication') },
      mainKey, READER_TOKEN_LENGTH * 8)))
  }

  /** The main key as it goes into a link: base64url, unpadded. */
  get keyB64 () {
    return toBase64(this.key).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }

  /** The key-chain salt as the server stores it: standard base64. */
  get saltB64 () {
    return toBase64(this.salt)
  }

  /** @returns {Promise<Uint8Array>} the reader token R */
  authToken () {
    return this.authTokenPromise
  }

  /** @returns {Promise<string>} the reader token, base64 */
  async authTokenB64 () {
    return toBase64(await this.authTokenPromise)
  }

  /** @param {ReadableStream<Uint8Array>} stream @returns {Promise<ReadableStream<Uint8Array>>} */
  async encryptStream (stream) {
    return encryptStream(stream, await this.mainKeyPromise)
  }

  /**
   * The raw decryption of one file. It authenticates every record, but not
   * which file this is or that it is whole: decryptedFile() adds both from
   * the manifest, and is what an application should use.
   *
   * @param {ReadableStream<Uint8Array>} stream
   * @param {{ allowEmpty?: boolean }} [options] - accept a bare header as an
   *   empty file; only when an authenticated manifest says the size is 0
   * @returns {Promise<ReadableStream<Uint8Array>>}
   */
  async decryptStream (stream, options) {
    return decryptStream(stream, await this.mainKeyPromise, options)
  }

  /**
   * @param {Uint8Array} plaintext
   * @returns {Promise<Uint8Array>} IV (16) || ciphertext || tag (16)
   */
  async encryptMeta (plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(MANIFEST_IV_LENGTH))
    const sealed = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 }, await this.metaKeyPromise, plaintext))
    const out = new Uint8Array(MANIFEST_IV_LENGTH + sealed.length)
    out.set(iv, 0)
    out.set(sealed, MANIFEST_IV_LENGTH)
    return out
  }

  /**
   * @param {Uint8Array} sealed - IV || ciphertext || tag
   * @returns {Promise<Uint8Array>}
   * @throws if it does not authenticate under this key chain
   */
  async decryptMeta (sealed) {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: sealed.subarray(0, MANIFEST_IV_LENGTH), tagLength: 128 },
      await this.metaKeyPromise, sealed.subarray(MANIFEST_IV_LENGTH)))
  }
}

/**
 * Key material from bytes or base64 (standard or URL-safe, padded or not),
 * or fresh random bytes when nothing is given.
 *
 * @param {string|Uint8Array|null|undefined} value
 * @param {number} length
 * @param {string} what - for the error message
 * @returns {Uint8Array}
 * @throws {Error} for anything else, or the wrong length
 */
function decodeBits (value, length, what) {
  let bytes
  if (value == null) bytes = crypto.getRandomValues(new Uint8Array(length))
  else if (value instanceof Uint8Array) bytes = new Uint8Array(value)
  else if (typeof value === 'string') {
    const standard = value.replace(/-/g, '+').replace(/_/g, '/')
    try {
      bytes = fromBase64(standard + '==='.slice((standard.length + 3) % 4))
    } catch {
      throw new Error(`${what} is not valid base64`)
    }
  } else throw new Error(`${what} must be bytes or base64`)
  if (bytes.length !== length) throw new Error(`${what} must be ${length} bytes`)
  return bytes
}

/**
 * A new key chain with a random main key and salt — one per transfer.
 *
 * @returns {Keychain}
 */
export function createKeychain () {
  return new Keychain()
}

/**
 * The key chain for a received transfer.
 *
 * @param {string|Uint8Array} key - base64url from the link's #fragment, or the unwrapped bytes
 * @param {string} saltB64 - the key-chain salt, as the server stores it
 * @returns {Keychain}
 * @throws {Error} if the key is not exactly 32 bytes (or the salt not 16)
 */
export function openKeychain (key, saltB64) {
  return new Keychain(key, saltB64)
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/**
 * A reader over the encrypted form of `file` — for an upload client such as
 * tus-js-client, which accepts a reader plus an explicit size
 * (ciphertextSize()). The file is encrypted as it is read, never held in
 * memory as a whole.
 *
 * `onSalt` receives the file's header salt (base64) as soon as the header
 * has passed; it belongs in the file's manifest entry. A new reader means a
 * new salt — the last one reported is the one uploaded.
 *
 * @param {Keychain} keychain
 * @param {File|Blob} file
 * @param {(saltB64: string) => void} [onSalt]
 * @returns {Promise<ReadableStreamDefaultReader<Uint8Array>>}
 */
export async function encryptedReader (keychain, file, onSalt) {
  const stream = await keychain.encryptStream(file.stream())
  if (!onSalt) return stream.getReader()
  return stream.pipeThrough(headerTap(SALT_LENGTH, (head) => onSalt(toBase64(head)))).getReader()
}

/**
 * The header salt of an encrypted file (base64), for code that has the whole
 * ciphertext at hand rather than a stream.
 *
 * @param {Uint8Array} ciphertext
 * @returns {string}
 */
export function fileSalt (ciphertext) {
  return toBase64(ciphertext.subarray(0, SALT_LENGTH))
}

/**
 * The plaintext stream of one downloaded file — decrypted as it arrives, and
 * checked against its manifest entry:
 *   - the header salt must be the one the sender recorded, so a stored file
 *     cannot be passed off as another one of the same transfer;
 *   - the size must be the one promised. RFC 8188 detects a truncated
 *     record, but a file cut down to its bare header would decrypt to
 *     nothing without complaint; the size check closes that gap.
 * An error mid-way errors the stream, so a partial or wrong file is never
 * saved as complete.
 *
 * @param {Keychain} keychain
 * @param {ReadableStream<Uint8Array>} ciphertext
 * @param {{ size: number, salt: string }} entry - the file's manifest entry
 * @returns {Promise<ReadableStream<Uint8Array>>}
 */
export async function decryptedFile (keychain, ciphertext, entry) {
  const expectedSize = entry.size
  // Throwing in the tap errors the stream before the chunk is passed on, so
  // the decryptor never sees a byte of a mismatched file.
  const checked = ciphertext.pipeThrough(headerTap(SALT_LENGTH, (head) => {
    if (toBase64(head) !== entry.salt) throw new Error('File does not match the manifest')
  }))
  // An empty file has no record to authenticate; the manifest vouches for it.
  const plain = await keychain.decryptStream(checked, { allowEmpty: expectedSize === 0 })
  let seen = 0
  return plain.pipeThrough(new TransformStream({
    transform (chunk, controller) {
      seen += chunk.byteLength
      if (seen > expectedSize) throw new Error('File is larger than announced')
      controller.enqueue(chunk)
    },
    flush () {
      if (seen !== expectedSize) throw new Error('File is incomplete')
    }
  }))
}

/**
 * A pass-through stream that hands the first `length` bytes to `onHead`
 * once they have arrived, whatever the chunking — before the chunk that
 * completes them is passed on, so an `onHead` that throws stops the stream.
 *
 * @param {number} length
 * @param {(head: Uint8Array) => void} onHead
 * @returns {TransformStream<Uint8Array, Uint8Array>}
 */
function headerTap (length, onHead) {
  let head = new Uint8Array(0)
  return new TransformStream({
    transform (chunk, controller) {
      if (head !== null) {
        const joined = new Uint8Array(head.length + chunk.length)
        joined.set(head, 0)
        joined.set(chunk, head.length)
        if (joined.length >= length) {
          onHead(joined.slice(0, length))
          head = null
        } else {
          head = joined
        }
      }
      controller.enqueue(chunk)
    }
  })
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/**
 * Builds and encrypts the manifest. File entries keep the given order; entry
 * `i` is the file uploaded as index i.
 *
 * @param {Keychain} keychain
 * @param {object} details
 * @param {Array<{ name: string, path?: string|null, size: number, type?: string, salt: string }>} details.files
 *   `salt` is the file's header salt (encryptedReader's onSalt)
 * @param {object} [details.meta] - the application's own fields (e.g. a
 *   subject and a message), stored next to `v` and `files`; JSON values only
 * @returns {Promise<Uint8Array>} IV + ciphertext
 * @throws {Error} if a file has no valid salt — sealing without one would
 *   leave that file unbound — or `meta` uses a reserved key
 */
export async function sealManifest (keychain, { files, meta = {} }) {
  if (!meta || typeof meta !== 'object' || Array.isArray(meta) || 'v' in meta || 'files' in meta) {
    throw new Error('meta must be an object without the keys "v" and "files"')
  }
  if (!Array.isArray(files)) throw new Error('files must be an array')
  const manifest = {
    v: MANIFEST_VERSION,
    ...meta,
    files: files.map((f, i) => {
      if (!isSalt(f?.salt)) throw new Error(`File ${i} has no salt`)
      const entry = {
        i,
        name: f.name,
        path: f.path || null,
        size: f.size,
        type: f.type || '',
        salt: f.salt
      }
      const problem = entryProblem(entry, i)
      if (problem) throw new Error(`File ${i}: ${problem}`)
      return entry
    })
  }
  return keychain.encryptMeta(padManifest(new TextEncoder().encode(JSON.stringify(manifest))))
}

/** Longest file name, folder path and MIME type a manifest may carry. */
const MAX_NAME_LENGTH = 1024
const MAX_PATH_LENGTH = 4096
const MAX_TYPE_LENGTH = 255

/**
 * What is wrong with a manifest entry, or null. The manifest is authenticated,
 * but authentic is not the same as harmless: the sender wrote it, and a
 * sender can write anything. So every entry has exactly the expected shape —
 * index equal to its position (no gaps, no duplicates, no negatives), text
 * where text belongs, bounded lengths — before a page uses it.
 *
 * `path` is the file's full relative path including its name (e.g.
 * "Belege/2026/scan.png"), or null for a file outside any folder.
 *
 * @param {object} file
 * @param {number} position
 * @returns {string|null}
 */
function entryProblem (file, position) {
  if (!file || typeof file !== 'object' || Array.isArray(file)) return 'not an object'
  if (file.i !== position) return 'index does not match its position'
  if (typeof file.name !== 'string' || file.name.length === 0 || file.name.length > MAX_NAME_LENGTH) return 'invalid name'
  if (file.path !== null && (typeof file.path !== 'string' || file.path.length === 0 || file.path.length > MAX_PATH_LENGTH)) return 'invalid path'
  if (!Number.isSafeInteger(file.size) || file.size < 0) return 'invalid size'
  if (typeof file.type !== 'string' || file.type.length > MAX_TYPE_LENGTH) return 'invalid type'
  if (!isSalt(file.salt)) return 'invalid salt'
  return null
}

/**
 * Decrypts and parses the manifest.
 *
 * @param {Keychain} keychain
 * @param {string} manifestB64 - as the server stores it
 * @returns {Promise<{ v: number, files: Array<{ i: number, name: string, path: string|null, size: number, type: string, salt: string }> }>}
 *   plus the application's own fields
 * @throws {Error} if it does not decrypt, or is not a manifest of this
 *   format — every file entry must have exactly the expected shape
 *   (see entryProblem)
 */
export async function openManifest (keychain, manifestB64) {
  const plain = await keychain.decryptMeta(fromBase64(manifestB64))
  const manifest = JSON.parse(new TextDecoder().decode(plain))
  if (!manifest || typeof manifest !== 'object' || manifest.v !== MANIFEST_VERSION || !Array.isArray(manifest.files)) {
    throw new Error('Unsupported manifest')
  }
  manifest.files.forEach((file, position) => {
    const problem = entryProblem(file, position)
    if (problem) throw new Error(`Unsupported manifest: file ${position}: ${problem}`)
  })
  return manifest
}

/**
 * Pads serialized JSON with spaces to the next multiple of MANIFEST_BLOCK
 * (at least one block). JSON.parse ignores trailing whitespace, so the
 * recipient needs no unpadding step.
 *
 * @param {Uint8Array} json
 * @returns {Uint8Array}
 */
function padManifest (json) {
  const padded = new Uint8Array(Math.max(1, Math.ceil(json.length / MANIFEST_BLOCK)) * MANIFEST_BLOCK)
  padded.fill(0x20)
  padded.set(json, 0)
  return padded
}

/** Whether a value is a base64 salt of the right length. */
function isSalt (value) {
  if (typeof value !== 'string') return false
  try {
    return fromBase64(value).length === SALT_LENGTH
  } catch {
    return false
  }
}

// ---------------------------------------------------------------------------
// What the server stores, and the link
// ---------------------------------------------------------------------------

/**
 * What the server stores for a transfer (PROTOCOL.md §4): the key-chain
 * salt, the reader token (the server keeps only its SHA-256) and the
 * encrypted manifest — all base64.
 *
 * @param {Keychain} keychain
 * @param {Uint8Array} sealedManifest - from sealManifest()
 * @returns {Promise<{ salt: string, readerToken: string, manifest: string }>}
 */
export async function serverRecord (keychain, sealedManifest) {
  return {
    salt: keychain.saltB64,
    readerToken: await keychain.authTokenB64(),
    manifest: toBase64(sealedManifest)
  }
}

/**
 * The reader token of a key chain (base64) — what a recipient sends to
 * prove they hold the key.
 *
 * @param {Keychain} keychain
 * @returns {Promise<string>}
 */
export function readerToken (keychain) {
  return keychain.authTokenB64()
}

/**
 * The share link: `baseUrl` with the key in its #fragment, which browsers
 * keep to themselves — it is not sent with the request, so it never reaches
 * the server or its logs.
 *
 * @param {string} baseUrl - the page that opens the transfer, without a fragment
 * @param {Keychain} keychain
 * @returns {string}
 * @throws {Error} if baseUrl already has a fragment
 */
export function shareLink (baseUrl, keychain) {
  if (String(baseUrl).includes('#')) throw new Error('baseUrl must not contain a fragment')
  return `${baseUrl}#${keychain.keyB64}`
}

// ---------------------------------------------------------------------------
// Password variant
// ---------------------------------------------------------------------------

const PASSPHRASE_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789'  // no i/l/o/0/1

/**
 * A random passphrase like "k7mp-2qxr-9tvh-…": 20 characters from a
 * 31-letter alphabet without look-alikes, about 99 bits — far beyond any
 * guessing attack, still easy to read out over the phone.
 *
 * @returns {string}
 */
export function generatePassphrase () {
  const out = []
  // Rejection sampling keeps every character equally likely.
  const limit = 256 - (256 % PASSPHRASE_ALPHABET.length)
  while (out.length < 20) {
    for (const byte of crypto.getRandomValues(new Uint8Array(32))) {
      if (byte < limit && out.length < 20) out.push(PASSPHRASE_ALPHABET[byte % PASSPHRASE_ALPHABET.length])
    }
  }
  return out.join('').match(/.{4}/g).join('-')
}

/**
 * Argon2id(password) split into the wrapping key and the password proof.
 * The password is NFC-normalised, so the same password typed on different
 * systems (composed vs. decomposed umlauts) gives the same keys.
 *
 * The parameters usually come from the server. A server that sent cheap
 * ones would get back a proof it could crack in seconds — and with the
 * password the transfer key — so they are checked against KDF_BOUNDS
 * before the password is used at all.
 *
 * @param {string} password
 * @param {Uint8Array} kdfSalt - 16 bytes
 * @param {{ m: number, t: number, p: number }} params
 * @param {(progress: number) => void} [onProgress] - 0…1
 * @returns {Promise<{ wrapKey: CryptoKey, passwordAuth: Uint8Array }>}
 * @throws {Error} if the salt or the parameters are not acceptable
 */
export async function derivePasswordKeys (password, kdfSalt, params, onProgress) {
  checkKdf(kdfSalt, params)
  const out = await argon2idAsync(password.normalize('NFC'), kdfSalt, {
    m: params.m, t: params.t, p: params.p, dkLen: KDF_OUTPUT_LENGTH, onProgress
  })
  const wrapKey = await crypto.subtle.importKey('raw', out.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt'])
  const passwordAuth = out.slice(32, 64)
  out.fill(0)
  return { wrapKey, passwordAuth }
}

/**
 * Refuses an Argon2id salt or parameter set outside KDF_BOUNDS.
 *
 * @param {Uint8Array} kdfSalt
 * @param {object} params
 * @throws {Error}
 */
function checkKdf (kdfSalt, params) {
  if (!(kdfSalt instanceof Uint8Array) || kdfSalt.length !== KDF_SALT_LENGTH) {
    throw new Error('Unacceptable Argon2id salt')
  }
  // The labels too, not only the costs: parameters for another version or
  // algorithm must not be run as if they were format 1's Argon2id.
  if (params?.v !== KDF_DEFAULTS.v || params.alg !== KDF_DEFAULTS.alg) {
    throw new Error('Unacceptable Argon2id parameters')
  }
  for (const [key, [min, max]] of Object.entries(KDF_BOUNDS)) {
    const value = params?.[key]
    if (!Number.isInteger(value) || value < min || value > max) {
      throw new Error('Unacceptable Argon2id parameters')
    }
  }
}

/**
 * The AES-GCM additional data of the wrapped key: it opens only in the
 * context it was made for — so a wrapped key copied onto another transfer
 * does not open there.
 *
 * @param {string} bindTo
 * @returns {Uint8Array}
 * @throws {Error} for an empty context
 */
function bindingData (bindTo) {
  if (typeof bindTo !== 'string' || bindTo.length === 0) throw new Error('bindTo must be a non-empty string')
  return new TextEncoder().encode(bindTo)
}

/**
 * Refuses a password too weak to protect a transfer: it must be a string of
 * at least MIN_PASSWORD_LENGTH characters, with at least
 * MIN_PASSWORD_DISTINCT different ones — counted as Unicode code points
 * after NFC, so an umlaut or an emoji counts once, however it was typed.
 *
 * This is the floor, checked wherever a password is set. Argon2id slows down
 * guessing but cannot make a weak password strong: with a copy of the
 * server's database, a password is only as good as its own entropy, and
 * "Password1234" passes this check. Make generatePassphrase() the default;
 * further checks (lists of common passwords, words) are the application's
 * to add — locally, never by sending the password anywhere.
 *
 * @param {unknown} password
 * @throws {Error} with `code`: PASSWORD_NOT_A_STRING, PASSWORD_TOO_SHORT or
 *   PASSWORD_TOO_REPETITIVE — for an application to show in its own words
 */
export function checkNewPassword (password) {
  if (typeof password !== 'string') throw coded('PASSWORD_NOT_A_STRING', 'Password must be a string')
  const chars = [...password.normalize('NFC')]
  if (chars.length < MIN_PASSWORD_LENGTH) {
    throw coded('PASSWORD_TOO_SHORT', `Password must be at least ${MIN_PASSWORD_LENGTH} characters`)
  }
  if (new Set(chars).size < MIN_PASSWORD_DISTINCT) {
    throw coded('PASSWORD_TOO_REPETITIVE', `Password must contain at least ${MIN_PASSWORD_DISTINCT} different characters`)
  }
}

/**
 * @param {string} code
 * @param {string} message
 * @returns {Error}
 */
function coded (code, message) {
  const err = new Error(message)
  err.code = code
  return err
}

/**
 * The password block the server stores; the share link then carries no key.
 *
 * @param {Keychain} keychain
 * @param {string} password - at least MIN_PASSWORD_LENGTH characters (checkNewPassword)
 * @param {string} bindTo - context the wrapped key is bound to, e.g.
 *   "myapp-v1:<transferId>"; the recipient must pass the same string
 * @param {(progress: number) => void} [onProgress]
 * @returns {Promise<{ kdfSalt: string, kdfParams: object, wrappedKey: string, passwordAuth: string }>}
 * @throws {Error} for a password that checkNewPassword refuses, or no bindTo
 */
export async function passwordBlock (keychain, password, bindTo, onProgress) {
  checkNewPassword(password)
  const aad = bindingData(bindTo)
  const kdfSalt = crypto.getRandomValues(new Uint8Array(KDF_SALT_LENGTH))
  const { wrapKey, passwordAuth } = await derivePasswordKeys(password, kdfSalt, KDF_DEFAULTS, onProgress)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const sealed = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad }, wrapKey, keychain.key))
  const wrapped = new Uint8Array(12 + sealed.length)
  wrapped.set(iv, 0)
  wrapped.set(sealed, 12)
  return {
    kdfSalt: toBase64(kdfSalt),
    kdfParams: { ...KDF_DEFAULTS },
    wrappedKey: toBase64(wrapped),
    passwordAuth: toBase64(passwordAuth)
  }
}

/**
 * Opens a wrapped main key with the key derived from the password.
 *
 * @param {CryptoKey} wrapKey
 * @param {string} wrappedKeyB64 - as the server releases it
 * @param {string} bindTo - the same context the sender used
 * @returns {Promise<Uint8Array>} the 32-byte main key
 * @throws if the key does not open (wrong password, other context) or is
 *   not a full-length key
 */
export async function unwrapKey (wrapKey, wrappedKeyB64, bindTo) {
  const aad = bindingData(bindTo)
  const wrapped = fromBase64(wrappedKeyB64)
  const key = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: wrapped.slice(0, 12), additionalData: aad },
    wrapKey, wrapped.slice(12)))
  if (key.length !== KEY_LENGTH) throw new Error('Unwrapped key has the wrong length')
  return key
}

// ---------------------------------------------------------------------------
// Sending — the whole upload side in one object
// ---------------------------------------------------------------------------

/**
 * One transfer, seen from the sender's browser. Everything that touches the
 * key happens in here: the upload code gets readers to hand to its upload
 * client, the record to send to its server and the link to show — never
 * the key itself, and it never has to know about salts or the manifest
 * format.
 *
 * Order: reader() for every file, then finalize() once, then shareLink().
 *
 * @returns {{
 *   reader: (file: File|Blob, index: number) => Promise<ReadableStreamDefaultReader<Uint8Array>>,
 *   ciphertextSize: (plaintextLength: number) => number,
 *   finalize: (details: object) => Promise<object>,
 *   shareLink: (baseUrl: string) => string
 * }}
 */
export function createUpload () {
  const keychain = createKeychain()
  const salts = []
  let withPassword = null  // known once finalize() has run

  return {
    /** Encrypting reader for file `index`; records the file's salt. */
    reader: (file, index) => encryptedReader(keychain, file, (salt) => { salts[index] = salt }),

    ciphertextSize,

    /**
     * What the server stores (serverRecord), and with a password the
     * password block (Argon2id — about a second).
     *
     * @param {object} details
     * @param {Array<{ name: string, path?: string|null, size: number, type?: string }>} details.files
     *   in upload order — index i is the file whose reader(…, i) was uploaded
     * @param {object} [details.meta] - the application's own manifest fields
     * @param {string|null} [details.password] - null (or absent) for the link
     *   variant; any string means the password variant and must pass
     *   checkNewPassword — an empty string is refused, never read as "no
     *   password"
     * @param {string} [details.bindTo] - required with a password (see passwordBlock)
     * @returns {Promise<{ salt: string, readerToken: string, manifest: string, password?: object }>}
     * @throws {Error} if a file has no recorded salt (it was never read), or
     *   the password or bindTo is not acceptable
     */
    async finalize ({ files, meta = {}, password = null, bindTo }) {
      // The variant is decided by presence, not truthiness: an empty field
      // must not silently turn a password transfer into a link transfer.
      const wantsPassword = password !== null && password !== undefined
      if (wantsPassword) {
        checkNewPassword(password)
        bindingData(bindTo)
      }
      const sealed = await sealManifest(keychain, {
        meta,
        files: files.map((f, i) => ({ ...f, salt: salts[i] }))
      })
      const record = await serverRecord(keychain, sealed)
      if (wantsPassword) record.password = await passwordBlock(keychain, password, bindTo)
      withPassword = wantsPassword
      return record
    },

    /**
     * The link to hand out: `baseUrl` with the key in its #fragment — or,
     * with a password, `baseUrl` alone (the password opens it).
     *
     * @param {string} baseUrl
     * @returns {string}
     * @throws {Error} before finalize()
     */
    shareLink (baseUrl) {
      if (withPassword === null) throw new Error('Upload not finalized')
      return withPassword ? String(baseUrl) : shareLink(baseUrl, keychain)
    }
  }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/**
 * Bytes ↔ standard, padded base64 — the encoding of every binary value in
 * PROTOCOL.md (salts, tokens, proofs, the manifest).
 */
export { toBase64 as encodeBase64, fromBase64 as decodeBase64 }

/**
 * Standard, padded base64.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function toBase64 (bytes) {
  let binary = ''
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000))
  }
  return btoa(binary)
}

/**
 * Standard base64 to bytes.
 *
 * @param {string} b64
 * @returns {Uint8Array}
 */
function fromBase64 (b64) {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}
