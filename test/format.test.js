// SPDX-License-Identifier: Apache-2.0
/**
 * test/format.test.js
 *
 * Format 1 (PROTOCOL.md), checked against the browser API in src/browser/:
 *   - it really is AES-256: Node's own HKDF and AES-256-GCM (node:crypto,
 *     not the library's code) decrypt what the browser module wrote, file and
 *     manifest alike, and a 128-bit key is refused;
 *   - the ciphertext layout and length formula;
 *   - the manifest: round trip, the application's own fields, padding,
 *     per-file salt binding;
 *   - the share link keeps the key in the #fragment;
 *   - the password variant, its binding context, and the recipient's
 *     distrust of the server's answers (Argon2id floor, key length);
 *   - createUpload(), the sender side in one object.
 *
 * The browser modules run unchanged: Node has the same Web Crypto and
 * streams APIs.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import * as e2ee from '../src/browser/index.js'

const RS = 64 * 1024
const PER_RECORD = RS - 17
const HEADER = 21

/** Reads a reader to the end. */
async function drain (reader) {
  const chunks = []
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(Buffer.from(value))
  }
  return Buffer.concat(chunks)
}

/** Encrypts `bytes` as an upload would and returns the ciphertext. */
async function encrypt (keychain, bytes) {
  return drain(await e2ee.encryptedReader(keychain, new Blob([bytes])))
}

/** Decrypts with the library's own reader. */
async function decrypt (keychain, ciphertext, options) {
  const stream = await keychain.decryptStream(new Blob([ciphertext]).stream(), options)
  return Buffer.from(await new Response(stream).arrayBuffer())
}

/** A per-file salt as an upload records it (any 16 bytes, base64). */
const someSalt = () => crypto.randomBytes(16).toString('base64')

/** The ciphertext length PROTOCOL.md states, computed independently. */
const expectedLength = (n) => HEADER + n + 17 * Math.ceil(n / PER_RECORD)

// ---------------------------------------------------------------------------
// AES-256, checked with Node's own crypto
// ---------------------------------------------------------------------------

/**
 * Node's own reading of format 1: the first record of a file, decrypted with
 * HKDF-SHA-256 and AES-256-GCM from node:crypto — not with the library's code.
 *
 * @param {Uint8Array} mainKey - 32 bytes
 * @param {Buffer} cipher - a whole encrypted file that fits in one record
 * @returns {Buffer} the plaintext
 */
function nodeDecryptSingleRecord (mainKey, cipher) {
  const salt = cipher.subarray(0, 16)
  assert.equal(cipher.readUInt32BE(16), RS, 'record size in the header')
  assert.equal(cipher[20], 0, 'no key id')
  const key = Buffer.from(crypto.hkdfSync('sha256', mainKey, salt, 'Content-Encoding: aes256gcm\0', 32))
  const nonce = Buffer.from(crypto.hkdfSync('sha256', mainKey, salt, 'Content-Encoding: nonce\0', 12))
  const record = cipher.subarray(HEADER)
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce)  // record 0: nonce XOR 0
  decipher.setAuthTag(record.subarray(record.length - 16))
  const padded = Buffer.concat([decipher.update(record.subarray(0, record.length - 16)), decipher.final()])
  assert.equal(padded[padded.length - 1], 2, 'final-record delimiter')
  return padded.subarray(0, padded.length - 1)
}

test('format 1 is AES-256: Node\'s own HKDF + AES-256-GCM decrypt the browser\'s file', async () => {
  const keychain = e2ee.createKeychain()
  assert.equal(keychain.key.length, 32, '256-bit main key')
  const plain = crypto.randomBytes(5000)
  const cipher = await encrypt(keychain, plain)
  assert.ok(nodeDecryptSingleRecord(keychain.key, cipher).equals(plain))

  // The RFC's aes128gcm reading of the same bytes fails: it is not the
  // 128-bit format under another name.
  const salt = cipher.subarray(0, 16)
  const key128 = Buffer.from(crypto.hkdfSync('sha256', keychain.key, salt, 'Content-Encoding: aes128gcm\0', 16))
  const nonce = Buffer.from(crypto.hkdfSync('sha256', keychain.key, salt, 'Content-Encoding: nonce\0', 12))
  const record = cipher.subarray(HEADER)
  const d = crypto.createDecipheriv('aes-128-gcm', key128, nonce)
  d.setAuthTag(record.subarray(record.length - 16))
  d.update(record.subarray(0, record.length - 16))
  assert.throws(() => d.final())
})

test('the manifest: AES-256-GCM under the metadata key, padded to whole blocks', async () => {
  const keychain = e2ee.createKeychain()
  for (const message of ['', 'kurz', 'x'.repeat(5000)]) {
    const sealed = Buffer.from(await e2ee.sealManifest(keychain, { meta: { message }, files: [{ name: 'a', size: 1, salt: someSalt() }] }))
    assert.equal((sealed.length - 32) % e2ee.MANIFEST_BLOCK, 0, `padded (${message.length})`)

    const metaKey = Buffer.from(crypto.hkdfSync('sha256', keychain.key, keychain.salt, 'metadata', 32))
    const decipher = crypto.createDecipheriv('aes-256-gcm', metaKey, sealed.subarray(0, 16))
    decipher.setAuthTag(sealed.subarray(sealed.length - 16))
    const plain = Buffer.concat([decipher.update(sealed.subarray(16, sealed.length - 16)), decipher.final()])
    assert.equal(JSON.parse(plain.toString('utf8')).message, message)
  }
  // Same length for a short and a longer message within one block.
  const a = await e2ee.sealManifest(keychain, { meta: { message: 'a' }, files: [] })
  const b = await e2ee.sealManifest(keychain, { meta: { message: 'a'.repeat(1000) }, files: [] })
  assert.equal(a.length, b.length)
})

test('the reader token is HKDF(main key, salt, "authentication"), 128 bits', async () => {
  const keychain = e2ee.createKeychain()
  const expected = Buffer.from(crypto.hkdfSync('sha256', keychain.key, keychain.salt, 'authentication', 16))
  assert.equal(await e2ee.readerToken(keychain), expected.toString('base64'))
})

test('a 128-bit key is refused, in the link and after unwrapping', async () => {
  const salt = Buffer.alloc(16).toString('base64')
  assert.throws(() => e2ee.openKeychain(crypto.randomBytes(16).toString('base64url'), salt), /32 bytes/)
  assert.throws(() => e2ee.openKeychain(new Uint8Array(16), salt), /32 bytes/)
  assert.doesNotThrow(() => e2ee.openKeychain(crypto.randomBytes(32).toString('base64url'), salt))

  // A server cannot hand back a shorter key wrapped under the right password.
  const bindTo = `test-v1:${crypto.randomUUID()}`
  const kdfSalt = new Uint8Array(crypto.randomBytes(16))
  const { wrapKey } = await e2ee.derivePasswordKeys('ein-langes-passwort', kdfSalt, e2ee.KDF_DEFAULTS)
  const iv = new Uint8Array(12)
  const short = new Uint8Array(await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(bindTo) }, wrapKey, new Uint8Array(16)))
  const wrapped = Buffer.concat([Buffer.from(iv), Buffer.from(short)]).toString('base64')
  await assert.rejects(() => e2ee.unwrapKey(wrapKey, wrapped, bindTo), /wrong length/)
})

// ---------------------------------------------------------------------------
// Files: layout, lengths, round trip, binding
// ---------------------------------------------------------------------------

test('ciphertext length follows the stated formula, and the inverse agrees', () => {
  for (const n of [0, 1, 2, PER_RECORD - 1, PER_RECORD, PER_RECORD + 1, 2 * PER_RECORD + 1, 5 * 1024 * 1024 + 7]) {
    assert.equal(e2ee.ciphertextSize(n), expectedLength(n), `plaintext ${n}`)
    assert.equal(e2ee.plaintextSize(expectedLength(n)), n)
  }
  // 21 = empty plaintext, 39 = one byte; nothing in between exists.
  for (let len = 22; len < 39; len++) assert.equal(e2ee.plaintextSize(len), null, `length ${len}`)
  assert.throws(() => e2ee.ciphertextSize(-1), TypeError)
})

test('real ciphertext round-trips, with the stated header', async () => {
  const keychain = e2ee.createKeychain()
  for (const n of [0, 1, PER_RECORD, PER_RECORD + 1, 3 * PER_RECORD + 99]) {
    const plain = crypto.randomBytes(n)
    const cipher = await encrypt(keychain, plain)
    assert.equal(cipher.length, expectedLength(n), `length for ${n}`)
    assert.equal(cipher.readUInt32BE(16), RS)
    assert.equal(cipher[20], 0)
    assert.ok((await decrypt(keychain, cipher, { allowEmpty: n === 0 })).equals(plain), `round trip for ${n}`)
  }
})

test('every file gets its own key: same content, different ciphertext', async () => {
  const keychain = e2ee.createKeychain()
  const plain = crypto.randomBytes(5000)
  const a = await encrypt(keychain, plain)
  const b = await encrypt(keychain, plain)
  assert.equal(a.equals(b), false)
  assert.equal(a.subarray(0, 16).equals(b.subarray(0, 16)), false, 'fresh per-file salt in the header')
})

test('a downloaded file must have exactly the size the manifest promises', async () => {
  const keychain = e2ee.createKeychain()
  const plain = crypto.randomBytes(100000)
  const cipher = await encrypt(keychain, plain)
  const salt = e2ee.fileSalt(cipher)
  const read = async (bytes, size) => Buffer.from(await new Response(
    await e2ee.decryptedFile(keychain, new Blob([bytes]).stream(), { size, salt })).arrayBuffer())

  assert.ok((await read(cipher, plain.length)).equals(plain))
  // Cut down to the bare header: RFC 8188 alone would decrypt this to an
  // empty file without complaint.
  await assert.rejects(() => read(cipher.subarray(0, HEADER), plain.length))
  await assert.rejects(() => read(cipher, plain.length - 1), 'more than announced')
  await assert.rejects(() => read(cipher, plain.length + 1), 'less than announced')
})

test('every file is bound to its manifest entry by its header salt', async () => {
  const keychain = e2ee.createKeychain()
  // Two files of the same size: the size check alone would not notice a swap.
  const plains = [crypto.randomBytes(3000), crypto.randomBytes(3000)]
  const reported = []
  const ciphers = []
  for (let i = 0; i < 2; i++) {
    ciphers.push(await drain(await e2ee.encryptedReader(keychain, new Blob([plains[i]]), salt => { reported[i] = salt })))
    assert.equal(reported[i], e2ee.fileSalt(ciphers[i]), 'onSalt reports the header salt')
  }
  const entries = plains.map((p, i) => ({ size: p.length, salt: reported[i] }))

  // Delivered in tiny pieces, so the salt check has to work across chunks.
  const trickle = bytes => new ReadableStream({
    start (controller) {
      for (let o = 0; o < bytes.length; o += 5) controller.enqueue(new Uint8Array(bytes.subarray(o, o + 5)))
      controller.close()
    }
  })
  const read = async (bytes, entry) => Buffer.from(await new Response(
    await e2ee.decryptedFile(keychain, trickle(bytes), entry)).arrayBuffer())

  assert.ok((await read(ciphers[0], entries[0])).equals(plains[0]))
  assert.ok((await read(ciphers[1], entries[1])).equals(plains[1]))
  await assert.rejects(() => read(ciphers[1], entries[0]), /does not match the manifest/, 'swapped')
  await assert.rejects(() => read(ciphers[0], entries[1]), /does not match the manifest/, 'swapped back')
})

// ---------------------------------------------------------------------------
// Manifest, server record, link
// ---------------------------------------------------------------------------

test('the manifest carries files and the application\'s own fields; nothing readable is in its ciphertext', async () => {
  const keychain = e2ee.createKeychain()
  const salts = [someSalt(), someSalt()]
  const files = [
    { name: 'Vertrag.pdf', size: 1234, type: 'application/pdf', salt: salts[0] },
    { name: 'scan 2.png', path: 'Belege/2026/scan 2.png', size: 99, type: 'image/png', salt: salts[1] }
  ]
  const meta = { subject: 'Unterlagen', note: { lang: 'de', tags: ['a', 'b'] } }
  const record = await e2ee.serverRecord(keychain, await e2ee.sealManifest(keychain, { meta, files }))
  assert.deepEqual(Object.keys(record).sort(), ['manifest', 'readerToken', 'salt'])
  assert.equal(Buffer.from(record.salt, 'base64').length, 16)
  assert.equal(Buffer.from(record.readerToken, 'base64').length, 16)

  const bytes = Buffer.from(record.manifest, 'base64')
  assert.equal(bytes.includes(Buffer.from('Vertrag')), false)
  assert.equal(bytes.includes(Buffer.from('Unterlagen')), false)

  const recipient = e2ee.openKeychain(keychain.keyB64, record.salt)
  const manifest = await e2ee.openManifest(recipient, record.manifest)
  assert.equal(manifest.v, e2ee.MANIFEST_VERSION)
  assert.equal(manifest.subject, 'Unterlagen')
  assert.deepEqual(manifest.note, meta.note)
  assert.deepEqual(manifest.files, [
    { i: 0, name: 'Vertrag.pdf', path: null, size: 1234, type: 'application/pdf', salt: salts[0] },
    { i: 1, name: 'scan 2.png', path: 'Belege/2026/scan 2.png', size: 99, type: 'image/png', salt: salts[1] }
  ])
  assert.equal(await e2ee.readerToken(recipient), record.readerToken, 'the recipient derives the same reader token')
})

test('the manifest refuses reserved fields and unbound files, and opens only complete entries', async () => {
  const keychain = e2ee.createKeychain()
  await assert.rejects(() => e2ee.sealManifest(keychain, { meta: { v: 2 }, files: [] }), /reserved|without the keys/)
  await assert.rejects(() => e2ee.sealManifest(keychain, { meta: { files: [] }, files: [] }), /without the keys/)
  await assert.rejects(() => e2ee.sealManifest(keychain, { meta: [], files: [] }), /must be an object/)
  await assert.rejects(() => e2ee.sealManifest(keychain, { files: [{ name: 'a', size: 1 }] }), /no salt/)
  await assert.rejects(() => e2ee.sealManifest(keychain, { files: [{ name: 'a', size: 1, salt: 'c2hvcnQ=' }] }), /no salt/)

  const json = JSON.stringify({ v: 1, files: [{ i: 0, name: 'a', path: null, size: 1, type: '' }] })
  const sealed = await keychain.encryptMeta(new TextEncoder().encode(json))
  await assert.rejects(() => e2ee.openManifest(keychain, Buffer.from(sealed).toString('base64')), /Unsupported manifest/)
})

test('the share link carries the key only in the fragment, and it reads back', () => {
  // Many keys, so the URL-safe characters '-' and '_' are certain to occur.
  for (let i = 0; i < 200; i++) {
    const keychain = e2ee.createKeychain()
    const base = `https://files.example/open/${crypto.randomUUID()}`
    const url = new URL(e2ee.shareLink(base, keychain))
    assert.equal(url.origin + url.pathname, base)
    assert.equal(url.search, '')
    assert.match(url.hash, /^#[A-Za-z0-9_-]{43}$/, '256-bit key, base64url, unpadded')
    assert.deepEqual(e2ee.openKeychain(url.hash.slice(1), keychain.saltB64).key, keychain.key)
  }
  assert.throws(() => e2ee.shareLink('https://x.example/#already', e2ee.createKeychain()), /fragment/)
})

// ---------------------------------------------------------------------------
// Password variant
// ---------------------------------------------------------------------------

test('the Argon2id the browser uses gives exactly the native library\'s output', async () => {
  const noble = await import('@noble/hashes/argon2.js')
  const argon2 = (await import('argon2')).default
  const salt = crypto.randomBytes(16)
  const { m, t, p } = e2ee.KDF_DEFAULTS
  for (const pw of ['correct horse battery staple', 'Grüße-aus-Wien-2026', '']) {
    const js = noble.argon2id(pw, salt, { m, t, p, dkLen: 64 })
    const native = await argon2.hash(pw, { raw: true, type: argon2.argon2id, salt, memoryCost: m, timeCost: t, parallelism: p, hashLength: 64 })
    assert.ok(Buffer.from(js).equals(native), JSON.stringify(pw))
  }
})

test('password block: wraps the key; only the right password and context unwrap it', async () => {
  const keychain = e2ee.createKeychain()
  const bindTo = `test-v1:${crypto.randomUUID()}`
  const block = await e2ee.passwordBlock(keychain, 'ein-langes-passwort', bindTo)
  assert.deepEqual(block.kdfParams, e2ee.KDF_DEFAULTS)
  assert.equal(Buffer.from(block.kdfSalt, 'base64').length, 16)
  assert.equal(Buffer.from(block.wrappedKey, 'base64').length, 12 + 32 + 16)
  assert.equal(Buffer.from(block.passwordAuth, 'base64').length, 32)

  const salt = new Uint8Array(Buffer.from(block.kdfSalt, 'base64'))
  const right = await e2ee.derivePasswordKeys('ein-langes-passwort', salt, block.kdfParams)
  assert.equal(Buffer.from(right.passwordAuth).toString('base64'), block.passwordAuth)
  assert.deepEqual(Buffer.from(await e2ee.unwrapKey(right.wrapKey, block.wrappedKey, bindTo)), Buffer.from(keychain.key))
  await assert.rejects(() => e2ee.unwrapKey(right.wrapKey, block.wrappedKey, `test-v1:${crypto.randomUUID()}`), 'bound to its context')
  await assert.rejects(() => e2ee.unwrapKey(right.wrapKey, block.wrappedKey, ''), /bindTo/)
  await assert.rejects(() => e2ee.passwordBlock(keychain, 'ein-langes-passwort'), /bindTo/, 'no context, no block')

  const wrong = await e2ee.derivePasswordKeys('ein-langes-Passwort', salt, block.kdfParams)
  assert.notEqual(Buffer.from(wrong.passwordAuth).toString('base64'), block.passwordAuth)
  await assert.rejects(() => e2ee.unwrapKey(wrong.wrapKey, block.wrappedKey, bindTo))
})

test('the same password typed composed or decomposed gives the same keys', async () => {
  const salt = new Uint8Array(crypto.randomBytes(16))
  const composed = await e2ee.derivePasswordKeys('Grüße-Passwort', salt, e2ee.KDF_DEFAULTS)
  const decomposed = await e2ee.derivePasswordKeys('Grüße-Passwort', salt, e2ee.KDF_DEFAULTS)
  assert.deepEqual(Buffer.from(composed.passwordAuth), Buffer.from(decomposed.passwordAuth))
})

test('the recipient refuses cheap Argon2id parameters before using the password', async () => {
  const salt = new Uint8Array(crypto.randomBytes(16))
  const cases = [
    [salt, { m: 8, t: 1, p: 1 }, 'trivially cheap'],
    [salt, { ...e2ee.KDF_DEFAULTS, m: 19456 }, 'less memory than the defaults'],
    [salt, { ...e2ee.KDF_DEFAULTS, t: 2 }, 'fewer passes than the defaults'],
    [salt, { ...e2ee.KDF_DEFAULTS, m: 4 * 1024 * 1024 }, 'more than a browser can do'],
    [salt, null, 'no parameters'],
    [new Uint8Array(8), e2ee.KDF_DEFAULTS, 'short salt']
  ]
  for (const [kdfSalt, params, name] of cases) {
    const started = Date.now()
    await assert.rejects(() => e2ee.derivePasswordKeys('ein-langes-passwort', kdfSalt, params), /Unacceptable/, name)
    // Refused up front — not after spending (or leaking) an Argon2id run.
    assert.ok(Date.now() - started < 200, `${name}: refused before deriving`)
  }
})

test('generated passphrases: format, alphabet, no repeats', () => {
  const seen = new Set()
  for (let i = 0; i < 500; i++) {
    const p = e2ee.generatePassphrase()
    assert.match(p, /^[a-hjkmnp-z2-9]{4}(-[a-hjkmnp-z2-9]{4}){4}$/)
    assert.ok(p.length >= e2ee.MIN_PASSWORD_LENGTH)
    seen.add(p)
  }
  assert.equal(seen.size, 500)
})

// ---------------------------------------------------------------------------
// createUpload(): the sender side in one object
// ---------------------------------------------------------------------------

test('createUpload: link variant — what the recipient opens from the link alone', async () => {
  const upload = e2ee.createUpload()
  const plains = [crypto.randomBytes(2000), crypto.randomBytes(70000)]
  const ciphers = []
  for (let i = 0; i < plains.length; i++) {
    ciphers.push(await drain(await upload.reader(new Blob([plains[i]]), i)))
    assert.equal(ciphers[i].length, upload.ciphertextSize(plains[i].length))
  }
  assert.throws(() => upload.shareLink('https://files.example/t/1'), /not finalized/)

  const record = await upload.finalize({
    meta: { title: 'Fotos' },
    files: plains.map((p, i) => ({ name: `f${i}.bin`, size: p.length }))
  })
  assert.equal(record.password, undefined)
  assert.equal((Buffer.from(record.manifest, 'base64').length - 32) % e2ee.MANIFEST_BLOCK, 0)

  const link = new URL(upload.shareLink('https://files.example/t/1'))
  assert.equal(link.pathname, '/t/1')
  assert.match(link.hash, /^#[A-Za-z0-9_-]{43}$/)

  const keychain = e2ee.openKeychain(link.hash.slice(1), record.salt)
  const manifest = await e2ee.openManifest(keychain, record.manifest)
  assert.equal(manifest.title, 'Fotos')
  assert.deepEqual(manifest.files.map(f => f.name), ['f0.bin', 'f1.bin'])
  for (let i = 0; i < plains.length; i++) {
    const plain = Buffer.from(await new Response(
      await e2ee.decryptedFile(keychain, new Blob([ciphers[i]]).stream(), manifest.files[i])).arrayBuffer())
    assert.ok(plain.equals(plains[i]), `file ${i}`)
  }
})

test('createUpload: password variant — no key in the link; a file never read is refused', async () => {
  const upload = e2ee.createUpload()
  await drain(await upload.reader(new Blob([Buffer.from('a')]), 0))
  const bindTo = `test-v1:${crypto.randomUUID()}`
  const record = await upload.finalize({ password: 'ein-langes-passwort', bindTo, files: [{ name: 'a.txt', size: 1 }] })
  assert.ok(record.password.wrappedKey)
  assert.equal(upload.shareLink('https://files.example/t/2'), 'https://files.example/t/2')

  // A password without a binding context is refused.
  const unbound = e2ee.createUpload()
  await drain(await unbound.reader(new Blob([Buffer.from('a')]), 0))
  await assert.rejects(() => unbound.finalize({ password: 'ein-langes-passwort', files: [{ name: 'a', size: 1 }] }), /bindTo/)

  // Two files announced, one uploaded: refused rather than sealed unbound.
  const partial = e2ee.createUpload()
  await drain(await partial.reader(new Blob([Buffer.from('a')]), 0))
  await assert.rejects(() => partial.finalize({ files: [{ name: 'a', size: 1 }, { name: 'b', size: 1 }] }), /no salt/)
})
