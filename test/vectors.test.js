// SPDX-License-Identifier: Apache-2.0
/**
 * test/vectors.test.js
 *
 * The library against the format 1 test vectors (test/vectors/format-1.json),
 * which an independent implementation (test/vectors/reference.js, Node's own
 * crypto plus native Argon2id) produced from fixed inputs:
 *   - the stored vectors are exactly what the reference produces today;
 *   - the library opens every vector: reader token, files, manifest, the
 *     password proof and the wrapped key;
 *   - the library's encryption, given the same salt, produces the vector's
 *     ciphertext byte for byte.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import * as e2ee from '../src/browser/index.js'
import { encryptStream } from '../src/browser/ece.js'
import { buildVectors, VECTORS_FILE } from './vectors/generate.js'
import { encryptFile, pattern } from './vectors/reference.js'

const vectors = JSON.parse(fs.readFileSync(VECTORS_FILE, 'utf8'))
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex')
const mainKey = Buffer.from(vectors.mainKey, 'base64url')

/** A vector file's plaintext and ciphertext. */
function bytesOf (file) {
  const plaintext = file.plaintext.base64 !== undefined
    ? Buffer.from(file.plaintext.base64, 'base64')
    : pattern(file.plaintext.length)
  const ciphertext = file.ciphertext !== undefined
    ? Buffer.from(file.ciphertext, 'base64')
    : encryptFile(mainKey, Buffer.from(file.salt, 'base64'), plaintext)
  assert.equal(ciphertext.length, file.ciphertextLength, `${file.name}: length`)
  assert.equal(sha256(ciphertext), file.ciphertextSha256, `${file.name}: hash`)
  return { plaintext, ciphertext }
}

test('the stored vectors are exactly what the reference implementation produces', async () => {
  assert.deepEqual(await buildVectors(), vectors)
})

test('the vectors follow the stated lengths', () => {
  for (const file of vectors.files) {
    const n = bytesOf(file).plaintext.length
    assert.equal(file.ciphertextLength, e2ee.ciphertextSize(n), file.name)
  }
  assert.equal(Buffer.from(vectors.manifest.sealed, 'base64').length, 32 + 4096)
  assert.equal(Buffer.from(vectors.password.wrappedKey, 'base64').length, 60)
})

test('the library derives the vectors\' reader token', async () => {
  const keychain = e2ee.openKeychain(vectors.mainKey, vectors.keychainSalt)
  assert.equal(await e2ee.readerToken(keychain), vectors.readerToken)
})

test('the library decrypts every vector file', async () => {
  const keychain = e2ee.openKeychain(vectors.mainKey, vectors.keychainSalt)
  for (const file of vectors.files) {
    const { plaintext, ciphertext } = bytesOf(file)
    const out = Buffer.from(await new Response(await e2ee.decryptedFile(
      keychain, new Blob([ciphertext]).stream(), { size: plaintext.length, salt: file.salt })).arrayBuffer())
    assert.ok(out.equals(plaintext), file.name)
  }
})

test('the library\'s encryption, given the same salt, produces the vector ciphertext', async () => {
  const hkdfKey = await globalThis.crypto.subtle.importKey('raw', mainKey, 'HKDF', false, ['deriveBits', 'deriveKey'])
  for (const file of vectors.files) {
    const { plaintext } = bytesOf(file)
    const stream = encryptStream(new Blob([plaintext]).stream(), hkdfKey, new Uint8Array(Buffer.from(file.salt, 'base64')))
    const out = Buffer.from(await new Response(stream).arrayBuffer())
    assert.equal(sha256(out), file.ciphertextSha256, file.name)
  }
})

test('the library opens the vectors\' manifest', async () => {
  const keychain = e2ee.openKeychain(vectors.mainKey, vectors.keychainSalt)
  assert.deepEqual(await e2ee.openManifest(keychain, vectors.manifest.sealed), vectors.manifest.json)
})

test('the library derives the password proof and unwraps the vectors\' key', async () => {
  const p = vectors.password
  const { wrapKey, passwordAuth } = await e2ee.derivePasswordKeys(p.password, e2ee.decodeBase64(p.kdfSalt), p.kdfParams)
  assert.equal(e2ee.encodeBase64(passwordAuth), p.passwordAuth)
  const key = await e2ee.unwrapKey(wrapKey, p.wrappedKey, p.bindTo)
  assert.ok(Buffer.from(key).equals(mainKey))
  await assert.rejects(() => e2ee.unwrapKey(wrapKey, p.wrappedKey, p.bindTo + 'x'), 'another context does not open it')
})
