// SPDX-License-Identifier: Apache-2.0
/**
 * test/server.test.js
 *
 * The Node side (src/server/) against the browser side (src/browser/): what a
 * browser produces is exactly what the server accepts, and anything else is
 * refused.
 *   - ciphertext lengths agree, and impossible lengths are refused;
 *   - real browser output passes the shape check; plaintext, a wrong record
 *     size, a key id or a wrong length do not;
 *   - a finalize record (with and without password) is accepted and turned
 *     into hashes; malformed, unpadded or oversized ones are refused;
 *   - Argon2id parameters outside the bounds are refused;
 *   - stored hashes match only the right token or proof.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import * as e2ee from '../src/browser/index.js'
import * as server from '../src/server/index.js'

const RS = 64 * 1024
const PER_RECORD = RS - 17

async function encrypt (keychain, bytes) {
  const reader = await e2ee.encryptedReader(keychain, new Blob([bytes]))
  const chunks = []
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(Buffer.from(value))
  }
  return Buffer.concat(chunks)
}

const someSalt = () => crypto.randomBytes(16).toString('base64')

/** A complete finalize record as a browser builds it. */
async function browserRecord ({ password = null } = {}) {
  const keychain = e2ee.createKeychain()
  const sealed = await e2ee.sealManifest(keychain, { meta: { subject: 'x' }, files: [{ name: 'a', size: 1, salt: someSalt() }] })
  const record = await e2ee.serverRecord(keychain, sealed)
  if (password) record.password = await e2ee.passwordBlock(keychain, password, 'test-v1:1')
  return { keychain, record }
}

// ---------------------------------------------------------------------------
// Sizes and shape
// ---------------------------------------------------------------------------

test('the server computes the same ciphertext length as the browser', () => {
  for (const n of [0, 1, 2, PER_RECORD - 1, PER_RECORD, PER_RECORD + 1, 2 * PER_RECORD + 1, 50 * 1024 ** 3, 4 * 1024 ** 4]) {
    assert.equal(server.ciphertextSize(n), e2ee.ciphertextSize(n), `plaintext ${n}`)
    assert.equal(server.plaintextSize(server.ciphertextSize(n)), n, `inverse at ${n}`)
  }
  for (let i = 0; i < 2000; i++) {
    const n = crypto.randomInt(0, 2 ** 40)
    assert.equal(server.ciphertextSize(n), e2ee.ciphertextSize(n))
  }
  assert.equal(server.plaintextSize(20), null)
  assert.equal(server.plaintextSize(-5), null)
  assert.equal(server.plaintextSize(1.5), null)
  assert.equal(server.plaintextSize(21 + RS + 1), null)
})

test('real browser ciphertext passes the shape check', async () => {
  const keychain = e2ee.createKeychain()
  for (const n of [0, 1, PER_RECORD, PER_RECORD + 1, 3 * PER_RECORD + 99]) {
    const cipher = await encrypt(keychain, crypto.randomBytes(n))
    assert.equal(server.isShaped(cipher.subarray(0, 21), cipher.length), true, `shape for ${n}`)
  }
})

test('plaintext and malformed ciphertext fail the shape check', async () => {
  const cipher = await encrypt(e2ee.createKeychain(), crypto.randomBytes(1000))
  const header = Buffer.from(cipher.subarray(0, 21))

  const pdf = Buffer.from('%PDF-1.7\n%âãÏÓ\n1 0 obj << /Type /Catalog >> endobj\n'.padEnd(1000, ' '))
  assert.equal(server.isShaped(pdf.subarray(0, 21), pdf.length), false, 'an ordinary file')

  const wrongRs = Buffer.from(header); wrongRs.writeUInt32BE(4096, 16)
  assert.equal(server.isShaped(wrongRs, cipher.length), false, 'other record size')
  const withKeyId = Buffer.from(header); withKeyId[20] = 1
  assert.equal(server.isShaped(withKeyId, cipher.length), false, 'key id present')
  assert.equal(server.isShaped(header, 30), false, 'length inside the first gap')
  assert.equal(server.isShaped(header, 21 + RS + 5), false, 'length inside a later gap')
  assert.equal(server.isShaped(header.subarray(0, 20), cipher.length), false, 'short header')
  assert.equal(server.isShaped('not bytes', cipher.length), false)
})

test('file indexes: bounded decimal numbers only', () => {
  assert.equal(server.parseFileIndex('0'), 0)
  assert.equal(server.parseFileIndex('41'), 41)
  assert.equal(server.parseFileIndex('5', 4), null, 'above the given maximum')
  for (const bad of [undefined, '', '-1', '1.5', 'abc', '1e3', '100000', '0x1', ' 1', 7]) {
    assert.equal(server.parseFileIndex(bad), null, String(bad))
  }
})

// ---------------------------------------------------------------------------
// Finalize record
// ---------------------------------------------------------------------------

test('a browser\'s finalize record is accepted and stored as hashes', async () => {
  const { keychain, record } = await browserRecord()
  const parsed = server.parseTransferRecord({ ...record, uploadToken: 'ignored-here' })
  assert.equal(parsed.ok, true, parsed.error)
  assert.ok(parsed.salt.equals(Buffer.from(keychain.salt)))
  assert.ok(parsed.readerTokenHash.equals(server.sha256(Buffer.from(await keychain.authToken()))))
  assert.equal(parsed.password, null)
  assert.equal(server.matchesStoredHash(record.readerToken, server.READER_TOKEN_LENGTH, parsed.readerTokenHash), true)
  assert.equal(server.matchesStoredHash(crypto.randomBytes(16).toString('base64'), server.READER_TOKEN_LENGTH, parsed.readerTokenHash), false)
})

test('with a password: the block is accepted, the proof matches only its hash', async () => {
  const { record } = await browserRecord({ password: 'ein-langes-passwort' })
  const parsed = server.parseTransferRecord(record)
  assert.equal(parsed.ok, true, parsed.error)
  assert.deepEqual(parsed.password.kdfParams, e2ee.KDF_DEFAULTS)
  assert.equal(parsed.password.wrappedKey.length, 60)
  assert.equal(server.matchesStoredHash(record.password.passwordAuth, server.PASSWORD_AUTH_LENGTH, parsed.password.passwordAuthHash), true)
  assert.equal(server.matchesStoredHash(crypto.randomBytes(32).toString('base64'), server.PASSWORD_AUTH_LENGTH, parsed.password.passwordAuthHash), false)
  assert.equal(JSON.stringify(parsed).includes(record.password.passwordAuth), false, 'the proof itself is not kept')
})

test('malformed, unpadded or oversized records are refused', async () => {
  const { record: good } = await browserRecord()
  const { record: pw } = await browserRecord({ password: 'ein-langes-passwort' })
  const cases = {
    'missing salt': { ...good, salt: undefined },
    'salt too short': { ...good, salt: Buffer.alloc(15).toString('base64') },
    'non-canonical base64': { ...good, salt: good.salt.replace(/==$/, '') },
    'url-safe alphabet': { ...good, readerToken: Buffer.alloc(16, 0xfb).toString('base64url') + '==' },
    'token too long': { ...good, readerToken: Buffer.alloc(32).toString('base64') },
    'manifest too small': { ...good, manifest: Buffer.alloc(10).toString('base64') },
    'manifest not padded': { ...good, manifest: Buffer.alloc(32 + 4096 + 1).toString('base64') },
    'manifest not a string': { ...good, manifest: 12345 },
    'manifest too large': { ...good, manifest: Buffer.alloc(server.MAX_MANIFEST_BYTES + 3).toString('base64') },
    'wrapped key 44 bytes': { ...pw, password: { ...pw.password, wrappedKey: Buffer.alloc(44).toString('base64') } },
    'cheap parameters': { ...pw, password: { ...pw.password, kdfParams: { ...pw.password.kdfParams, m: 1024 } } },
    'short proof': { ...pw, password: { ...pw.password, passwordAuth: Buffer.alloc(16).toString('base64') } }
  }
  for (const [name, body] of Object.entries(cases)) {
    assert.equal(server.parseTransferRecord(body).ok, false, name)
  }
  assert.equal(server.parseTransferRecord(undefined).ok, false)
  assert.equal(server.parseTransferRecord(good, { maxManifestBytes: 1000 }).ok, false, 'a smaller limit of the application')
})

test('Argon2id parameters outside the bounds are refused', () => {
  const ok = { v: 1, alg: 'argon2id', m: 65536, t: 3, p: 1 }
  assert.deepEqual(server.parseKdfParams(ok), ok)
  assert.deepEqual(server.parseKdfParams({ ...ok, extra: 'dropped' }), ok)
  for (const bad of [null, [], { ...ok, v: 2 }, { ...ok, alg: 'argon2i' }, { ...ok, m: 1024 }, { ...ok, m: 1048576 },
    { ...ok, t: 1 }, { ...ok, t: 50 }, { ...ok, p: 0 }, { ...ok, p: 8 }, { ...ok, m: '65536' }, { ...ok, t: 2.5 },
    { ...ok, m: 19456 }, { ...ok, m: 65535 }, { ...ok, t: 2 }]) {
    assert.equal(server.parseKdfParams(bad), null, JSON.stringify(bad))
  }
})

test('stored-hash checks: malformed input is simply wrong', () => {
  const hash = server.sha256(Buffer.alloc(16, 7))
  assert.equal(server.matchesStoredHash(Buffer.alloc(16, 7).toString('base64'), 16, hash), true)
  for (const bad of [undefined, '', 'not base64!', Buffer.alloc(15, 7).toString('base64'), 42]) {
    assert.equal(server.matchesStoredHash(bad, 16, hash), false, String(bad))
  }
  assert.equal(server.matchesStoredHash(Buffer.alloc(16, 7).toString('base64'), 16, null), false, 'no stored hash')
})
