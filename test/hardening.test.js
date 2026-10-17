// SPDX-License-Identifier: Apache-2.0
/**
 * test/hardening.test.js
 *
 * Misuse and malformed input that an external security review (October 2026)
 * found accepted. Each test reproduces the attempt and requires it to be
 * refused now:
 *   - an empty or short password (silent switch to the link variant,
 *     guessable passwords);
 *   - Argon2id parameters labelled for another version or algorithm;
 *   - manifest entries of the wrong shape — from the sender's API and inside
 *     an authentic, correctly encrypted manifest;
 *   - a fallback download longer than announced;
 *   - reaching the file encryption with a chosen salt through the package;
 *   - a ZIP path that is only a folder.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import * as lib from '../src/browser/index.js'

const someSalt = () => crypto.randomBytes(16).toString('base64')

/** Reads a reader to the end. */
async function drain (reader) {
  for (;;) if ((await reader.read()).done) return
}

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

test('an empty password is refused — never a silent switch to the link variant', async () => {
  const upload = lib.createUpload()
  await drain(await upload.reader(new Blob([Buffer.from('x')]), 0))
  await assert.rejects(() => upload.finalize({ files: [{ name: 'x', size: 1 }], password: '', bindTo: 'test:1' }), /at least 12/)
  // Nothing was finalized, so no link — in particular none with a key.
  assert.throws(() => upload.shareLink('https://files.example/t/1'), /not finalized/)
})

test('a password must have at least 12 characters, counted after NFC', async () => {
  const keychain = lib.createKeychain()
  // Every letter typed decomposed: base letter + combining diaeresis.
  const decomposed = (s) => [...s].map(c => c + String.fromCharCode(0x308)).join('')
  for (const pw of ['a', '12345678901', decomposed('aouAOUeiyao')]) {
    await assert.rejects(() => lib.passwordBlock(keychain, pw, 'test:1'), /at least 12/, JSON.stringify(pw))
    assert.throws(() => lib.checkNewPassword(pw), { code: 'PASSWORD_TOO_SHORT' })
  }
  for (const bad of [null, undefined, 123456789012, ['123456789012']]) {
    assert.throws(() => lib.checkNewPassword(bad), { code: 'PASSWORD_NOT_A_STRING' }, String(bad))
  }
  // Exactly 12 — also when every character is typed decomposed (24 code points before NFC).
  assert.doesNotThrow(() => lib.checkNewPassword('123456789012'))
  assert.equal(decomposed('aouAOUeiyaou').length, 24)
  assert.doesNotThrow(() => lib.checkNewPassword(decomposed('aouAOUeiyaou')))
  const block = await lib.passwordBlock(keychain, decomposed('aouAOUeiyaou'), 'test:1')
  assert.ok(block.wrappedKey)
})

test('a password must not be mere repetition', () => {
  for (const pw of ['aaaaaaaaaaaa', 'abababababab', '123123123123', 'abcdabcdabcd', 'x'.repeat(40)]) {
    assert.throws(() => lib.checkNewPassword(pw), { code: 'PASSWORD_TOO_REPETITIVE' }, pw)
  }
  assert.doesNotThrow(() => lib.checkNewPassword('abcdeabcdeab'), `${lib.MIN_PASSWORD_DISTINCT} different suffice`)
  for (let i = 0; i < 200; i++) assert.doesNotThrow(() => lib.checkNewPassword(lib.generatePassphrase()))
})

test('createUpload checks the password before doing any work, and needs bindTo with it', async () => {
  const upload = lib.createUpload()
  await drain(await upload.reader(new Blob([Buffer.from('x')]), 0))
  const files = [{ name: 'x', size: 1 }]
  await assert.rejects(() => upload.finalize({ files, password: 'short', bindTo: 'test:1' }), /at least 12/)
  await assert.rejects(() => upload.finalize({ files, password: 'long-enough-password' }), /bindTo/)
  // null and absent both mean the link variant.
  const record = await upload.finalize({ files, password: null })
  assert.equal(record.password, undefined)
  assert.match(upload.shareLink('https://files.example/t/1'), /#[A-Za-z0-9_-]{43}$/)
})

test('Argon2id parameters of another version or algorithm are refused before deriving', async () => {
  const salt = new Uint8Array(crypto.randomBytes(16))
  for (const params of [
    { ...lib.KDF_DEFAULTS, v: 99 },
    { ...lib.KDF_DEFAULTS, alg: 'not-argon2id' },
    { ...lib.KDF_DEFAULTS, alg: 'argon2i' },
    { m: lib.KDF_DEFAULTS.m, t: lib.KDF_DEFAULTS.t, p: lib.KDF_DEFAULTS.p }  // no labels at all
  ]) {
    const started = Date.now()
    await assert.rejects(() => lib.derivePasswordKeys('password-with-enough-letters', salt, params), /Unacceptable/, JSON.stringify(params))
    assert.ok(Date.now() - started < 200, 'refused before an Argon2id run')
  }
})

// ---------------------------------------------------------------------------
// Manifest shape
// ---------------------------------------------------------------------------

test('the sender\'s API refuses manifest entries of the wrong shape', async () => {
  const keychain = lib.createKeychain()
  const ok = { name: 'a.txt', size: 1, salt: someSalt() }
  for (const [entry, why] of [
    [{ ...ok, name: 17 }, /invalid name/],
    [{ ...ok, name: { x: 1 } }, /invalid name/],
    [{ ...ok, name: '' }, /invalid name/],
    [{ ...ok, name: 'x'.repeat(1025) }, /invalid name/],
    [{ ...ok, path: ['odd'] }, /invalid path/],
    [{ ...ok, path: { evil: 1 } }, /invalid path/],
    [{ ...ok, type: 42 }, /invalid type/],
    [{ ...ok, size: -1 }, /invalid size/],
    [{ ...ok, size: 1.5 }, /invalid size/]
  ]) {
    await assert.rejects(() => lib.sealManifest(keychain, { files: [entry] }), why, JSON.stringify(entry).slice(0, 60))
  }
  await assert.rejects(() => lib.sealManifest(keychain, { files: 'nope' }), /must be an array/)
})

test('an authentic manifest of the wrong shape is refused when opened', async () => {
  const keychain = lib.createKeychain()
  const good = (i) => ({ i, name: `f${i}`, path: null, size: 1, type: '', salt: someSalt() })
  // Encrypted under the right key, as a sender who bypasses the API could.
  const sealedB64 = async (manifest) => lib.encodeBase64(await keychain.encryptMeta(new TextEncoder().encode(JSON.stringify(manifest))))
  const cases = {
    'object as name': { v: 1, files: [{ ...good(0), name: { x: 1 } }] },
    'array as path': { v: 1, files: [{ ...good(0), path: ['odd'] }] },
    'number as type': { v: 1, files: [{ ...good(0), type: 42 }] },
    'negative index': { v: 1, files: [{ ...good(0), i: -1 }] },
    'duplicate index': { v: 1, files: [good(0), { ...good(1), i: 0 }] },
    'index out of order': { v: 1, files: [good(1), good(0)] },
    'gap in the indexes': { v: 1, files: [good(0), { ...good(1), i: 2 }] },
    'entry not an object': { v: 1, files: ['file'] },
    'manifest not an object': [1, 2, 3]
  }
  for (const [name, manifest] of Object.entries(cases)) {
    await assert.rejects(async () => lib.openManifest(keychain, await sealedB64(manifest)), /Unsupported manifest/, name)
  }
  // The well-formed one opens.
  const opened = await lib.openManifest(keychain, await sealedB64({ v: 1, files: [good(0), good(1)] }))
  assert.equal(opened.files.length, 2)
})

// ---------------------------------------------------------------------------
// Saving, exports, ZIP paths
// ---------------------------------------------------------------------------

test('the fallback download counts the bytes that arrive, not the size it was told', async (t) => {
  const saved = { document: globalThis.document, create: URL.createObjectURL, revoke: URL.revokeObjectURL }
  let created = null
  let revoked = null
  // The object URL is revoked after a minute; with real timers that minute
  // kept this test file open.
  t.mock.timers.enable({ apis: ['setTimeout'] })
  try {
    URL.createObjectURL = (blob) => { created = blob; return 'blob:test' }
    URL.revokeObjectURL = (url) => { revoked = url }
    globalThis.document = { createElement: () => ({ click () {}, remove () {} }), body: { append () {} } }
    const big = new Blob([Buffer.alloc(64, 0x51)]).stream()
    await assert.rejects(
      () => lib.saveStream(big, { filename: 'x.bin', size: 1, registration: null, inMemoryLimit: 8 }),
      (err) => err.code === 'TOO_LARGE_WITHOUT_WORKER')
    assert.equal(created, null, 'nothing was assembled')
    // Within the limit it still works.
    await lib.saveStream(new Blob([Buffer.alloc(8, 1)]).stream(), { filename: 'y.bin', size: 8, registration: null, inMemoryLimit: 8 })
    assert.equal(created.size, 8)
    t.mock.timers.tick(60 * 1000)
    assert.equal(revoked, 'blob:test', 'the object URL is released')
  } finally {
    t.mock.timers.reset()
    globalThis.document = saved.document
    URL.createObjectURL = saved.create
    URL.revokeObjectURL = saved.revoke
  }
})

test('the file encryption with a chosen salt is not reachable through the package', async () => {
  // The package imports itself by its own name, as an application would.
  const self = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).name
  await assert.rejects(() => import(`${self}/src/browser/ece.js`), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' })
  await assert.rejects(() => import(`${self}/src/browser/sealed.js`), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' })
  const api = await import(self)
  assert.equal(typeof api.createUpload, 'function')
  assert.equal(api.encryptStream, undefined, 'not part of the public API')
  assert.equal(typeof (await import(`${self}/server`)).parseTransferRecord, 'function')
})

test('a ZIP path that is only a folder still ends in the file\'s name', () => {
  assert.equal(lib.safeZipPath({ path: 'folder/subfolder', name: 'payload.pdf' }), 'folder/subfolder/payload.pdf')
  assert.equal(lib.safeZipPath({ path: 'folder/payload.pdf', name: 'payload.pdf' }), 'folder/payload.pdf')
  assert.equal(lib.safeZipPath({ path: '../../', name: '../x' }), '.._x')
})

test('Argon2id costs above the ceiling are refused on both sides, before deriving', async () => {
  const { parseKdfParams } = await import('../src/server/index.js')
  const top = { ...lib.KDF_DEFAULTS, m: 131072, t: 4, p: 4 }
  assert.deepEqual(parseKdfParams(top), top, 'the ceiling itself is accepted')
  const salt = new Uint8Array(crypto.randomBytes(16))
  for (const params of [{ ...top, m: 262144 }, { ...top, t: 5 }, { ...top, t: 10 }, { ...top, p: 5 }]) {
    assert.equal(parseKdfParams(params), null, JSON.stringify(params))
    const started = Date.now()
    await assert.rejects(() => lib.derivePasswordKeys('password-with-enough-letters', salt, params), /Unacceptable/, JSON.stringify(params))
    assert.ok(Date.now() - started < 200, 'refused before an Argon2id run')
  }
})
