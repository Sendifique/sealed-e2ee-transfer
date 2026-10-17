// SPDX-License-Identifier: Apache-2.0
/**
 * test/example-server.test.js
 *
 * The example application's server (examples/basic/server.js) over HTTP,
 * without a browser: every route reaches its transfer, the reader token
 * gates the manifest and the files, a transfer is finalized once and only
 * complete, and the limits it shows hold — wrong passwords per transfer
 * within a window (broken requests cost nothing), bytes held and given
 * back by stalled uploads, the cap on transfers, requests from other sites. (The browser side: e2e/browser.test.js.)
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import * as lib from '../src/browser/index.js'
import { start } from '../examples/basic/server.js'

let server
let base

/** Small limits, so the tests reach them quickly. */
const WINDOW_MS = 2500
const MAX_FILE_BYTES = 250_000
const MAX_TOTAL_BYTES = 200_000
const IDLE_MS = 500

test.before(async () => {
  server = await start(0, {
    wrongPasswordWindowMs: WINDOW_MS, maxFileBytes: MAX_FILE_BYTES, maxTotalBytes: MAX_TOTAL_BYTES,
    uploadIdleMs: IDLE_MS
  })
  base = `http://127.0.0.1:${server.address().port}`
})
test.after(() => new Promise((resolve) => server.close(resolve)))

const post = (path, body) => fetch(base + path, {
  method: 'POST',
  headers: body ? { 'content-type': 'application/json' } : {},
  body: body ? JSON.stringify(body) : undefined
})

async function encrypted (keychain, bytes) {
  return Buffer.from(await new Response(await keychain.encryptStream(new Blob([bytes]).stream())).arrayBuffer())
}

/** A finalized transfer with one file; returns what a recipient needs. */
async function transfer ({ password = null } = {}) {
  const { id } = await (await post('/api/transfers')).json()
  const keychain = lib.createKeychain()
  const plain = Buffer.from('hello from the example')
  const cipher = await encrypted(keychain, plain)
  assert.equal((await fetch(`${base}/api/transfers/${id}/files/0`, { method: 'PUT', body: cipher })).status, 204)
  const record = await lib.serverRecord(keychain,
    await lib.sealManifest(keychain, { files: [{ name: 'hello.txt', size: plain.length, salt: lib.fileSalt(cipher) }] }))
  if (password) record.password = await lib.passwordBlock(keychain, password, `example-v1:${id}`)
  assert.equal((await post(`/api/transfers/${id}/finalize`, { ...record, fileCount: 1 })).status, 204)
  return { id, keychain, record, cipher }
}

test('every route reaches its transfer; the reader token gates manifest and files', async () => {
  const { id, keychain, record, cipher } = await transfer()
  const info = await (await fetch(`${base}/api/transfers/${id}/info`)).json()
  assert.equal(info.format, lib.FORMAT_VERSION)
  assert.deepEqual(info.sizes, [cipher.length])

  const wrong = crypto.randomBytes(16).toString('base64')
  assert.equal((await post(`/api/transfers/${id}/open`, { readerToken: wrong })).status, 403)
  assert.equal((await fetch(`${base}/api/transfers/${id}/files/0`)).status, 403, 'no token')
  assert.equal((await fetch(`${base}/api/transfers/${id}/files/0`, { headers: { 'x-reader-token': wrong } })).status, 403)

  const opened = await post(`/api/transfers/${id}/open`, { readerToken: record.readerToken })
  assert.equal(opened.status, 200)
  const manifest = await lib.openManifest(keychain, (await opened.json()).manifest)
  assert.equal(manifest.files[0].name, 'hello.txt')
  const file = await fetch(`${base}/api/transfers/${id}/files/0`, { headers: { 'x-reader-token': record.readerToken } })
  assert.ok(Buffer.from(await file.arrayBuffer()).equals(cipher))
})

test('a transfer is finalized once, only with JSON, and takes no files afterwards', async () => {
  const { id, record } = await transfer()
  assert.equal((await post(`/api/transfers/${id}/finalize`, { ...record, fileCount: 1 })).status, 409)
  const { id: other } = await (await post('/api/transfers')).json()
  const asText = await fetch(`${base}/api/transfers/${other}/finalize`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: JSON.stringify(record) })
  assert.equal(asText.status, 400)
  assert.equal((await fetch(`${base}/api/transfers/${id}/files/1`, { method: 'PUT', body: Buffer.alloc(40) })).status, 400)
})

test('plaintext and unknown transfers are refused', async () => {
  const { id } = await (await post('/api/transfers')).json()
  const res = await fetch(`${base}/api/transfers/${id}/files/0`, { method: 'PUT', body: Buffer.from('%PDF-1.7 not encrypted at all') })
  assert.equal(res.status, 400)
  assert.equal((await fetch(`${base}/api/transfers/${crypto.randomUUID()}/info`)).status, 404)
  assert.equal((await post('/api/other')).status, 404)
})

test('a transfer is finalized only when every announced file has arrived', async () => {
  const keychain = lib.createKeychain()
  const ciphers = [await encrypted(keychain, Buffer.from('one')), await encrypted(keychain, Buffer.from('two'))]
  const record = await lib.serverRecord(keychain, await lib.sealManifest(keychain, {
    files: ciphers.map((c, i) => ({ name: `f${i}`, size: 3, salt: lib.fileSalt(c) }))
  }))
  const { id } = await (await post('/api/transfers')).json()
  const finalize = (body) => post(`/api/transfers/${id}/finalize`, body).then(r => r.status)
  const put = (i) => fetch(`${base}/api/transfers/${id}/files/${i}`, { method: 'PUT', body: ciphers[i % 2] })

  assert.equal(await finalize({ ...record, fileCount: 2 }), 409, 'no file yet')
  assert.equal(await finalize(record), 409, 'no count')
  assert.equal((await put(1)).status, 204)
  assert.equal(await finalize({ ...record, fileCount: 2 }), 409, 'file 0 is missing')
  assert.equal((await put(0)).status, 204)
  assert.equal(await finalize({ ...record, fileCount: 1 }), 409, 'more files than announced')
  assert.equal(await finalize({ ...record, fileCount: '2' }), 409, 'not a number')
  assert.equal(await finalize({ ...record, fileCount: 2 }), 204)
})

test('uploads are refused beyond the size of a file and the bytes held overall', async () => {
  const { id } = await (await post('/api/transfers')).json()
  const put = (bytes) => fetch(`${base}/api/transfers/${id}/files/0`, { method: 'PUT', body: Buffer.alloc(bytes) })
  assert.equal((await put(MAX_FILE_BYTES + 1)).status, 413, 'larger than a file may be')
  assert.equal((await put(MAX_TOTAL_BYTES + 1)).status, 507, 'more than the server holds')
})

test('a broken unlock request costs no attempt', async () => {
  const { id, record } = await transfer({ password: 'correct horse battery staple' })
  for (let i = 0; i < 15; i++) {
    const asText = await fetch(`${base}/api/transfers/${id}/unlock`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: '{}' })
    assert.equal(asText.status, 400)
    assert.equal((await post(`/api/transfers/${id}/unlock`, { passwordAuth: 'short' })).status, 400)
  }
  assert.equal((await post(`/api/transfers/${id}/unlock`, { passwordAuth: record.password.passwordAuth })).status, 200)
})

test('requests that change something are refused from another site', async () => {
  const from = (headers) => fetch(`${base}/api/transfers`, { method: 'POST', headers }).then(r => r.status)
  assert.equal(await from({ origin: 'https://elsewhere.example' }), 403)
  assert.equal(await from({ 'sec-fetch-site': 'cross-site' }), 403)
  assert.equal(await from({ 'sec-fetch-site': 'same-site' }), 403)
  assert.equal(await from({ 'sec-fetch-site': 'same-origin', origin: 'https://ignored.example' }), 200)
  assert.equal(await from({ origin: base }), 200)
  assert.equal((await fetch(`${base}/api/transfers/${crypto.randomUUID()}/info`, { headers: { 'sec-fetch-site': 'cross-site' } })).status, 404, 'reading is not affected')
})

test('an upload that stops arriving gives its reserved bytes back', async () => {
  const { id } = await (await post('/api/transfers')).json()
  const { request } = await import('node:http')
  // Declares most of the budget (other tests hold a little), sends one
  // byte, then goes quiet.
  const stalled = request(`${base}/api/transfers/${id}/files/0`, {
    method: 'PUT', headers: { 'content-length': String(MAX_TOTAL_BYTES - 5000) }
  })
  stalled.on('error', () => {})
  stalled.write(Buffer.alloc(1))
  await new Promise((resolve) => setTimeout(resolve, 200))
  const blocked = await fetch(`${base}/api/transfers/${id}/files/1`, { method: 'PUT', body: Buffer.alloc(10_000) })
  assert.equal(blocked.status, 507, 'reserved while it is still arriving')
  await new Promise((resolve) => setTimeout(resolve, IDLE_MS + 300))
  const after = await fetch(`${base}/api/transfers/${id}/files/1`, { method: 'PUT', body: Buffer.alloc(10_000) })
  assert.equal(after.status, 400, 'budget free again (refused only as not encrypted)')
  stalled.destroy()
})

test('wrong passwords are limited per transfer; parallel guesses cannot overrun the limit', async () => {
  const { id, record } = await transfer({ password: 'correct horse battery staple' })
  const guesses = await Promise.all(Array.from({ length: 30 }, () =>
    post(`/api/transfers/${id}/unlock`, { passwordAuth: crypto.randomBytes(32).toString('base64') }).then(r => r.status)))
  assert.equal(guesses.filter(s => s === 403).length, 10, 'ten wrong guesses are answered')
  assert.equal(guesses.filter(s => s === 429).length, 20, 'the rest are refused')
  // Locked for now — even for the right proof (it would come from the browser).
  assert.ok(record.password.passwordAuth)
  const locked = await post(`/api/transfers/${id}/unlock`, { passwordAuth: record.password.passwordAuth })
  assert.equal(locked.status, 429)
  assert.ok(Number(locked.headers.get('retry-after')) >= 1, 'says when to try again')

  // But only for the window: whoever guessed cannot lock the recipients out
  // for the transfer's whole life.
  await new Promise((resolve) => setTimeout(resolve, WINDOW_MS + 100))
  assert.equal((await post(`/api/transfers/${id}/unlock`, { passwordAuth: record.password.passwordAuth })).status, 200)
})

test('the right password unlocks, and gives its attempt back', async () => {
  const { id, record } = await transfer({ password: 'correct horse battery staple' })
  for (let i = 0; i < 12; i++) {
    const res = await post(`/api/transfers/${id}/unlock`, { passwordAuth: record.password.passwordAuth })
    assert.equal(res.status, 200, `attempt ${i}`)
  }
})
