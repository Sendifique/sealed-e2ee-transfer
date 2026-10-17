// SPDX-License-Identifier: Apache-2.0
/**
 * test/save.test.js
 *
 * The parts of src/browser/save.js that run without a browser: names from a
 * (sender-controlled) manifest are made safe to save under, and a ZIP of
 * decrypted files has exactly the predicted length. Also the base64 helpers
 * every binary value of the protocol goes through.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { safeFileName, safeZipPath, makeZip, predictZipLength, encodeBase64, decodeBase64 } from '../src/browser/index.js'

test('file names: no folders, no control characters, nothing that is only dots', () => {
  assert.equal(safeFileName('report.pdf'), 'report.pdf')
  assert.equal(safeFileName('../../etc/passwd'), '.._.._etc_passwd')
  assert.equal(safeFileName('a\\b:c\u0000d\u001f'), 'a_b_c_d_')
  assert.equal(safeFileName('..'), 'file')
  assert.equal(safeFileName('   '), 'file')
  assert.equal(safeFileName(null, 'download'), 'download')
  assert.equal(safeFileName('x'.repeat(300)).length, 255)
  assert.equal(safeFileName('a\uD800b'), 'a�b', 'a lone surrogate cannot break the name')
})

test('file names: no hidden direction, no Windows device names, no trailing dots', () => {
  // "invoice\u202Efdp.exe" would display as "invoiceexe.pdf".
  assert.equal(safeFileName('invoice\u202Efdp.exe'), 'invoicefdp.exe')
  assert.equal(safeFileName('a\u2066b\u2069\u200Ec\u061C'), 'abc')
  assert.equal(safeFileName('\u202E'), 'file', 'nothing left')
  assert.equal(safeFileName('\u{1F468}\u200D\u{1F469}\u200D\u{1F467}.png'), '\u{1F468}\u200D\u{1F469}\u200D\u{1F467}.png', 'emoji keep their joiners')
  for (const name of ['CON', 'con', 'nul.txt', 'COM1', 'lpt9.log', 'AUX.tar.gz', 'COM¹']) {
    assert.equal(safeFileName(name), `_${name}`, name)
  }
  for (const name of ['CONSOLE.txt', 'nullable', 'com10', 'a.con']) assert.equal(safeFileName(name), name, name)
  assert.equal(safeFileName('report. . .'), 'report')
  assert.equal(safeFileName('...'), 'file')
})

test('file names: nothing Windows refuses, a safe fallback, no half characters', () => {
  assert.equal(safeFileName('a?b<c>d"e|f*g.txt'), 'a_b_c_d_e_f_g.txt')
  assert.equal(safeFileName('', '../../exfil.txt'), '.._.._exfil.txt', 'the fallback is made safe too')
  assert.equal(safeFileName('', 'CON'), '_CON')
  assert.equal(safeFileName('', ''), 'file')
  const emoji = safeFileName('\u{1F600}'.repeat(128))
  assert.equal(emoji.length, 254, 'cut before the last whole emoji')
  assert.ok(emoji.isWellFormed())
  assert.equal(safeFileName('x'.repeat(254) + '\u{1F600}'), 'x'.repeat(254))
  assert.equal(safeZipPath({ path: 'a?/b*/c.txt', name: 'c.txt' }), 'a_/b_/c.txt')
})

test('ZIP paths: relative, no "..", no empty parts', () => {
  assert.equal(safeZipPath({ path: 'Belege/2026/scan.png', name: 'scan.png' }), 'Belege/2026/scan.png')
  assert.equal(safeZipPath({ path: '../../../evil.sh', name: 'evil.sh' }), 'evil.sh')
  assert.equal(safeZipPath({ path: '/abs//dir\\x.txt', name: 'x.txt' }), 'abs/dir/x.txt')
  assert.equal(safeZipPath({ path: 'a/./b:c', name: 'b:c' }), 'a/b_c')
  assert.equal(safeZipPath({ path: null, name: 'only.txt' }), 'only.txt')
  assert.equal(safeZipPath({ path: '../..', name: '..' }), 'file')
  assert.equal(safeZipPath({ path: 'CON/a\u202Eb/x.txt', name: 'x.txt' }), '_CON/ab/x.txt', 'folders get the same rules')
})

test('a ZIP of streamed files has exactly the predicted length', async () => {
  const files = [crypto.randomBytes(1000), crypto.randomBytes(70000), Buffer.alloc(0)]
  const entries = files.map((f, i) => ({ name: `dir/f${i}.bin`, size: f.length }))
  const length = Number(predictZipLength(entries))
  async function * inputs () {
    for (let i = 0; i < files.length; i++) {
      yield { name: entries[i].name, size: files[i].length, lastModified: new Date(0), input: new Blob([files[i]]).stream() }
    }
  }
  const zip = Buffer.from(await new Response(makeZip(inputs(), { length })).arrayBuffer())
  assert.equal(zip.length, length)
  assert.equal(zip.readUInt32LE(0), 0x04034b50, 'local file header')
})

test('base64 helpers: standard, padded, round trip', () => {
  for (const len of [0, 1, 2, 3, 16, 32, 70000]) {
    const bytes = crypto.randomBytes(len)
    const encoded = encodeBase64(new Uint8Array(bytes))
    assert.equal(encoded, bytes.toString('base64'))
    assert.deepEqual(Buffer.from(decodeBase64(encoded)), bytes)
  }
})
