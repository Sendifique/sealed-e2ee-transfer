// SPDX-License-Identifier: Apache-2.0
/**
 * test/ece.test.js
 *
 * The file encryption (src/browser/ece.js) refuses every way a stored file can
 * be tampered with — and works whatever the chunking of the stream. The
 * positive side, byte for byte, is in test/vectors.test.js.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { encryptStream, decryptStream } from '../src/browser/ece.js'

const RS = 65536
const HEADER = 21

const mainKey = await globalThis.crypto.subtle.importKey('raw', crypto.randomBytes(32), 'HKDF', false, ['deriveBits', 'deriveKey'])

/** A stream of `bytes` in pieces of `size` (default: one piece). */
function streamOf (bytes, size = bytes.length || 1) {
  return new ReadableStream({
    start (controller) {
      for (let o = 0; o < bytes.length; o += size) controller.enqueue(new Uint8Array(bytes.subarray(o, o + size)))
      controller.close()
    }
  })
}

const collect = async (stream) => Buffer.from(await new Response(stream).arrayBuffer())
const encrypt = (plain, size) => collect(encryptStream(streamOf(plain, size), mainKey))
const decrypt = (cipher, size) => collect(decryptStream(streamOf(cipher, size), mainKey))

test('round trip, whatever the chunking on either side', async () => {
  // Several records, in pieces around the record size.
  const plain = crypto.randomBytes(3 * (RS - 17) + 1234)
  for (const size of [4093, RS - 18, RS - 17, RS - 16, RS, RS + 1, plain.length]) {
    const cipher = await encrypt(plain, size)
    assert.ok((await decrypt(cipher, 997)).equals(plain), `encrypted in pieces of ${size}`)
    assert.ok((await decrypt(cipher, RS + 3)).equals(plain), `decrypted in large pieces (${size})`)
  }
  // Tiny pieces: byte by byte through the header and a short record, and in
  // 7-byte pieces across a record boundary. (Kept small: Node's web streams
  // cost ~50 µs per piece; real files arrive in pieces of many kilobytes.)
  const short = crypto.randomBytes(300)
  assert.ok((await decrypt(await encrypt(short, 1), 1)).equals(short), 'single bytes')
  const across = crypto.randomBytes(RS - 17 + 300)
  assert.ok((await decrypt(await encrypt(across, 7), 7)).equals(across), '7-byte pieces across a record boundary')
})

test('an empty file is its header alone, and decrypts to nothing only when allowed', async () => {
  const cipher = await encrypt(Buffer.alloc(0))
  assert.equal(cipher.length, HEADER)
  const allowed = await collect(decryptStream(streamOf(cipher), mainKey, { allowEmpty: true }))
  assert.equal(allowed.length, 0)
  // Without the manifest's word for it, a bare header proves nothing.
  await assert.rejects(() => decrypt(cipher), /bare header/)
})

test('a file cut down to its header is refused — under the right key or any other', async () => {
  const cipher = await encrypt(crypto.randomBytes(90_000))
  const otherKey = await globalThis.crypto.subtle.importKey('raw', crypto.randomBytes(32), 'HKDF', false, ['deriveBits', 'deriveKey'])
  for (const key of [mainKey, otherKey]) {
    await assert.rejects(() => collect(decryptStream(streamOf(cipher.subarray(0, HEADER)), key)), /bare header/)
  }
})

test('a missing or foreign header is refused', async () => {
  const cipher = await encrypt(crypto.randomBytes(100))
  await assert.rejects(() => decrypt(Buffer.alloc(0)), /before its header/, 'nothing at all')
  await assert.rejects(() => decrypt(cipher.subarray(0, 20)), /before its header/, 'cut inside the header')
  const otherRs = Buffer.from(cipher); otherRs.writeUInt32BE(4096, 16)
  await assert.rejects(() => decrypt(otherRs), /record size/)
  const keyId = Buffer.from(cipher); keyId[20] = 1
  await assert.rejects(() => decrypt(keyId), /Key ids/)
})

test('tampering with any record fails authentication', async () => {
  const cipher = await encrypt(crypto.randomBytes(2 * (RS - 17) + 50))
  for (const at of [HEADER, HEADER + 100, HEADER + RS + 5, cipher.length - 1]) {
    const flipped = Buffer.from(cipher); flipped[at] ^= 1
    await assert.rejects(() => decrypt(flipped), `byte ${at} flipped`)
  }
  const otherSalt = Buffer.from(cipher); otherSalt[0] ^= 1
  await assert.rejects(() => decrypt(otherSalt), 'header salt changed: other keys')
})

test('cut at a record boundary, records swapped or dropped: refused', async () => {
  const cipher = await encrypt(crypto.randomBytes(2 * (RS - 17) + 50))   // three records
  const r0 = cipher.subarray(HEADER, HEADER + RS)
  const r1 = cipher.subarray(HEADER + RS, HEADER + 2 * RS)
  const r2 = cipher.subarray(HEADER + 2 * RS)
  const head = cipher.subarray(0, HEADER)
  await assert.rejects(() => decrypt(Buffer.concat([head, r0])), /before its last record/, 'last records cut off')
  await assert.rejects(() => decrypt(Buffer.concat([head, r0, r1])), /before its last record/, 'last record cut off')
  await assert.rejects(() => decrypt(Buffer.concat([head, r1, r0, r2])), 'records swapped')
  await assert.rejects(() => decrypt(Buffer.concat([head, r0, r2])), 'a record dropped')
  await assert.rejects(() => decrypt(Buffer.concat([head, r0, r1, r2.subarray(0, 10)])), /too short/, 'last record cut short')
  await assert.rejects(() => decrypt(Buffer.concat([cipher, Buffer.alloc(1)])), 'a byte appended')
})

test('a salt of the wrong length is refused', () => {
  assert.throws(() => encryptStream(streamOf(Buffer.from('x')), mainKey, new Uint8Array(15)), /salt/)
})
