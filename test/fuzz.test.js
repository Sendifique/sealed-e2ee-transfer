// SPDX-License-Identifier: Apache-2.0
/**
 * test/fuzz.test.js
 *
 * Randomised cases on top of the hand-written ones, in four classes:
 *   - streaming: any plaintext, cut into any pieces on either side,
 *     decrypts to exactly itself;
 *   - manipulation: a ciphertext with one bit flipped, cut off, extended,
 *     with records swapped, dropped, repeated or taken from another file,
 *     or with its header changed is refused — never a different or shorter
 *     plaintext;
 *   - edge cases: a wrong key, a wrong size or salt in the manifest entry;
 *   - the manifest: one changed or missing byte is refused.
 * Sizes are drawn around the record boundaries, where mistakes live.
 *
 * Reproducible: every case follows from FUZZ_SEED (random when unset, and
 * then printed). A failure names its seed and case; run it again with
 *     FUZZ_SEED=<seed> npm test
 * FUZZ_CASES sets the number of cases per class (default 50; the weekly
 * workflow runs 2500 per class).
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import * as lib from '../src/browser/index.js'
import { encryptStream } from '../src/browser/ece.js'
import { HEADER_LENGTH, RECORD_SIZE, RECORD_OVERHEAD, ciphertextSize } from '../src/format.js'

const CASES = Number(process.env.FUZZ_CASES) || 50
const SEED = Number(process.env.FUZZ_SEED) || crypto.randomInt(1, 2 ** 31)
const CHUNK = RECORD_SIZE - RECORD_OVERHEAD

test(`fuzz seed ${SEED}, ${CASES} cases per class`, (t) => {
  t.diagnostic(`FUZZ_SEED=${SEED}`)
})

// ---------------------------------------------------------------------------
// Deterministic randomness
// ---------------------------------------------------------------------------

/** mulberry32: small, fast, good enough to pick cases (not for keys). */
function rng (seed) {
  let a = seed >>> 0
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0
    let x = a
    x = Math.imul(x ^ (x >>> 15), x | 1)
    x ^= x + Math.imul(x ^ (x >>> 7), x | 61)
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296
  }
  const int = (n) => Math.floor(next() * n)
  return {
    int,
    pick: (list) => list[int(list.length)],
    /** n bytes, expanded from the stream with AES-CTR — fast and repeatable. */
    bytes (n) {
      const key = Buffer.alloc(32)
      for (let i = 0; i < 32; i++) key[i] = int(256)
      return crypto.createCipheriv('aes-256-ctr', key, Buffer.alloc(16)).update(Buffer.alloc(n))
    }
  }
}

/** The random source of one case of one class. */
const caseRng = (cls, i) => rng(SEED ^ Math.imul(cls + 1, 0x9e3779b1) ^ Math.imul(i + 1, 0x85ebca6b))

/** A plaintext length, mostly at or around a record boundary. */
function size (r) {
  if (r.int(3) === 0) return r.int(3 * CHUNK + 5000)
  return Math.max(0, r.pick([0, 1, 2, CHUNK, 2 * CHUNK, 3 * CHUNK]) + r.pick([-2, -1, 0, 0, 1, 2]))
}

/** `bytes` as a stream of random pieces — at most about 200 of them. */
function pieces (r, bytes) {
  const min = Math.max(1, Math.ceil(bytes.length / 200))
  const mode = r.int(3)
  const fixed = Math.max(min, r.pick([1, 7, 4096, CHUNK, RECORD_SIZE, RECORD_SIZE + 1, 3 * RECORD_SIZE]))
  const parts = []
  for (let o = 0; o < bytes.length;) {
    const n = mode === 0 ? bytes.length : mode === 1 ? fixed : min + r.int(2 * RECORD_SIZE)
    parts.push(new Uint8Array(bytes.subarray(o, o + n)))
    o += n
  }
  return new ReadableStream({
    start (controller) {
      for (const p of parts) controller.enqueue(p)
      controller.close()
    }
  })
}

const collect = async (stream) => Buffer.from(await new Response(stream).arrayBuffer())

/** A key chain and its HKDF key, both from the case's randomness. */
async function keys (r) {
  const key = new Uint8Array(r.bytes(32))
  const keychain = lib.openKeychain(key, r.bytes(16).toString('base64'))
  const mainKey = await globalThis.crypto.subtle.importKey('raw', key, 'HKDF', false, ['deriveBits', 'deriveKey'])
  return { keychain, mainKey }
}

/** A ciphertext of `plain` with the file salt the case chose. */
async function encrypt (r, mainKey, plain) {
  const salt = new Uint8Array(r.bytes(16))
  const cipher = await collect(encryptStream(pieces(r, plain), mainKey, salt))
  return { cipher, entry: { size: plain.length, salt: Buffer.from(salt).toString('base64') } }
}

const opened = (r, keychain, cipher, entry) => lib.decryptedFile(keychain, pieces(r, cipher), entry).then(collect)
const where = (i) => `seed ${SEED}, case ${i}`

// ---------------------------------------------------------------------------

test('streaming: any plaintext, in any pieces on either side, round-trips', async () => {
  for (let i = 0; i < CASES; i++) {
    const r = caseRng(0, i)
    const { keychain, mainKey } = await keys(r)
    const plain = r.bytes(size(r))
    const { cipher, entry } = await encrypt(r, mainKey, plain)
    assert.equal(cipher.length, ciphertextSize(plain.length), where(i))
    assert.ok((await opened(r, keychain, cipher, entry)).equals(plain), where(i))
    const raw = await keychain.decryptStream(pieces(r, cipher), { allowEmpty: plain.length === 0 })
    assert.ok((await collect(raw)).equals(plain), `${where(i)}: raw`)
  }
})

/** The records of a ciphertext, after its header. */
function records (cipher) {
  const list = []
  for (let o = HEADER_LENGTH; o < cipher.length; o += RECORD_SIZE) list.push(cipher.subarray(o, o + RECORD_SIZE))
  return list
}

/**
 * One random change that makes the ciphertext differ from the original.
 * `other` is another file's ciphertext under the same key.
 */
function mutate (r, cipher, other) {
  const head = cipher.subarray(0, HEADER_LENGTH)
  const recs = records(cipher)
  const kinds = ['flip', 'flip', 'truncate', 'append', 'header']
  if (recs.length >= 2) kinds.push('swap', 'drop')
  if (recs.length >= 1) kinds.push('repeat', 'foreign')
  const kind = r.pick(kinds)
  switch (kind) {
    case 'flip': {
      const out = Buffer.from(cipher)
      out[r.int(out.length)] ^= 1 + r.int(255)
      return { kind, out }
    }
    case 'header': {
      const out = Buffer.from(cipher)
      out[r.int(HEADER_LENGTH)] ^= 1 + r.int(255)
      return { kind, out }
    }
    case 'truncate':
      return { kind, out: cipher.subarray(0, r.int(cipher.length)) }
    case 'append':
      return { kind, out: Buffer.concat([cipher, r.bytes(1 + r.int(40))]) }
    case 'swap': {
      const a = r.int(recs.length - 1)
      const list = [...recs]
      ;[list[a], list[a + 1]] = [list[a + 1], list[a]]
      return { kind, out: Buffer.concat([head, ...list]) }
    }
    case 'drop': {
      const list = [...recs]
      list.splice(r.int(list.length), 1)
      return { kind, out: Buffer.concat([head, ...list]) }
    }
    case 'repeat': {
      const list = [...recs]
      const at = r.int(list.length)
      list.splice(at, 0, list[at])
      return { kind, out: Buffer.concat([head, ...list]) }
    }
    case 'foreign': {
      // A record of another file of the same transfer, at the same place.
      const theirs = records(other)
      const list = [...recs]
      const at = r.int(list.length)
      list[at] = theirs[Math.min(at, theirs.length - 1)]
      return { kind, out: Buffer.concat([head, ...list]) }
    }
  }
}

test('manipulation: any change to a ciphertext is refused', async () => {
  for (let i = 0; i < CASES; i++) {
    const r = caseRng(1, i)
    const { keychain, mainKey } = await keys(r)
    const plain = r.bytes(size(r))
    const { cipher, entry } = await encrypt(r, mainKey, plain)
    const { cipher: other } = await encrypt(r, mainKey, r.bytes(Math.max(1, size(r))))
    const { kind, out } = mutate(r, cipher, other)
    assert.equal(out.equals(cipher), false, `${where(i)}: ${kind} changed nothing`)
    await assert.rejects(() => opened(r, keychain, out, entry), `${where(i)}: ${kind} accepted`)
    // The raw decryptor alone, without the manifest's checks, refuses it too.
    await assert.rejects(async () => collect(await keychain.decryptStream(pieces(r, out))), `${where(i)}: ${kind} accepted raw`)
  }
})

test('edge cases: a wrong key, size or salt is refused', async () => {
  for (let i = 0; i < CASES; i++) {
    const r = caseRng(2, i)
    const { keychain, mainKey } = await keys(r)
    const { keychain: wrong } = await keys(r)
    const plain = r.bytes(size(r))
    const { cipher, entry } = await encrypt(r, mainKey, plain)
    if (plain.length > 0) {
      await assert.rejects(() => opened(r, wrong, cipher, entry), `${where(i)}: wrong key`)
      await assert.rejects(() => opened(r, keychain, cipher, { ...entry, size: plain.length - 1 }), `${where(i)}: size - 1`)
    }
    await assert.rejects(() => opened(r, keychain, cipher, { ...entry, size: plain.length + 1 }), `${where(i)}: size + 1`)
    await assert.rejects(() => opened(r, keychain, cipher, { ...entry, salt: r.bytes(16).toString('base64') }), `${where(i)}: other salt`)
  }
})

test('manifest: one changed or missing byte is refused', async () => {
  for (let i = 0; i < CASES; i++) {
    const r = caseRng(3, i)
    const { keychain } = await keys(r)
    const files = Array.from({ length: 1 + r.int(5) }, (_, n) => ({
      name: `f${n}-${r.bytes(4).toString('hex')}.bin`, size: r.int(1e6), salt: r.bytes(16).toString('base64')
    }))
    const sealed = Buffer.from(await lib.sealManifest(keychain, { files }))
    const back = await lib.openManifest(keychain, sealed.toString('base64'))
    assert.deepEqual(back.files.map(f => [f.name, f.size, f.salt]), files.map(f => [f.name, f.size, f.salt]), where(i))
    const changed = Buffer.from(sealed)
    changed[r.int(changed.length)] ^= 1 + r.int(255)
    const cut = sealed.subarray(0, r.int(sealed.length))
    for (const bad of [changed, cut]) {
      await assert.rejects(() => lib.openManifest(keychain, bad.toString('base64')), where(i))
    }
  }
})
