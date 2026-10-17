// SPDX-License-Identifier: Apache-2.0
/**
 * test/take-key.test.js
 *
 * src/browser/take-key.js, run in a vm with a stand-in page: the key
 * leaves the address bar (and the history entry) before anything else runs,
 * and the page module gets it exactly once.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import vm from 'node:vm'

const SOURCE = fs.readFileSync(new URL('../src/browser/take-key.js', import.meta.url), 'utf8')

/** Runs take-key.js against a stand-in page at `url`. */
function run (url) {
  const location = new URL(url)
  const replaced = []
  const window = {}
  vm.runInNewContext(SOURCE, {
    window,
    location,
    history: {
      replaceState (_state, _title, next) {
        replaced.push(next)
        location.hash = new URL(next, location).hash
      }
    }
  })
  return { window, location, replaced }
}

test('the key is taken out of the address bar and handed over once', () => {
  const key = 'A'.repeat(43)
  const page = run(`https://files.example/t/2f1c3a4b-5d6e-4f70-8a9b-0c1d2e3f4a5b?x=1#${key}`)
  assert.deepEqual(page.replaced, ['/t/2f1c3a4b-5d6e-4f70-8a9b-0c1d2e3f4a5b?x=1'], 'no fragment in the new history entry')
  assert.equal(page.location.hash, '')
  assert.equal(page.window.__sealedKey(), key)
  assert.equal(page.window.__sealedKey(), null, 'only once')
})

test('without a fragment nothing is replaced and there is no key', () => {
  const page = run('https://files.example/t/x')
  assert.deepEqual(page.replaced, [])
  assert.equal(page.window.__sealedKey(), null)
})

test('the hand-over cannot be replaced by a later script', () => {
  const page = run('https://files.example/t/x#secret')
  // Non-writable: a module (strict mode) gets an error, the key stays put.
  assert.throws(() => { page.window.__sealedKey = () => 'forged' }, TypeError)
  assert.equal(page.window.__sealedKey(), 'secret')
})
