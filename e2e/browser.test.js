// SPDX-License-Identifier: Apache-2.0
/**
 * e2e/browser.test.js
 *
 * The whole way, in a real browser (Chromium, through Playwright), against
 * the example application (examples/basic/): choose files, encrypt and
 * upload them, open the link in a fresh page, download through the service
 * worker, and compare the saved bytes with the originals — for the link and
 * the password variant, for single files and the ZIP. Also: the key leaves
 * the address bar, the pages run under a strict Content-Security-Policy
 * without a single violation, and wrong keys, wrong passwords and an empty
 * password field are refused.
 *
 *     npx playwright install chromium   (once)
 *     npm run test:e2e
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import * as playwright from 'playwright'
import { start } from '../examples/basic/server.js'

/** Which engine: chromium (default), firefox or webkit — E2E_BROWSER. */
const BROWSER = process.env.E2E_BROWSER || 'chromium'

let server
let base
let browser

test.before(async () => {
  server = await start(0)
  base = `http://127.0.0.1:${server.address().port}`
  browser = await playwright[BROWSER].launch()
})

test.after(async () => {
  await browser?.close()
  await new Promise((resolve) => server.close(resolve))
})

const FILES = [
  { name: 'notes.txt', bytes: Buffer.from('Grüße aus dem Test. 🔒\n'.repeat(50)) },
  { name: 'data.bin', bytes: crypto.randomBytes(200 * 1024 + 7) }   // several records
]

/** A new browser context that records console errors (CSP violations among them). */
async function newContext () {
  const context = await browser.newContext({ acceptDownloads: true })
  context.errors = []
  context.on('page', (page) => {
    page.on('console', (msg) => { if (msg.type() === 'error') context.errors.push(msg.text()) })
    page.on('pageerror', (err) => context.errors.push(String(err)))
  })
  return context
}

/** Sends FILES from the example's send page; returns the link. */
async function send (context, password = null) {
  const page = await context.newPage()
  await page.goto(`${base}/`)
  await page.setInputFiles('#files', FILES.map(f => ({ name: f.name, mimeType: 'application/octet-stream', buffer: f.bytes })))
  if (password !== null) {
    await page.check('#use-password')
    await page.fill('#password', password)
  }
  await page.click('#send')
  await page.waitForSelector('#result:not([hidden])', { timeout: 60000 })
  const link = await page.textContent('#link')
  await page.close()
  return link
}

/** Clicks `selector` and returns the bytes of the download it starts. */
async function downloaded (page, selector) {
  const [download] = await Promise.all([page.waitForEvent('download', { timeout: 60000 }), page.click(selector)])
  return fs.readFileSync(await download.path())
}

/** Waits until the opened transfer lists its files. */
async function opened (page) {
  await page.waitForSelector('#content:not([hidden])', { timeout: 60000 })
  return page.$$eval('#files li', (items) => items.map(li => li.firstChild.textContent))
}

test('link variant: upload, open, download every file and the ZIP — byte for byte', async () => {
  const context = await newContext()
  try {
    const link = await send(context)
    assert.match(link, /^http:\/\/127\.0\.0\.1:\d+\/t\/[0-9a-f-]{36}#[A-Za-z0-9_-]{43}$/)

    const page = await context.newPage()
    await page.goto(link)
    const names = await opened(page)
    assert.deepEqual(names.map(n => n.split(' (')[0]), ['notes.txt', 'data.bin'])
    assert.equal(new URL(page.url()).hash, '', 'the key left the address bar')

    // The saver is the service worker, not the in-memory fallback.
    const state = await page.evaluate(async () => (await navigator.serviceWorker.getRegistration('/t/'))?.active?.state)
    assert.equal(state, 'activated')

    for (const [i, file] of FILES.entries()) {
      const bytes = await downloaded(page, `button[data-index="${i}"]`)
      assert.ok(bytes.equals(file.bytes), `${file.name}: identical`)
    }
    const zip = await downloaded(page, '#download-all')
    assert.equal(zip.readUInt32LE(0), 0x04034b50, 'a ZIP')
    for (const file of FILES) assert.ok(zip.includes(file.bytes), `${file.name} inside the ZIP (stored)`)

    assert.deepEqual(context.errors, [], 'no console errors, no CSP violations')
  } finally {
    await context.close()
  }
})

test('password variant: no key in the link; wrong password refused, right one opens', async () => {
  const context = await newContext()
  try {
    const password = 'correct horse battery staple'
    const link = await send(context, password)
    assert.doesNotMatch(link, /#/, 'no key in the link')

    const page = await context.newPage()
    await page.goto(link)
    await page.waitForSelector('#password-form:not([hidden])')
    await page.fill('#password', 'wrong horse battery staple')
    await page.click('#unlock')
    await page.waitForFunction(() => document.getElementById('status').textContent === 'Wrong password.', null, { timeout: 60000 })

    await page.fill('#password', password)
    await page.click('#unlock')
    await opened(page)
    const bytes = await downloaded(page, 'button[data-index="1"]')
    assert.ok(bytes.equals(FILES[1].bytes))

    // The wrong attempt above logged a 403 for the unlock request; nothing else.
    assert.deepEqual(context.errors.filter(e => !/403/.test(e)), [])
  } finally {
    await context.close()
  }
})

test('a link with another key does not open the transfer', async () => {
  const context = await newContext()
  try {
    const link = await send(context)
    const forged = link.replace(/#.*$/, '#' + crypto.randomBytes(32).toString('base64url'))
    const page = await context.newPage()
    await page.goto(forged)
    await page.waitForFunction(() => document.getElementById('status').textContent.includes('does not open'), null, { timeout: 60000 })
    assert.equal(await page.isHidden('#content'), true)
  } finally {
    await context.close()
  }
})

test('an empty password field is an error, not a link with the key', async () => {
  const context = await newContext()
  try {
    const page = await context.newPage()
    await page.goto(`${base}/`)
    await page.setInputFiles('#files', [{ name: 'a.txt', mimeType: 'text/plain', buffer: Buffer.from('a') }])
    await page.check('#use-password')
    // The page suggests a generated passphrase; whoever clears it gets an
    // error, not the link variant.
    assert.match(await page.inputValue('#password'), /^[a-z0-9]{4}(-[a-z0-9]{4}){4}$/)
    await page.fill('#password', '')
    await page.click('#send')
    await page.waitForFunction(() => /at least 12/.test(document.getElementById('status').textContent))
    assert.equal(await page.isHidden('#result'), true, 'no link was made')
  } finally {
    await context.close()
  }
})
