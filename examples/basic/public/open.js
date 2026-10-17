// SPDX-License-Identifier: Apache-2.0
/**
 * examples/basic/public/open.js
 *
 * The opening page: takes the key (from the link, or by unwrapping it with
 * the password), opens the manifest, lists the files and saves them —
 * decrypted as they stream, through the service worker. Every check of
 * PROTOCOL.md §6 happens in the library; this page only has to compare the
 * stored sizes with the manifest before downloading.
 *
 * take-key.js ran before this module and took the key out of the
 * address bar; window.__sealedKey() hands it over once.
 */

import {
  FORMAT_VERSION, openKeychain, openManifest, readerToken, decryptedFile, ciphertextSize,
  derivePasswordKeys, unwrapKey, encodeBase64, decodeBase64,
  registerSaver, saveStream, safeFileName, safeZipPath, makeZip, predictZipLength
} from '/lib/browser/index.js'

const $ = (id) => document.getElementById(id)
const id = location.pathname.split('/')[2]
const linkKey = window.__sealedKey()
const saver = registerSaver('/t/sw.js', '/t/')

let info = null
let keychain = null
let token = null
let manifest = null

function status (text, isError = false) {
  $('status').textContent = text
  $('status').classList.toggle('error', isError)
}

async function api (method, path, body, headers = {}) {
  return fetch(`/api/transfers/${id}${path}`, {
    method,
    headers: body ? { 'content-type': 'application/json', ...headers } : headers,
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'omit',
    cache: 'no-store'
  })
}

async function start () {
  const res = await api('GET', '/info')
  if (!res.ok) return status('This transfer does not exist.', true)
  info = await res.json()
  if (info.format !== FORMAT_VERSION) return status('This transfer uses a format this page does not know.', true)

  if (info.password) {
    $('password-form').hidden = false
    $('password').focus()
    return
  }
  if (!linkKey) return status('The link is incomplete: the key after # is missing.', true)
  await open(linkKey)
}

async function open (key) {
  keychain = openKeychain(key, info.salt)
  token = await readerToken(keychain)
  const res = await api('POST', '/open', { readerToken: token })
  if (!res.ok) return status('This key does not open the transfer.', true)
  manifest = await openManifest(keychain, (await res.json()).manifest)

  const list = $('files')
  list.textContent = ''
  for (const file of manifest.files) {
    const item = document.createElement('li')
    // Sender-controlled text: textContent, never HTML.
    item.textContent = `${file.path || file.name} (${file.size} bytes) `
    const button = document.createElement('button')
    button.type = 'button'
    button.textContent = 'Download'
    button.dataset.index = String(file.i)
    button.addEventListener('click', () => download([file]))
    item.append(button)
    list.append(item)
  }
  $('content').hidden = false
  status(`${manifest.files.length} file(s).`)
}

$('password-form').addEventListener('submit', async (event) => {
  event.preventDefault()
  status('Checking the password …')
  try {
    // Refuses cheap or foreign Argon2id parameters before using the password.
    const { wrapKey, passwordAuth } = await derivePasswordKeys(
      $('password').value, decodeBase64(info.kdf.salt), info.kdf.params)
    const res = await api('POST', '/unlock', { passwordAuth: encodeBase64(passwordAuth) })
    if (res.status === 429) return status('Too many wrong passwords.', true)
    if (!res.ok) return status('Wrong password.', true)
    const key = await unwrapKey(wrapKey, (await res.json()).wrappedKey, `example-v1:${id}`)
    $('password-form').hidden = true
    await open(key)
  } catch (err) {
    status(`Could not unlock: ${err.message}`, true)
  }
})

async function plaintextOf (file) {
  const res = await api('GET', `/files/${file.i}`, undefined, { 'x-reader-token': token })
  if (!res.ok || !res.body) throw new Error(`file ${file.i}: ${res.status}`)
  // Checks the salt (no swapped files) and the exact size as it streams.
  return decryptedFile(keychain, res.body, file)
}

async function download (files) {
  try {
    // Stored sizes must match the manifest before anything is fetched.
    for (const file of files) {
      if (info.sizes[file.i] !== ciphertextSize(file.size)) throw new Error('stored file does not match the manifest')
    }
    status('Downloading …')
    const registration = await saver
    if (files.length === 1) {
      const [file] = files
      await saveStream(await plaintextOf(file), { filename: safeFileName(file.name), size: file.size, registration })
    } else {
      const entries = files.map(f => ({ name: safeZipPath(f), size: f.size }))
      const length = Number(predictZipLength(entries))
      async function * inputs () {
        for (const [n, file] of files.entries()) {
          yield { name: entries[n].name, size: file.size, lastModified: new Date(), input: await plaintextOf(file) }
        }
      }
      await saveStream(makeZip(inputs(), { length }), { filename: 'files.zip', size: length, registration })
    }
    status('Done.')
  } catch (err) {
    status(`Download failed: ${err.message}`, true)
  }
}

$('download-all').addEventListener('click', () => manifest && download(manifest.files))
start().catch((err) => status(`Failed: ${err.message}`, true))
