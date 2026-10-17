// SPDX-License-Identifier: Apache-2.0
/**
 * src/browser/save.js
 *
 * Saving decrypted files as ordinary browser downloads — of any size.
 *
 * With the service worker (sw.js) registered, the plaintext streams straight
 * to disk: the page hands chunks to the worker, which answers a download
 * request with them, one chunk per request (backpressure), so nothing is
 * collected in memory. Without a service worker (some private-browsing
 * modes, old browsers) a file up to a limit is assembled in memory instead.
 *
 * Also: making file names and folder paths from a (sender-controlled)
 * manifest safe to save under.
 *
 * Errors carry a `code` for the page to turn into its own text:
 *   SAVE_FAILED                 the worker never served, or reported an error
 *   SAVE_CANCELLED              the user or the browser aborted the download
 *   TOO_LARGE_WITHOUT_WORKER    no service worker, and the file is over the limit
 */

/**
 * Several decrypted files as one ZIP stream (store-only, ZIP64), built as
 * the files stream in — from client-zip:
 *
 *     const entries = files.map(f => ({ name: safeZipPath(f), size: f.size }))
 *     const length = Number(predictZipLength(entries))
 *     const zip = makeZip(inputs, { length })   // inputs: async iterable of
 *                                               // { name, size, lastModified, input }
 *     await saveStream(zip, { filename: 'files.zip', size: length, registration })
 */
export { makeZip, predictLength as predictZipLength } from 'client-zip'

/** Largest file assembled in memory when no service worker is available. */
export const IN_MEMORY_LIMIT = 1024 * 1024 * 1024

/**
 * Registers the service worker and resolves once it is active — or with null
 * where service workers are unavailable or refused. Register early: by the
 * time a download starts, the worker is ready.
 *
 * @param {string} scriptUrl - where sw.js is served, e.g. '/t/sw.js'
 * @param {string} scope - e.g. '/t/'; downloads go through '<scope>_dl/<id>'
 * @returns {Promise<ServiceWorkerRegistration|null>}
 */
export async function registerSaver (scriptUrl, scope) {
  if (!('serviceWorker' in navigator)) return null
  try {
    await navigator.serviceWorker.register(scriptUrl, { scope })
    return await navigator.serviceWorker.ready
  } catch {
    return null
  }
}

/**
 * Saves a plaintext stream as a download.
 *
 * @param {ReadableStream<Uint8Array>} stream
 * @param {object} options
 * @param {string} options.filename - already made safe (safeFileName)
 * @param {number} options.size - bytes, for the browser's progress display
 * @param {ServiceWorkerRegistration|null} options.registration - from registerSaver()
 * @param {number} [options.inMemoryLimit]
 * @param {() => void} [options.onFallback] - called when saving without the worker
 * @returns {Promise<void>} resolves when the last chunk has been handed over
 * @throws {Error} with a `code` (see above)
 */
export async function saveStream (stream, { filename, size, registration, inMemoryLimit = IN_MEMORY_LIMIT, onFallback }) {
  if (registration?.active) return saveViaWorker(registration, stream, filename, size)
  onFallback?.()
  if (size > inMemoryLimit) {
    stream.cancel().catch(() => {})
    throw coded('TOO_LARGE_WITHOUT_WORKER')
  }
  // The declared size is only a first check: the bytes that actually arrive
  // are counted, so a stream longer than announced cannot get past the
  // memory limit.
  const chunks = []
  let received = 0
  const reader = stream.getReader()
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    received += value.byteLength
    if (received > inMemoryLimit) {
      reader.cancel().catch(() => {})
      throw coded('TOO_LARGE_WITHOUT_WORKER')
    }
    chunks.push(value)
  }
  const url = URL.createObjectURL(new Blob(chunks, { type: 'application/octet-stream' }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.append(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 60 * 1000)
}

/**
 * Streams through the service worker: registers the download with it, then
 * opens '<scope>_dl/<id>' in a hidden frame, which the worker answers with
 * the chunks this side hands over on request.
 *
 * @param {ServiceWorkerRegistration} registration
 * @param {ReadableStream<Uint8Array>} stream
 * @param {string} filename
 * @param {number} size
 * @returns {Promise<void>}
 */
function saveViaWorker (registration, stream, filename, size) {
  const worker = registration.active
  const id = toBase64Url(crypto.getRandomValues(new Uint8Array(18)))
  const channel = new MessageChannel()
  const reader = stream.getReader()
  return new Promise((resolve, reject) => {
    let frame = null
    let settled = false
    // Keeps the worker alive while a long download streams (see sw.js).
    const keepAlive = setInterval(() => worker.postMessage({ type: 'ping' }), 10 * 1000)
    // If the worker never starts serving (restarted, refused the download),
    // fail instead of waiting forever. Reset by every chunk it asks for.
    // Generous, because a browser set to "ask where to save" waits for the
    // user before it requests the first chunk.
    let watchdog = null
    const arm = () => {
      clearTimeout(watchdog)
      watchdog = setTimeout(() => finish(coded('SAVE_FAILED')), 5 * 60 * 1000)
    }
    const finish = (err) => {
      if (settled) return
      settled = true
      clearInterval(keepAlive)
      clearTimeout(watchdog)
      setTimeout(() => frame?.remove(), 30 * 1000)
      if (err) reader.cancel().catch(() => {})
      err ? reject(err) : resolve()
    }
    arm()
    channel.port1.onmessage = async (event) => {
      const type = event.data?.type
      if (type !== 'registered') arm()
      if (type === 'registered') {
        frame = document.createElement('iframe')
        frame.hidden = true
        frame.src = new URL(`_dl/${id}`, registration.scope).href
        document.body.append(frame)
      } else if (type === 'pull') {
        try {
          const { done, value } = await reader.read()
          if (done) {
            channel.port1.postMessage({ type: 'end' })
            finish()
          } else {
            const copy = value.slice()
            channel.port1.postMessage({ type: 'chunk', chunk: copy.buffer }, [copy.buffer])
          }
        } catch (err) {
          channel.port1.postMessage({ type: 'error' })
          finish(err)
        }
      } else if (type === 'cancel') {
        finish(coded('SAVE_CANCELLED'))
      } else if (type === 'error') {
        finish(coded('SAVE_FAILED'))
      }
    }
    worker.postMessage({ type: 'register', id, filename, size }, [channel.port2])
  })
}

// ---------------------------------------------------------------------------
// Safe names
// ---------------------------------------------------------------------------

/**
 * Bidirectional controls. They let a name show something other than what
 * it is ("invoice<U+202E>fdp.exe" displays as "invoiceexe.pdf"), so they
 * are removed and the name shows its real extension. Other invisible
 * characters stay: the zero-width joiner, for one, is part of many emoji.
 */
const BIDI_CONTROLS = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g

/**
 * Characters no part of a name may contain: controls, the path separators,
 * and what Windows refuses in a file name (< > : " | ? *).
 */
const FORBIDDEN = /[\u0000-\u001f\u007f/\\<>:"|?*]/g

/**
 * Names Windows reserves for devices, with or without an extension
 * ("CON", "nul.txt"): saving under one fails or writes to the device.
 */
const WINDOWS_DEVICE = /^(con|prn|aux|nul|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3])(\.|$)/i

/** Longest part, in UTF-16 units (the NTFS limit; others count bytes). */
const MAX_PART_LENGTH = 255

/**
 * At most MAX_PART_LENGTH units, never cutting an emoji or any other
 * character outside the BMP in half.
 *
 * @param {string} text
 * @returns {string}
 */
function cut (text) {
  if (text.length <= MAX_PART_LENGTH) return text
  const head = text.slice(0, MAX_PART_LENGTH)
  return /[\ud800-\udbff]$/.test(head) ? head.slice(0, -1) : head
}

/**
 * One part of a name or path, made safe: well-formed, no forbidden
 * characters or bidirectional controls, no trailing dots or spaces
 * (Windows drops them, so "a." and "a" would collide), no device name, at
 * most MAX_PART_LENGTH long. May come back empty.
 *
 * @param {string} text
 * @returns {string}
 */
function safePart (text) {
  const wellFormed = typeof text.toWellFormed === 'function' ? text.toWellFormed() : text
  const part = cut(wellFormed.replace(BIDI_CONTROLS, '').replace(FORBIDDEN, '_').trim()).replace(/[. ]+$/, '')
  return WINDOWS_DEVICE.test(part) ? cut('_' + part) : part
}

/**
 * A file name from a (sender-controlled) manifest, made safe for saving: no
 * folders, no characters Windows refuses, no control or bidirectional
 * characters, no Windows device name, nothing that is only dots. The
 * fallback goes through the same rules — it may come from a manifest too.
 *
 * @param {unknown} name
 * @param {string} [fallback]
 * @returns {string}
 */
export function safeFileName (name, fallback = 'file') {
  return safePart(String(name || '')) || safePart(String(fallback || '')) || 'file'
}

/**
 * A file's path inside a ZIP: relative, no '..', no empty parts, and always
 * ending in the file's own name.
 *
 * `path` is the full relative path including the name (PROTOCOL.md §3). A
 * sender may still hand over only a folder ("Belege/2026") — then the name
 * is appended, so a file is never stored under its folder's name.
 *
 * @param {{ path?: string|null, name?: string }} file - a manifest entry
 * @returns {string}
 */
export function safeZipPath (file) {
  const name = safeFileName(file.name)
  // Every folder gets the same treatment as the name; "." and ".." end up
  // empty (no trailing dots) and are dropped.
  const parts = String(file.path || '').split(/[/\\]/).map(safePart).filter(Boolean)
  if (parts.length === 0) return name
  if (parts[parts.length - 1] !== name) parts.push(name)
  return parts.join('/')
}

// ---------------------------------------------------------------------------

function coded (code) {
  const err = new Error(code)
  err.code = code
  return err
}

function toBase64Url (bytes) {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
