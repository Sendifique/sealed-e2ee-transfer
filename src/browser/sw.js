// SPDX-License-Identifier: Apache-2.0
/**
 * src/browser/sw.js
 *
 * Service worker for saving decrypted downloads (save.js). Serve it from
 * the directory it should cover and register it with that scope — e.g.
 * '/t/sw.js' with scope '/t/'. If the script is not in that directory, the
 * server must allow the scope with a `Service-Worker-Allowed` header.
 *
 * It turns a stream of decrypted bytes into an ordinary browser download, so
 * a file of any size goes straight to disk instead of being collected in
 * memory first. It does NO cryptography and never sees a key: the page
 * decrypts and hands over plaintext chunks through a MessageChannel, one
 * chunk per request from here (backpressure).
 *
 * Protocol:
 *   page → worker  { type: 'register', id, filename, size } + MessagePort
 *   page           opens <scope>_dl/<id> in a hidden iframe
 *   worker         answers that request with a streaming attachment and asks
 *                  the port for data: { type: 'pull' }
 *   page → port    { type: 'chunk', chunk } | { type: 'end' } | { type: 'error' }
 *   worker → port  { type: 'cancel' } if the browser aborts the download
 *
 * A registration is used once and expires after a minute if never fetched.
 *
 * Classic script on purpose (no ES module): module service workers are not
 * available in every browser yet.
 */

'use strict'

/** id → { port, filename, size, expires } */
const pending = new Map()

/** Download URLs this worker answers: '<scope path>_dl/<id>'. */
const DOWNLOAD_PATH = new URL('_dl/', self.registration.scope).pathname

self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()))

self.addEventListener('message', (event) => {
  const data = event.data || {}
  // 'ping' (sent every few seconds during a download) needs no handling:
  // receiving a message event is what keeps this worker alive while a long
  // download is still streaming.
  const port = event.ports && event.ports[0]
  if (data.type !== 'register' || !port || !/^[A-Za-z0-9_-]{16,64}$/.test(String(data.id))) return
  const now = Date.now()
  for (const [id, entry] of pending) if (entry.expires < now) pending.delete(id)
  pending.set(data.id, {
    port,
    filename: String(data.filename || 'download'),
    size: Number.isSafeInteger(data.size) && data.size >= 0 ? data.size : null,
    expires: now + 60 * 1000
  })
  port.postMessage({ type: 'registered' })
})

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url)
  if (url.origin !== self.location.origin || !url.pathname.startsWith(DOWNLOAD_PATH)) return
  const match = url.pathname.slice(DOWNLOAD_PATH.length).match(/^([A-Za-z0-9_-]{16,64})$/)
  if (!match) return

  const entry = pending.get(match[1])
  pending.delete(match[1])
  if (!entry || entry.expires < Date.now()) {
    event.respondWith(new Response('Download expired', { status: 404 }))
    return
  }
  try {
    event.respondWith(streamingResponse(entry))
  } catch (err) {
    // Tell the page, so its download fails visibly instead of waiting forever.
    entry.port.postMessage({ type: 'error' })
    event.respondWith(new Response('Download failed', { status: 500 }))
  }
})

/**
 * The download response, fed chunk by chunk from the page.
 *
 * @param {{ port: MessagePort, filename: string, size: number|null }} entry
 * @returns {Response}
 */
function streamingResponse (entry) {

  const { port } = entry
  // pull() returns a promise that settles only when the page has answered,
  // so the stream asks for the next chunk only after the previous one has
  // arrived — real backpressure; nothing piles up in memory here.
  let answered = null
  const settle = () => { if (answered) { const done = answered; answered = null; done() } }
  const stream = new ReadableStream({
    start (controller) {
      port.onmessage = (msg) => {
        const d = msg.data || {}
        if (d.type === 'chunk') controller.enqueue(new Uint8Array(d.chunk))
        else if (d.type === 'end') controller.close()
        else if (d.type === 'error') controller.error(new Error('Download failed'))
        settle()
      }
    },
    pull () {
      return new Promise((resolve) => {
        answered = resolve
        port.postMessage({ type: 'pull' })
      })
    },
    cancel () {
      settle()
      port.postMessage({ type: 'cancel' })
    }
  }, { highWaterMark: 1 })

  const headers = new Headers({
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': contentDisposition(entry.filename),
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store'
  })
  if (entry.size !== null) headers.set('Content-Length', String(entry.size))
  return new Response(stream, { headers })
}

/**
 * attachment; filename="ascii fallback"; filename*=UTF-8''percent-encoded
 *
 * @param {string} name
 * @returns {string}
 */
function contentDisposition (name) {
  // Lone surrogates would make encodeURIComponent throw.
  const wellFormed = typeof name.toWellFormed === 'function' ? name.toWellFormed() : name
  const ascii = wellFormed.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_') || 'download'
  // RFC 5987 attr-chars: encodeURIComponent leaves ' ( ) * unencoded.
  const encoded = encodeURIComponent(wellFormed).replace(/['()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase())
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encoded}`
}
