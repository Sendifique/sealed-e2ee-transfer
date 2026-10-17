// SPDX-License-Identifier: Apache-2.0
/**
 * examples/basic/server.js
 *
 * A complete, minimal application around the library — for reading and for
 * the browser test (test/browser.test.js). PROTOCOL.md §7 lists what a
 * server provides; this is the smallest server that provides it.
 *
 * NOT A PRODUCTION SERVER. It keeps transfers in memory, has no accounts and
 * listens on 127.0.0.1 only. It does show the limits every real server
 * needs — in their simplest form: a cap on transfers, files and bytes held,
 * an expiry (short until a transfer is finalized), a check that every
 * announced file arrived, and a time window for wrong passwords per
 * transfer. Anyone who can reach it can still fill it up: a real deployment
 * adds authentication for uploads, per-account and per-source quotas,
 * streaming into persistent storage with cleanup, and the deployment rules
 * of THREAT-MODEL.md.
 *
 *     node examples/basic/server.js            → http://localhost:8080/
 *
 * Pages:
 *   /            send.html — choose files, optionally a password, get a link
 *   /t/<id>      open.html — open a link, download the files
 *
 * API (JSON unless stated):
 *   POST /api/transfers                    → { id }
 *   PUT  /api/transfers/:id/files/:i       ciphertext as the body
 *   POST /api/transfers/:id/finalize       the browser's record + fileCount → 204
 *   GET  /api/transfers/:id/info           what the opening page needs to start
 *   POST /api/transfers/:id/unlock         { passwordAuth } → { wrappedKey }
 *   POST /api/transfers/:id/open           { readerToken } → { manifest }
 *   GET  /api/transfers/:id/files/:i       ciphertext; header x-reader-token
 */

import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import {
  FORMAT_VERSION, HEADER_LENGTH, READER_TOKEN_LENGTH, PASSWORD_AUTH_LENGTH,
  isShaped, parseFileIndex, parseTransferRecord, matchesStoredHash, decodeBase64Strict
} from '../../src/server/index.js'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(HERE, '..', '..')

/**
 * Limits that keep the example from being an open store (see header).
 * start() can override them, so the tests need not wait an hour.
 */
const DEFAULT_LIMITS = Object.freeze({
  maxTransfers: 100,
  maxFilesPerTransfer: 100,
  maxFileBytes: 256 * 1024 * 1024,
  // Everything held in memory, over all transfers. Without it the caps
  // above would multiply to terabytes.
  maxTotalBytes: 1024 * 1024 * 1024,
  // An upload that is never finalized frees its place soon.
  pendingTtlMs: 10 * 60 * 1000,
  // An upload body that stops arriving gives its reserved bytes back.
  uploadIdleMs: 30 * 1000,
  transferTtlMs: 60 * 60 * 1000,
  // Wrong passwords per transfer within a window, not for the transfer's
  // life: a limit that never resets would let anyone with the link lock
  // the recipients out until the transfer expires. The window still caps
  // guessing — at 10 per 15 minutes, about a thousand a day — far from
  // what a 12-character password needs.
  maxWrongPasswords: 10,
  wrongPasswordWindowMs: 15 * 60 * 1000
})

let limits = DEFAULT_LIMITS

/**
 * id → { files: Buffer[], record: object|null, expires: number,
 *        wrongPasswords: number, windowStart: number } — in memory only.
 */
const transfers = new Map()

/** Bytes held in all transfers' files — checked against maxTotalBytes. */
let heldBytes = 0

function removeTransfer (id) {
  const t = transfers.get(id)
  if (!t) return
  for (const f of t.files) heldBytes -= f?.length ?? 0
  transfers.delete(id)
}

function sweep () {
  const now = Date.now()
  for (const [id, t] of transfers) if (t.expires < now) removeTransfer(id)
}

// Expired transfers go; unref() so the sweep never keeps the process alive.
setInterval(sweep, 60 * 1000).unref()

/**
 * Static files, by URL prefix. The library and its two dependencies are
 * served unchanged from their package directories; the page maps the
 * dependencies' names with an import map (see the HTML files).
 */
const STATIC = [
  ['/lib/', path.join(ROOT, 'src')],
  ['/deps/@noble/hashes/', path.join(ROOT, 'node_modules', '@noble', 'hashes')],
  ['/deps/client-zip/', path.join(ROOT, 'node_modules', 'client-zip')],
  ['/app/', path.join(HERE, 'public')]
]

const TYPES = { '.js': 'text/javascript; charset=utf-8', '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8' }

/**
 * A page with its Content-Security-Policy: scripts only from this origin —
 * plus the page's one inline script, its import map, allowed by its SHA-256
 * rather than by 'unsafe-inline'; an empty data: icon, so no browser asks
 * for /favicon.ico — nothing framed from elsewhere, no
 * referrer (THREAT-MODEL.md, "Deploying it"). Built once at start.
 *
 * @param {string} name - file in public/
 * @returns {{ html: Buffer, csp: string }}
 */
function page (name) {
  const html = fs.readFileSync(path.join(HERE, 'public', name))
  const map = /<script type="importmap">([\s\S]*?)<\/script>/.exec(html.toString('utf8'))
  const hash = map ? ` 'sha256-${crypto.createHash('sha256').update(map[1]).digest('base64')}'` : ''
  const csp = [
    "default-src 'none'", `script-src 'self'${hash}`, "connect-src 'self'", "style-src 'self'", "img-src data:",
    "worker-src 'self'", "frame-src 'self'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'"
  ].join('; ')
  return { html, csp }
}

const SEND_PAGE = page('send.html')
const OPEN_PAGE = page('open.html')

function servePage (res, { html, csp }) {
  send(res, 200, html, {
    'content-type': 'text/html; charset=utf-8', 'content-security-policy': csp, 'referrer-policy': 'no-referrer'
  })
}

// ---------------------------------------------------------------------------

function send (res, status, body, headers = {}) {
  const isJson = body !== null && typeof body === 'object' && !Buffer.isBuffer(body)
  res.writeHead(status, {
    'cache-control': 'no-store',
    ...(isJson ? { 'content-type': 'application/json' } : {}),
    ...headers
  })
  res.end(isJson ? JSON.stringify(body) : body)
}

function readBody (req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    req.on('data', (c) => {
      size += c.length
      if (size > limit) { reject(new Error('too large')); req.destroy() } else chunks.push(c)
    })
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
    // A connection that closes early must settle too — otherwise whatever
    // waits on it (a byte reservation) would wait for ever.
    req.on('close', () => reject(new Error('closed')))
  })
}

async function readJson (req) {
  if (!String(req.headers['content-type']).startsWith('application/json')) throw new Error('JSON only')
  return JSON.parse((await readBody(req, 4 * 1024 * 1024)).toString('utf8'))
}

function serveFile (res, file, headers = {}) {
  fs.readFile(file, (err, data) => {
    if (err) return send(res, 404, { error: 'NOT_FOUND' })
    send(res, 200, data, { 'content-type': TYPES[path.extname(file)] || 'application/octet-stream', ...headers })
  })
}

function serveStatic (res, urlPath) {
  for (const [prefix, dir] of STATIC) {
    if (!urlPath.startsWith(prefix)) continue
    const file = path.resolve(dir, '.' + urlPath.slice(prefix.length - 1))
    if (!file.startsWith(dir + path.sep)) return send(res, 404, { error: 'NOT_FOUND' })
    return serveFile(res, file)
  }
  send(res, 404, { error: 'NOT_FOUND' })
}

// ---------------------------------------------------------------------------

async function api (req, res, parts) {
  // /api/transfers[/<id>[/<action>[/<index>]]]
  const [, , resource, id, action, index] = parts
  if (resource !== 'transfers') return send(res, 404, { error: 'NOT_FOUND' })
  if (req.method === 'POST' && id === undefined) {
    // Expired places are freed here, not only by the minute's sweep.
    if (transfers.size >= limits.maxTransfers) sweep()
    if (transfers.size >= limits.maxTransfers) return send(res, 503, { error: 'FULL' })
    const newId = crypto.randomUUID()
    transfers.set(newId, {
      files: [], record: null, expires: Date.now() + limits.pendingTtlMs, wrongPasswords: 0, windowStart: 0
    })
    return send(res, 200, { id: newId })
  }
  const transfer = transfers.get(id)
  if (!transfer || transfer.expires < Date.now()) return send(res, 404, { error: 'NOT_FOUND' })

  if (action === 'files' && req.method === 'PUT') {
    const i = parseFileIndex(index, limits.maxFilesPerTransfer - 1)
    if (i === null || transfer.record) return send(res, 400, { error: 'BAD_REQUEST' })
    // The length is declared up front (PROTOCOL.md §7) and reserved before
    // the body is read, so parallel uploads cannot together overrun the
    // budget.
    const declared = Number(req.headers['content-length'])
    if (!Number.isSafeInteger(declared) || declared > limits.maxFileBytes) return send(res, 413, { error: 'TOO_LARGE' })
    if (heldBytes + declared > limits.maxTotalBytes) return send(res, 507, { error: 'STORAGE_FULL' })
    heldBytes += declared
    req.setTimeout(limits.uploadIdleMs, () => req.destroy(new Error('idle')))
    let body
    try {
      body = await readBody(req, declared)
    } finally {
      heldBytes -= declared
    }
    if (!isShaped(body.subarray(0, HEADER_LENGTH), body.length)) return send(res, 400, { error: 'NOT_ENCRYPTED' })
    // The transfer may have expired or been finalized while the body came in.
    if (transfers.get(id) !== transfer || transfer.record) return send(res, 409, { error: 'GONE' })
    heldBytes += body.length - (transfer.files[i]?.length ?? 0)
    transfer.files[i] = body
    return send(res, 204, '')
  }

  if (action === 'finalize' && req.method === 'POST') {
    if (transfer.record) return send(res, 409, { error: 'ALREADY_FINALIZED' })
    const body = await readJson(req)
    const parsed = parseTransferRecord(body)
    if (!parsed.ok) return send(res, 400, { error: parsed.error })
    // The manifest is encrypted, so the server cannot count its entries;
    // the browser states the count, and the server checks that exactly
    // those files arrived. (That they are the right files, the recipient's
    // browser checks — PROTOCOL.md §6.)
    const count = body.fileCount
    if (!Number.isSafeInteger(count) || count < 1 || count !== transfer.files.length ||
        !Array.from({ length: count }, (_, i) => transfer.files[i]).every(Boolean)) {
      return send(res, 409, { error: 'INCOMPLETE' })
    }
    transfer.record = parsed
    transfer.expires = Date.now() + limits.transferTtlMs
    return send(res, 204, '')
  }

  const record = transfer.record
  if (!record) return send(res, 404, { error: 'NOT_FOUND' })

  if (action === 'info' && req.method === 'GET') {
    return send(res, 200, {
      format: FORMAT_VERSION,
      salt: record.salt.toString('base64'),
      password: Boolean(record.password),
      kdf: record.password ? { salt: record.password.kdfSalt.toString('base64'), params: record.password.kdfParams } : null,
      sizes: transfer.files.map(f => f.length)
    })
  }

  if (action === 'unlock' && req.method === 'POST') {
    // Wrong passwords are limited per transfer within a window (see
    // DEFAULT_LIMITS). Only a well-formed proof is counted — a broken
    // request costs nothing — and it is counted before comparing, so
    // parallel guesses cannot overrun the limit. (A real server also limits
    // per source.)
    if (!record.password) return send(res, 400, { error: 'NO_PASSWORD' })
    const { passwordAuth } = await readJson(req)
    if (decodeBase64Strict(passwordAuth)?.length !== PASSWORD_AUTH_LENGTH) return send(res, 400, { error: 'BAD_REQUEST' })
    const now = Date.now()
    if (now - transfer.windowStart >= limits.wrongPasswordWindowMs) {
      transfer.windowStart = now
      transfer.wrongPasswords = 0
    }
    if (transfer.wrongPasswords >= limits.maxWrongPasswords) {
      const retry = Math.ceil((transfer.windowStart + limits.wrongPasswordWindowMs - now) / 1000)
      return send(res, 429, { error: 'TOO_MANY_ATTEMPTS' }, { 'retry-after': String(retry) })
    }
    transfer.wrongPasswords++
    if (!matchesStoredHash(passwordAuth, PASSWORD_AUTH_LENGTH, record.password.passwordAuthHash)) {
      return send(res, 403, { error: 'WRONG_PASSWORD' })
    }
    transfer.wrongPasswords--  // a right password gives its attempt back
    return send(res, 200, { wrappedKey: record.password.wrappedKey.toString('base64') })
  }

  if (action === 'open' && req.method === 'POST') {
    const { readerToken } = await readJson(req)
    if (!matchesStoredHash(readerToken, READER_TOKEN_LENGTH, record.readerTokenHash)) return send(res, 403, { error: 'WRONG_KEY' })
    return send(res, 200, { manifest: record.manifest.toString('base64') })
  }

  if (action === 'files' && req.method === 'GET') {
    if (!matchesStoredHash(req.headers['x-reader-token'], READER_TOKEN_LENGTH, record.readerTokenHash)) return send(res, 403, { error: 'WRONG_KEY' })
    const file = transfer.files[parseFileIndex(index) ?? -1]
    if (!file) return send(res, 404, { error: 'NOT_FOUND' })
    return send(res, 200, file, { 'content-type': 'application/octet-stream' })
  }

  send(res, 404, { error: 'NOT_FOUND' })
}

/**
 * The example's request handler.
 *
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 */
export async function handle (req, res) {
  const url = new URL(req.url, 'http://localhost')
  const parts = url.pathname.split('/')
  // Requests that change something come from this origin's own pages. A
  // missing CORS header only stops another site from reading the answer,
  // not from sending a form or a simple POST — so those are refused here.
  if (parts[1] === 'api' && req.method !== 'GET' && !sameOrigin(req)) return send(res, 403, { error: 'CROSS_ORIGIN' })
  try {
    if (url.pathname === '/') return servePage(res, SEND_PAGE)
    // The service worker is served from /t/ so that its scope covers the
    // opening pages and the download URLs under /t/.
    if (url.pathname === '/t/sw.js') return serveFile(res, path.join(ROOT, 'src', 'browser', 'sw.js'))
    if (/^\/t\/[0-9a-f-]{36}$/.test(url.pathname)) return servePage(res, OPEN_PAGE)
    if (parts[1] === 'api') return await api(req, res, parts)
    serveStatic(res, url.pathname)
  } catch (err) {
    send(res, 400, { error: 'BAD_REQUEST' })
  }
}

/**
 * Whether a request comes from this server's own pages: the browser's
 * Sec-Fetch-Site says so, or — in browsers without it — the Origin header
 * names this host. A request without either is not a browser's cross-site
 * request (curl, tests) and passes.
 *
 * @param {http.IncomingMessage} req
 * @returns {boolean}
 */
function sameOrigin (req) {
  const site = req.headers['sec-fetch-site']
  if (site) return site === 'same-origin'
  const origin = req.headers.origin
  return !origin || origin === `http://${req.headers.host}`
}

/**
 * Starts the example server.
 *
 * @param {number} [port] - 0 for any free port
 * @param {Partial<typeof DEFAULT_LIMITS>} [overrides] - limits to change (tests)
 * @returns {Promise<http.Server>}
 */
export function start (port = 8080, overrides = {}) {
  limits = { ...DEFAULT_LIMITS, ...overrides }
  const server = http.createServer(handle)
  return new Promise((resolve) => server.listen(port, '127.0.0.1', () => resolve(server)))
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  const server = await start(Number(process.env.PORT) || 8080)
  console.log(`http://localhost:${server.address().port}/`)
}
