# sealed-e2ee-transfer

[![Tests](https://github.com/Sendifique/sealed-e2ee-transfer/actions/workflows/test.yml/badge.svg)](https://github.com/Sendifique/sealed-e2ee-transfer/actions/workflows/test.yml)
[![npm](https://img.shields.io/npm/v/@sendifique/sealed-e2ee-transfer.svg)](https://www.npmjs.com/package/@sendifique/sealed-e2ee-transfer)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

End-to-end encrypted file transfer in the browser.

This library was developed for and is used by
[Sendifique](https://sendifique.com), a privacy-first file transfer service
hosted in the EU.

The sender's browser encrypts every file before it leaves the device; the
server stores ciphertext it cannot read; the recipient's browser decrypts.
The key travels only in the share link's `#fragment`, which browsers never
send to a server — or, instead, behind a password that unlocks it on the
recipient's side.

- **AES-256-GCM**, streaming: files of any size, never held in memory as a
  whole, saved straight to disk through a service worker.
- **Key in the link, or a password** (Argon2id in the browser; the server
  only ever sees a proof).
- **Encrypted, padded manifest**: file names, sizes, types, folder paths
  and the application's own fields — bound to the stored files, so they
  cannot be swapped.
- **Distrusts the server** wherever an answer could weaken the encryption.
- **Server-side checks for Node**: exact sizes, shape check of uploads,
  strict validation of what the browser sends, constant-time comparisons.
- **Small and plain**: ES modules, no build step; the encryption itself is
  Web Crypto. Two dependencies: [`@noble/hashes`](https://github.com/paulmillr/noble-hashes)
  for Argon2id and [`client-zip`](https://github.com/Touffy/client-zip) for
  ZIP downloads.

Documentation:

- **[PROTOCOL.md](PROTOCOL.md)** — format 1, byte by byte, and what a server
  has to provide.
- **[THREAT-MODEL.md](THREAT-MODEL.md)** — what this protects against, what
  it does not, and how to deploy it so the protection holds.
- **[SECURITY.md](SECURITY.md)** — how to report a vulnerability.

## Requirements

- **Browsers:** Chrome / Edge 93+, Firefox 102+, Safari 15.4+ — in
  practice any browser updated since 2022. `isSupported()` checks the
  needed features (Web Crypto, streams, `Blob.stream()`) at runtime, so an
  old browser gets a clear message instead of failing halfway. Saving large
  files needs service workers; without them, files up to 1 GiB are
  assembled in memory.
- **Node** (server side and tests): 22 or later.

## Install

```
npm install --save-exact @sendifique/sealed-e2ee-transfer
```

Pin an exact version and commit your lockfile: this is the code that holds
your users' keys (THREAT-MODEL.md).

**With a bundler** (Vite, webpack, esbuild, …) import it like any package.
Two files are not imported but served as they are, from your own origin:
`src/browser/take-key.js` (a classic script) and `src/browser/sw.js` (the
service worker).

**Without a bundler**, serve `src/` and the two dependencies from your
own origin, unchanged, and map the dependencies' names with an import map:

```html
<script type="importmap">
{ "imports": {
    "@noble/hashes/": "/deps/@noble/hashes/",
    "client-zip": "/deps/client-zip/index.js"
} }
</script>
```

## Sending

```js
import { createUpload, isSupported } from '@sendifique/sealed-e2ee-transfer'

const upload = createUpload()

// Every file: an encrypting reader for your upload client, and the exact
// size it will produce.
for (const [i, file] of files.entries()) {
  const reader = await upload.reader(file, i)
  await uploadToYourServer(transferId, i, reader, upload.ciphertextSize(file.size))
}

// What your server stores — no key, no names, no plaintext.
const record = await upload.finalize({
  files: files.map(f => ({ name: f.name, size: f.size, type: f.type })),
  meta: { message: 'Here are the contracts.' },        // your own fields, encrypted
  password: null,                                        // or a password — best
                                                         // generatePassphrase(); a chosen one
                                                         // passes checkNewPassword() first
  bindTo: `myapp-v1:${transferId}`                       // required with a password
})
await postToYourServer(transferId, record)

// With the key in the #fragment — or, with a password, without it.
const link = upload.shareLink(`https://open.example.com/t/${transferId}`)
```

## Opening

On the opening page, first thing in `<head>`:

```html
<script src="/sealed-e2ee-transfer/src/browser/take-key.js"></script>
```

Then, in a module:

```js
import {
  FORMAT_VERSION, openKeychain, openManifest, readerToken, decryptedFile, ciphertextSize,
  derivePasswordKeys, unwrapKey, encodeBase64, decodeBase64,
  registerSaver, saveStream, safeFileName
} from '/sealed-e2ee-transfer/src/browser/index.js'

const info = await getInfoFromYourServer(transferId)
if (info.format !== FORMAT_VERSION) throw new Error('Unsupported format')

let key = window.__sealedKey()                 // from the link; only once
if (info.password) {
  // Refuses cheap parameters before the password is used.
  const { wrapKey, passwordAuth } = await derivePasswordKeys(
    typedPassword, decodeBase64(info.kdf.salt), info.kdf.params)
  const wrappedKey = await unlockOnYourServer(transferId, encodeBase64(passwordAuth))
  key = await unwrapKey(wrapKey, wrappedKey, `myapp-v1:${transferId}`)
}

const keychain = openKeychain(key, info.salt)
const manifest = await openManifest(keychain,
  await openOnYourServer(transferId, await readerToken(keychain)))

const registration = await registerSaver('/t/sw.js', '/t/')
for (const entry of manifest.files) {
  if (info.sizes[entry.i] !== ciphertextSize(entry.size)) throw new Error('Mismatch')
  const ciphertext = await fetchFileFromYourServer(transferId, entry.i)   // a ReadableStream
  await saveStream(await decryptedFile(keychain, ciphertext, entry), {
    filename: safeFileName(entry.name), size: entry.size, registration
  })
}
```

`decryptedFile()` checks every file against its manifest entry (salt and
size); a wrong or partial file errors the stream instead of being saved.

## Server (Node)

```js
import {
  isShaped, ciphertextSize, parseTransferRecord, matchesStoredHash,
  READER_TOKEN_LENGTH, PASSWORD_AUTH_LENGTH, HEADER_LENGTH
} from '@sendifique/sealed-e2ee-transfer/server'

// After an upload: is it shaped like format 1 ciphertext?
isShaped(firstBytes.subarray(0, HEADER_LENGTH), totalLength)

// Finalize: validate once, store what comes back (hashes, not tokens).
const parsed = parseTransferRecord(body)
if (!parsed.ok) return reply.code(400).send({ error: parsed.error })

// Opening: constant-time comparison against the stored hash.
matchesStoredHash(body.readerToken, READER_TOKEN_LENGTH, row.readerTokenHash)
matchesStoredHash(body.passwordAuth, PASSWORD_AUTH_LENGTH, row.passwordAuthHash)
```

Storage, access control, rate limits and expiry are yours; PROTOCOL.md §7
lists what the browser side needs from the server.

## API

Every function and constant the package exports. The source has the full
JSDoc for each (parameters, return values, errors).

### Browser — `@sendifique/sealed-e2ee-transfer`

**Sending**

| Export | |
|---|---|
| `createUpload()` | The whole sending side in one object: `reader(file, index)` for your upload client, `ciphertextSize(n)`, `finalize({ files, meta, password, bindTo })` → the record for your server, `shareLink(baseUrl)`. |
| `isSupported()` | Whether this browser has what the encryption needs. |

**Keys and files** (what `createUpload()` and an opening page use underneath)

| Export | |
|---|---|
| `createKeychain()` | A new key chain: random 256-bit main key and 16-byte salt. |
| `openKeychain(key, saltB64)` | The key chain of a received transfer; refuses a key that is not 32 bytes. |
| `encryptedReader(keychain, file, onSalt)` | A reader over the encrypted file; reports the file's header salt. |
| `fileSalt(ciphertext)` | The header salt of a whole ciphertext, base64. |
| `decryptedFile(keychain, ciphertext, entry)` | The plaintext stream, checked against the manifest entry (salt and size) as it flows. |
| `ciphertextSize(n)` | Exact ciphertext length of `n` plaintext bytes. |
| `plaintextSize(length)` | Plaintext length of a ciphertext length, or `null` if no plaintext produces it. |

**Manifest, record and link**

| Export | |
|---|---|
| `sealManifest(keychain, { files, meta })` | Encrypts and pads the manifest; refuses entries of the wrong shape (PROTOCOL.md §3). |
| `openManifest(keychain, manifestB64)` | Decrypts the manifest and checks every entry. |
| `serverRecord(keychain, sealedManifest)` | `{ salt, readerToken, manifest }` — what the server stores. |
| `readerToken(keychain)` | The reader token, base64 — what a recipient sends to prove the key. |
| `shareLink(baseUrl, keychain)` | `baseUrl` with the key in its `#fragment`. |

**Password variant**

| Export | |
|---|---|
| `checkNewPassword(password)` | Throws unless it is a string of at least 12 characters with at least 5 different ones (code points after NFC); the error's `code` is `PASSWORD_NOT_A_STRING`, `PASSWORD_TOO_SHORT` or `PASSWORD_TOO_REPETITIVE`. |
| `generatePassphrase()` | A random passphrase of about 99 bits (`k7mp-2qxr-…`). |
| `passwordBlock(keychain, password, bindTo, onProgress)` | Wraps the key under the password; the block the server stores. |
| `derivePasswordKeys(password, kdfSalt, params, onProgress)` | Argon2id → wrap key and password proof; refuses parameters outside `KDF_BOUNDS` before using the password. |
| `unwrapKey(wrapKey, wrappedKeyB64, bindTo)` | Opens the wrapped key; refuses another context or a key that is not 32 bytes. |

**Saving**

| Export | |
|---|---|
| `registerSaver(scriptUrl, scope)` | Registers `sw.js`; resolves to the registration, or `null` without service workers. |
| `saveStream(stream, { filename, size, registration, inMemoryLimit, onFallback })` | Saves a stream as a download — through the service worker, or in memory up to a limit. Errors carry `code`: `SAVE_FAILED`, `SAVE_CANCELLED`, `TOO_LARGE_WITHOUT_WORKER`. |
| `makeZip(inputs, { length })` | A ZIP stream of several files (client-zip). |
| `predictZipLength(entries)` | The exact length of that ZIP. |
| `safeFileName(name, fallback)` | A sender's file name made safe to save under: no folders, no characters Windows refuses, no control or bidirectional characters, no Windows device names or trailing dots; the fallback gets the same rules. |
| `safeZipPath(file)` | A manifest entry's path made safe inside a ZIP, always ending in its name. |
| `encodeBase64(bytes)` / `decodeBase64(b64)` | Standard, padded base64 — the encoding of every binary value in the protocol. |

**Constants**

| Export | Value |
|---|---|
| `FORMAT_VERSION` | `1` — the wire format |
| `MANIFEST_VERSION` | `1` — the manifest's JSON |
| `KEY_LENGTH` | `32` — main key, bytes |
| `SALT_LENGTH` | `16` — key-chain and file salts, bytes |
| `READER_TOKEN_LENGTH` | `16` — reader token, bytes |
| `RECORD_SIZE` | `65536` — file records, bytes |
| `HEADER_LENGTH` | `21` — file header, bytes |
| `MANIFEST_BLOCK` | `4096` — the manifest is padded to multiples of this |
| `KDF_DEFAULTS` | `{ v: 1, alg: 'argon2id', m: 65536, t: 3, p: 1 }` |
| `KDF_BOUNDS` | the only accepted Argon2id costs: `m` 65536–131072, `t` 3–4, `p` 1–4 |
| `MIN_PASSWORD_LENGTH` | `12` |
| `MIN_PASSWORD_DISTINCT` | `5` — different characters a password needs at least |
| `IN_MEMORY_LIMIT` | 1 GiB — largest download assembled in memory without a service worker |

**Files served as they are, not imported:**
`@sendifique/sealed-e2ee-transfer/take-key.js` (first script on the opening
page) and `@sendifique/sealed-e2ee-transfer/sw.js` (the service worker).

### Server — `@sendifique/sealed-e2ee-transfer/server`

| Export | |
|---|---|
| `isShaped(header, totalLength)` | Whether an upload is shaped like format 1 ciphertext (header and length) — not a proof that it is encrypted. |
| `parseFileIndex(raw, max)` | A file index as a client declares it, or `null` (default `max` 99999). |
| `parseTransferRecord(body, { maxManifestBytes })` | Validates the finalize record and returns what to store (hashes, not tokens), or `{ ok: false, error }` with `INVALID_SALT`, `INVALID_READER_TOKEN`, `INVALID_MANIFEST`, `INVALID_KDF_SALT`, `INVALID_KDF_PARAMS`, `INVALID_WRAPPED_KEY` or `INVALID_PASSWORD_AUTH`. |
| `parsePasswordBlock(raw)` | The password part of that validation, on its own. |
| `parseKdfParams(raw)` | Argon2id parameters in canonical form, or `null` outside `KDF_BOUNDS`. |
| `matchesStoredHash(valueB64, expectedLength, storedHash)` | Constant-time check of a reader token or password proof against its stored hash. |
| `sha256(value)` | What to store instead of a token or proof. |
| `decodeBase64Strict(value)` | Canonical base64 only — the same bytes never arrive in two spellings. |
| `ciphertextSize(n)` / `plaintextSize(length)` | As in the browser. |
| `FORMAT_VERSION`, `RECORD_SIZE`, `HEADER_LENGTH`, `MANIFEST_BLOCK`, `READER_TOKEN_LENGTH`, `KDF_DEFAULTS`, `KDF_BOUNDS` | As in the browser. |
| `PASSWORD_AUTH_LENGTH` | `32` — password proof, bytes |
| `MAX_MANIFEST_BYTES` | 2 MiB — default limit of `parseTransferRecord` |

## Example

[`examples/basic/`](examples/basic/) is a complete, minimal application: a
sending page, an opening page and a small Node server (no dependencies,
transfers in memory) that serves both under a strict Content-Security-
Policy and implements PROTOCOL.md §7.

```
npm run example        →  http://localhost:8080/
```

It is a reference for reading, **not a production server**: it shows the
limits every server needs (a cap on transfers and on bytes held, an expiry,
a completeness check on finalize, wrong passwords limited per transfer
within a time window, stalled uploads timed out, requests from other sites
refused) only in their simplest form, has no accounts — anyone
who reaches it can fill it — and listens on 127.0.0.1.

## Layout

```
src/
  browser/           everything that runs in the browser
    index.js           the browser API
    sealed.js          keys, manifest, password variant, createUpload()
    ece.js             file encryption: AES-256-GCM records, as streams
    save.js            saving downloads of any size; ZIP; safe file names
    take-key.js        classic script: first on the opening page, takes the key from the link
    sw.js              service worker that streams decrypted files to disk
  server/            Node: sizes, shape check, validation, comparisons
  format.js          the numbers of format 1, shared by both sides
examples/basic/    a complete minimal application (server, sending and opening page)
test/              node:test — `npm test`
  vectors/           format 1 test vectors and the independent reference implementation
e2e/               the example in real browsers (Playwright) — `npm run test:e2e`
```

## Tests

```
npm ci
npm test
```

CI runs them on Node 22, 24 and 26. The tests run the browser modules
unchanged in Node (same Web Crypto and streams APIs) and check format 1
with Node's own HKDF and AES-256-GCM, so a mistake in the library cannot
hide behind itself.

**Fuzzing:** `test/fuzz.test.js` adds randomised cases — any plaintext in
any pieces must round-trip; a ciphertext with a flipped bit, cut off,
extended, with records swapped, dropped, repeated or taken from another
file must be refused; so must a wrong key, size or salt, and a changed
manifest. Every run prints its seed; `FUZZ_SEED=<seed>` repeats it, and
`FUZZ_CASES` sets the cases per class (50 by default). A weekly workflow
runs 10,000 cases with a new seed each time.

**In real browsers:** `npm run test:e2e` drives the example application
with Playwright — upload, open the link, download through the service
worker, compare the bytes; link and password variant, wrong keys and
passwords. CI runs it in Chromium, Firefox and WebKit. Locally, install a
browser once with `npx playwright install chromium` (or `firefox`,
`webkit`) and choose it with `E2E_BROWSER`.

**Test vectors** for format 1 are in
[`test/vectors/format-1.json`](test/vectors/format-1.json): fixed keys,
salts and IVs with the exact expected ciphertext of files, the manifest and
the password wrap. They are produced by a second, independent
implementation ([`test/vectors/reference.js`](test/vectors/reference.js),
Node's own crypto and native Argon2id); the library has to open them and,
given the same salts, reproduce them byte for byte. Check your own
implementation against them.

## Versions

Semantic versioning for the API. The wire format has its own number
(PROTOCOL.md §8); a new format is never a silent change.

## Contributing

Issues are welcome; for pull requests, please open an issue first. See
[CONTRIBUTING.md](CONTRIBUTING.md) — and [SECURITY.md](SECURITY.md) for
security issues, which never belong in a public issue.

## Acknowledgements

Format 1 builds on the design of
[wormhole-crypto](https://github.com/SocketDev/wormhole-crypto)
(RFC 8188 records, HKDF-derived keys), extended to AES-256.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE). Every file of this project
carries an `SPDX-License-Identifier: Apache-2.0` line.

The dependencies `@noble/hashes` and `client-zip` are MIT-licensed by
their authors.
