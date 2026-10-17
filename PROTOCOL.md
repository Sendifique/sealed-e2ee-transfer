# Protocol — format 1

How a transfer is encrypted, stored and opened. Precise enough to write an
independent implementation — `test/vectors/reference.js` is one, in about a
hundred lines of Node's own `crypto` — and to check it:
`test/vectors/format-1.json` holds test vectors (fixed keys, salts and IVs
with the exact expected output) for files, the manifest and the password
wrap.

Notation: `||` concatenation, `HKDF(ikm, salt, info, L)` HKDF-SHA-256 with an
output of `L` bytes, `b64` standard base64 with padding, `b64url` URL-safe
base64 without padding. All lengths in bytes.

## 1. Keys

Per transfer the sender's browser draws:

| Name | Length | Where it goes |
|---|---|---|
| `K` main key | 32 | only in the share link's `#fragment` (or wrapped under a password, §5) |
| `S` key-chain salt | 16 | to the server, not secret |

Derived from them:

| Name | Derivation | Use |
|---|---|---|
| metadata key | `HKDF(K, S, "metadata", 32)` | AES-256-GCM over the manifest (§3) |
| reader token `R` | `HKDF(K, S, "authentication", 16)` | proves knowledge of `K` to the server (§4) |
| per-file key | `HKDF(K, s, "Content-Encoding: aes256gcm\0", 32)` | AES-256-GCM over one file (§2) |
| per-file nonce base | `HKDF(K, s, "Content-Encoding: nonce\0", 12)` | nonces of that file's records (§2) |

`s` is a fresh random 16-byte salt per file. `\0` is one zero byte.

The share link is `<base URL>#<b64url(K)>` — 43 characters after the `#`.
The base URL is the application's page that opens the transfer; browsers do
not send the fragment to the server.

## 2. Files

Each file is encrypted on its own, in the record layout of RFC 8188
("Encrypted Content-Encoding for HTTP") but with AES-256-GCM. The label
`aes256gcm` is deliberately not the RFC's `aes128gcm`: this is not standard
RFC 8188 output and does not interoperate with it.

```
header  = s (16) || rs (uint32, big-endian, = 65536) || idlen (1, = 0)     21 bytes
record  = AES-256-GCM(per-file key, nonce(seq), padded) || tag (16)
```

- Plaintext is cut into chunks of at most `rs − 17 = 65519` bytes.
- `padded` is the chunk followed by a delimiter: `0x02` for the last record;
  `0x01` followed by zero bytes up to a full record (`rs` bytes including the
  tag) for every other record.
- `nonce(seq)` is the nonce base with its last 4 bytes XORed with the record
  number `seq` (uint32, big-endian, starting at 0).
- Ciphertext length for `n` plaintext bytes:
  `21 + n + 17 × ceil(n / 65519)` — so an empty file is 21 + 0 bytes, and
  every length in between two valid ones is impossible.

A record cut off, reordered or flagged wrongly fails authentication. A file
has at most 2^32 records (the nonce counter), so it stays below about
256 TiB.

An empty file has no record, so nothing in it carries a GCM tag: a bare
header, under any key, would decrypt to nothing. It is therefore accepted
only where the authenticated manifest says the file is empty — it records
the salt and the size 0, so a different header is refused (§6) — and an
empty file has no content to protect. The decryptor refuses a bare header
unless told so (`allowEmpty`, which `decryptedFile()` sets from the
manifest), and a file cut down to its header is caught there as well as by
the size check. A ciphertext shorter than the header is always refused.

## 3. Manifest

The file list and anything else the recipient should see live only in the
encrypted manifest:

```json
{
  "v": 1,
  "files": [
    { "i": 0, "name": "contract.pdf", "path": null, "size": 1234, "type": "application/pdf", "salt": "<b64 of s>" }
  ]
}
```

- `i` is the file's index and equals its position in `files` (0, 1, 2, …
  — no gaps, no duplicates). A server should store files under their index
  only, never under their name.
- `name` is a non-empty string of at most 1024 characters. `path` is the
  file's full relative path **including its name** (`"Belege/2026/scan.png"`),
  at most 4096 characters, or `null` for a file outside any folder. `type`
  is a string of at most 255 characters (may be empty). `size` is the
  plaintext length, a non-negative integer.
- `salt` is the file's header salt `s` (§2). It binds the stored file to its
  entry: the recipient refuses a file whose header salt differs, so a server
  cannot swap two files, even of the same size.
- The application may add its own fields next to `v` and `files` (a
  subject, a message, …); `v` and `files` are reserved. Validating those is
  the application's job.
- Both sides enforce the entry rules above — the sender when sealing, the
  recipient when opening. The manifest is authenticated, but authentic is
  not harmless: its author can write anything, so its shape is checked
  before a page uses it. Names and paths are still sender-controlled text:
  render them as text, and make them safe before saving
  (`safeFileName()`, `safeZipPath()`).
- The UTF-8 JSON is padded with spaces (`0x20`, valid trailing JSON
  whitespace) to the next multiple of **4096** bytes, at least one block, so
  its length shows only how many blocks the text fills, not how long it is.
- Encrypted: `IV (16, random) || AES-256-GCM(metadata key, IV, padded) || tag (16)`.
  A conforming server refuses a manifest whose length is not
  `32 + k × 4096`.

## 4. What the server stores and checks

The server never receives `K`, a password, a file name or a byte of
plaintext. It stores, per transfer:

| Field | Content |
|---|---|
| key-chain salt | `S` |
| reader token hash | `SHA-256(R)` |
| manifest | the encrypted manifest (§3) |
| files | each file's ciphertext (§2), under its index |
| password block | only for §5: Argon2id salt and parameters, wrapped key, `SHA-256(P)` |

A server may add its own encryption at rest on top; it must hand out the
ciphertext of §2 unchanged.

On upload a server should check that each file is *shaped* like §2 — header
with `rs = 65536` and `idlen = 0`, a length the formula can produce
(`isShaped()` in `src/server/`). This cannot prove the data is encrypted; it
stops "upload plaintext and call it encrypted" from being trivial.

## 5. Password variant

Instead of `K` in the link, the sender sets a password: a string of at
least **12 characters** with at least **5 different** ones, counted as
Unicode code points after NFC, enforced wherever a password is set
(`checkNewPassword()`). An empty password is an
error, never "no password" — the link variant is chosen by passing none
(`null`). `generatePassphrase()` gives one of about 99 bits; prefer it, since
Argon2id slows guessing down but cannot make a short or common password
strong.

```
k            = random 16 bytes                       (Argon2id salt)
params       = { v: 1, alg: "argon2id", m: 65536, t: 3, p: 1 }   (m in KiB)
out          = Argon2id(NFC(password), k, params, 64 bytes)
wrap key     = out[0..32]          never leaves the browser
P            = out[32..64]         "password proof"
wrapped key  = IV (12, random) || AES-256-GCM(wrap key, IV, K, aad = bindTo) || tag (16)
                                                                    = 60 bytes
```

`bindTo` is a context string the application chooses and both sides pass:
it should name the application and a version and include the transfer's
identifier (e.g. `"myapp-v1:<transferId>"`), so a wrapped key copied onto
another transfer does not open there.

The server stores `k`, `params`, the wrapped key and `SHA-256(P)`. To open,
the recipient's browser derives `out` from the typed password and sends `P`;
only if `SHA-256(P)` matches does the server hand out the wrapped key, which
only `wrap key` can open. A wrong guess costs a request (which the server
should rate-limit); an offline attack needs the server's database and a
full Argon2id run per guess.

The server accepts exactly `m ∈ [65536, 131072]`, `t ∈ [3, 4]`,
`p ∈ [1, 4]` — and so does the recipient's browser, before it uses the
password (§6).

## 6. What the recipient's side checks

Nothing the server answers is trusted where it could weaken the encryption:

- The format version must be `1`; anything else is refused.
- Argon2id parameters must be exactly `v: 1`, `alg: "argon2id"` with costs
  in the accepted range, and the salt 16 bytes (§5) — checked *before* the
  password is used. A server that sent cheap parameters would otherwise get
  back a proof `P` it could crack in seconds.
- The unwrapped key must be 32 bytes; a link key must decode to 32 bytes.
- The manifest must be version 1 and every entry must follow the rules of
  §3.
- Every file: header salt equal to its manifest entry's, decrypted length
  exactly the entry's `size`; and the page should compare the stored
  ciphertext length with `ciphertextSize(size)` before downloading. Any
  mismatch errors the stream, so a wrong or partial file is never saved as
  complete.
- Decryption streams: each record's plaintext is released once *that
  record* is authenticated, before the file's last record has arrived. A
  later failure errors the stream and the download fails, but the bytes
  already written may remain as a broken partial file (how browsers keep
  those differs). The application must report such a download as failed,
  never as saved; content that must not exist even in part is decrypted
  completely before it is offered.

## 7. What a server provides

Paths, transport and access control are the application's. What the
browser side needs, in some form:

| When | The browser sends | The server answers |
|---|---|---|
| Upload | each file's ciphertext, declared length `ciphertextSize(n)`, its index | — after checking the shape (§4) |
| Finalize | `{ salt, readerToken, manifest, password? }` (`serverRecord()` + `passwordBlock()`), and how many files there are | — after validating it (`parseTransferRecord()`) and checking that exactly those files arrived, once per transfer |
| Start opening | — | format version, `S`, whether a password is set, Argon2id salt and parameters, each file's ciphertext length |
| Password | `P` | the wrapped key, if `SHA-256(P)` matches |
| Open | `R` | the encrypted manifest, if `SHA-256(R)` matches |
| Download | `R` (or a grant issued for it) | a file's ciphertext |

Recommendations:

- Rate-limit wrong `P` per transfer and per source, counting only
  well-formed proofs, per transfer within a time window (a count that
  never resets lets anyone with the link lock recipients out for good);
  wrong `R` per source only (it cannot be guessed, and counting it per
  transfer would let anyone with the link lock recipients out).
- The manifest is encrypted, so the server cannot count its entries: the
  browser states the number of files on finalize, and the server checks
  that exactly those indexes arrived. That they are the right files is
  checked by the recipient's browser (§6).
- Make the step that uses up a download a POST from a button, so link
  previews and mail scanners cannot trigger it.
- Accept JSON only on these requests; answer them `Cache-Control: no-store`.
- Serve the opening page from its own origin (THREAT-MODEL.md).

## 8. Versioning

`format: 1` names everything above. A change to any of it — key length,
cipher, derivation labels, manifest layout, padding — is a new format
number, never a silent change to format 1; a page that does not know a
format refuses it.

Candidates for a format 2, none of them a known weakness of format 1:

- an authenticated final record for every file, so an empty file is 38
  bytes and carries a tag of its own;
- a 12-byte IV for the manifest, the size AES-GCM is specified for;
- versioned derivation labels and a canonical AAD (application, format,
  transfer, purpose) built by the library rather than by each application.

The Argon2id parameters already carry `v` and `alg` (§5), so a different
password function could be added without a new format for everything
else; the recipient refuses any `alg` it does not know.
