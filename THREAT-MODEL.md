# Threat model

What this library protects against, what it does not — and what an
application has to do so that the protection holds. The format itself is
in [PROTOCOL.md](PROTOCOL.md).

## What is protected

The **content** of the files and the **metadata the sender typed or
chose**: file names, folder paths, MIME types, exact sizes per file, and
whatever the application puts into the manifest (a subject, a message).
These exist in plaintext only in the sender's and the recipients'
browsers.

## Against whom

| Adversary | Protected? |
|---|---|
| Someone who gets a copy of the **stored files** (storage provider, stolen backup) | Yes. They hold ciphertext under keys they do not have. |
| Someone who gets the **server's database** | Yes for link transfers: it holds no key, only `SHA-256` of the reader token. For password transfers it enables an **offline password guess**, each costing a full Argon2id run (64 MiB, 3 passes); a strong or generated password makes that hopeless, a weak one does not. |
| The **operator**, honest but curious, reading what the server stores | Yes, as above. |
| A **network observer** | Yes, given HTTPS: the key is in the `#fragment`, which browsers do not send. |
| Someone who **has the link** (link variant) | **No** — the link is the key. Anyone it is forwarded to can open the transfer, until the server stops serving it. |
| Someone who has the link **and the password** | **No**, by design. |
| A **compromised sender or recipient device** | **No.** Malware on either end sees the plaintext. |

## What is not protected

**The code comes from the server.** This is the basic limit of encryption
in a web page: the browser runs whatever JavaScript the server delivers.
An operator acting in bad faith, or an attacker in control of the server,
could deliver different code to one visitor and read their key. What
narrows this:

- The library is public, and an application can pin one exact release
  (published with npm provenance, so a package can be traced to its
  commit) and serve its files unchanged — then what a page runs can be
  compared byte for byte with a release.
- The library distrusts the server's *answers* wherever they could weaken
  the encryption (PROTOCOL.md §6): it would not, for example, hand a server
  a cheaply derived password proof just because the server asked for cheap
  parameters.

It does not close the gap: checking what was served *to you, just now*
needs a check on your side, every time.

**Dependencies are part of what holds the key.** Argon2id comes from
`@noble/hashes`, ZIP from `client-zip`; both run in the page that holds
the key. A compromised release of either — or of this library — would
reach users through an application that updates without looking. Pin
exact versions, commit the lockfile (it records a checksum of every
package), and review the diff before updating.

**The page around the library holds the key too.** The library keeps the
key inside its functions, but the page that calls them receives it (from
the link, or unwrapped). An application's own page code is part of what
has to be trusted — and, for the same reason as the library, is best
published.

**Metadata the server needs or sees anyway:**

- the **number of files** and each file's **ciphertext length**, from which
  the plaintext length follows to within a few bytes (PROTOCOL.md §2);
  hiding sizes would mean padding every file;
- **when** a transfer was uploaded, opened and downloaded, and how often;
- who uploaded it (if the application has accounts), and the **IP
  addresses** of everyone involved, like any request;
- whether a password is set, and the application's own limits (expiry,
  download count).

**The sender is not authenticated.** Encryption proves that whoever made
a transfer knew its key — not who that was. Everything in a manifest is
what its author chose to write. The library refuses entries of the wrong
shape (PROTOCOL.md §3), but a well-formed name can still be misleading; it
is text to show, not a claim to trust.

**Passwords are as strong as people make them.** Without a password-
authenticated key exchange (PAKE), a copy of the server's database allows
offline guessing, one Argon2id run per guess. The library refuses passwords
under 12 characters and mere repetition; it cannot refuse common ones
("Password1234" passes). Generated passphrases (`generatePassphrase()`,
about 99 bits) put this out of reach — make them the default, and check
chosen passwords against a local list of common ones if you allow them.

**Downloads are streamed.** A file is decrypted record by record, and each
record is written once it is authenticated. If a later record fails, the
download fails — but what was already written may stay behind as a broken
partial file (PROTOCOL.md §6). Report such a download as failed; decrypt
completely before offering anything that must not exist even in part.

**No content scanning.** The server cannot read the files, so it cannot
check them for malware.

**No revocation of a key.** A link or password that went too far cannot be
changed; the server can only stop serving the transfer.

**No forward secrecy, no deniability.** Out of scope for a file transfer:
whoever has the link and the ciphertext can decrypt it, now or later.

**How far the checks reach.** The format is checked against test vectors
from a second implementation (`test/vectors/reference.js`) that shares no
code with the library — but it was written by the same authors, from the
same specification, so it cannot catch a misunderstanding of that
specification. Randomised tests (`test/fuzz.test.js`, 10,000 cases a
week) look for inputs nobody thought of, within the same limit. An
independent review of the protocol and the code is the step that would; until then, this is a carefully tested library, not a
formally assured one.

## Deploying it so the protection holds

The library cannot enforce these; the application must.

1. **Open transfers on their own origin** (e.g. a separate subdomain) that
   runs nothing but the opening page: no CMS content, no third-party
   script, no analytics script, no ads, no cookies. Any script on that
   origin can read the key.
2. **Strict Content-Security-Policy** there: scripts only from the own
   origin (plus a nonce or hash for anything inline), `connect-src` only what the
   page needs, `frame-ancestors 'none'`, `referrer` `no-referrer`.
3. **`src/browser/take-key.js` first**, as a classic script at the top of
   `<head>`, so the key leaves the address bar before anything else runs.
4. **Serve the library and its dependencies from your own origin** — not
   from a CDN — pinned to exact versions, with the lockfile committed.
5. **The sending side** creates the key. Ideally it runs on the same kind
   of isolated origin. Where it runs on a page with other scripts (a main
   website), those scripts could read the key — say so in your own threat
   model.
6. **Render sender-controlled text as text** (`textContent`), never as
   HTML; offer decrypted files only as downloads, never render them.
7. **Rate-limit password attempts** per transfer and per source
   (PROTOCOL.md §7) — per transfer within a time window, not for the
   transfer's life: a limit that never resets lets anyone with the link
   lock the recipients out until the transfer expires. Count only
   well-formed proofs. Whoever has the link can still renew the window;
   that is the price of capping guesses, and limits per source make it
   costly.
8. **Limit what an upload may cost**: who may create transfers, how many
   bytes one may hold and how long an unfinished one stays. The encrypted
   files are opaque to the server; its quotas are what keep it from being
   an open store. Time out uploads that stop arriving, so a reservation
   cannot be held open.
9. **Refuse state-changing requests from other sites** (Sec-Fetch-Site or
   Origin). The absence of CORS headers stops another site from reading an
   answer, not from sending a request.

## Reporting

See [SECURITY.md](SECURITY.md).
