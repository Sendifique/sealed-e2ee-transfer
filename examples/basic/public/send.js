// SPDX-License-Identifier: Apache-2.0
/**
 * examples/basic/public/send.js
 *
 * The sending page: encrypts the chosen files in the browser, uploads the
 * ciphertext, stores the record and shows the link. Everything that touches
 * the key is in createUpload(); this page only moves bytes.
 *
 * For brevity each encrypted file is collected into a Blob before it is
 * uploaded. A real application streams it instead (e.g. with tus), so file
 * size does not matter.
 */

import { createUpload, isSupported, checkNewPassword, generatePassphrase } from '/lib/browser/index.js'

const $ = (id) => document.getElementById(id)

function status (text, isError = false) {
  $('status').textContent = text
  $('status').classList.toggle('error', isError)
}

async function json (method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body ? { 'content-type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined
  })
  if (!res.ok) throw new Error(`${method} ${url}: ${res.status}`)
  return res.status === 204 ? null : res.json()
}

// A generated passphrase is the default: a chosen password is only as
// strong as the person choosing it (THREAT-MODEL.md).
$('use-password').addEventListener('change', () => {
  $('password-fields').hidden = !$('use-password').checked
  if ($('use-password').checked && !$('password').value) $('password').value = generatePassphrase()
})
$('generate').addEventListener('click', () => {
  $('password').value = generatePassphrase()
})

$('form').addEventListener('submit', async (event) => {
  event.preventDefault()
  $('result').hidden = true
  if (!isSupported()) return status('This browser cannot encrypt files.', true)

  // null = link variant. A checked box with an empty field is an error,
  // never a silent switch to the link variant.
  const password = $('use-password').checked ? $('password').value : null
  if (password !== null) {
    try {
      checkNewPassword(password)
    } catch (err) {
      return status(err.message, true)
    }
  }

  const files = [...$('files').files]
  $('send').disabled = true
  try {
    const { id } = await json('POST', '/api/transfers')
    const upload = createUpload()

    for (const [i, file] of files.entries()) {
      status(`Encrypting and uploading ${file.name} …`)
      const reader = await upload.reader(file, i)
      const chunks = []
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        chunks.push(value)
      }
      const res = await fetch(`/api/transfers/${id}/files/${i}`, { method: 'PUT', body: new Blob(chunks) })
      if (!res.ok) throw new Error(`upload of file ${i}: ${res.status}`)
    }

    status(password ? 'Securing the password …' : 'Finishing …')
    const record = await upload.finalize({
      files: files.map(f => ({ name: f.name, path: f.webkitRelativePath || null, size: f.size, type: f.type })),
      password,
      bindTo: `example-v1:${id}`
    })
    // The count lets the server check that every file arrived; the
    // manifest that lists them is encrypted.
    await json('POST', `/api/transfers/${id}/finalize`, { ...record, fileCount: files.length })

    const link = upload.shareLink(`${location.origin}/t/${id}`)
    $('link').href = link
    $('link').textContent = link
    $('result').hidden = false
    status(password ? 'Done. Send the link — and the password by another channel.' : 'Done. The link holds the key: anyone with it can open the files.')
  } catch (err) {
    status(`Failed: ${err.message}`, true)
  } finally {
    $('send').disabled = false
  }
})
