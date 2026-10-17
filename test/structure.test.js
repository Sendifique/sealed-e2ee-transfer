// SPDX-License-Identifier: Apache-2.0
/**
 * test/structure.test.js
 *
 * Keeps the library a library:
 *   - the server side imports only the shared format and Node's modules;
 *   - browser code imports its own files by relative path, and other code
 *     only from the packages declared in package.json "dependencies";
 *   - no code names a particular application, host or URL scheme. What an
 *     application decides (where pages live, what the manifest carries,
 *     what a wrapped key is bound to) is passed in;
 *   - every own file carries the licence identifier, and no file names a
 *     person.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const PKG = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'))

function files (dir) {
  return fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true }).flatMap(e =>
    e.isDirectory() ? files(path.join(dir, e.name)) : [path.join(dir, e.name)])
}

/**
 * Every static import / re-export specifier of a module — real statements
 * only: comments are removed first, and a statement may not span lines
 * other than its own (examples in JSDoc are not imports).
 */
function imports (file) {
  const src = fs.readFileSync(path.join(ROOT, file), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '')
  return [...src.matchAll(/^\s*(?:import|export)\b[^'";]*?\bfrom\s+['"]([^'"]+)['"]/gm)].map(m => m[1])
}

/** Where a relative specifier of `file` points, relative to the package root. */
function target (file, spec) {
  return path.relative(ROOT, path.resolve(ROOT, path.dirname(file), spec)).split(path.sep).join('/')
}

/** The package a bare specifier names: '@scope/name/sub.js' → '@scope/name'. */
function packageOf (spec) {
  const parts = spec.split('/')
  return spec.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0]
}

const js = (dir) => files(dir).filter(f => f.endsWith('.js'))

test('the server imports only the shared format and Node\'s own modules', () => {
  for (const file of js('src/server')) {
    for (const spec of imports(file)) {
      assert.ok(spec.startsWith('node:') || target(file, spec) === 'src/format.js', `${file} imports ${spec}`)
    }
  }
})

test('browser code imports its own files, or declared dependencies only', () => {
  const declared = Object.keys(PKG.dependencies || {})
  for (const file of js('src/browser')) {
    for (const spec of imports(file)) {
      if (spec.startsWith('.')) {
        const to = target(file, spec)
        assert.ok(to.startsWith('src/browser/') || to === 'src/format.js', `${file} reaches ${to}`)
        assert.ok(fs.existsSync(path.join(ROOT, to)), `${file}: ${spec} exists`)
      } else {
        assert.ok(declared.includes(packageOf(spec)), `${file}: ${spec} is not a declared dependency`)
      }
    }
  }
})

test('dependencies are few and known', () => {
  assert.deepEqual(Object.keys(PKG.dependencies).sort(), ['@noble/hashes', 'client-zip'])
})

test('no code names a particular application, host or URL scheme', () => {
  for (const file of [...files('src'), ...files('test'), ...files('examples'), ...files('e2e')]) {
    if (file.endsWith('structure.test.js')) continue
    const src = fs.readFileSync(path.join(ROOT, file), 'utf8').toLowerCase()
    for (const marker of ['sendifique', 'vertraulich', 'matomo', '/c/']) {
      assert.ok(!src.includes(marker), `${file} mentions ${marker}`)
    }
  }
})

test('no file hides text behind bidirectional controls ("Trojan Source")', () => {
  // Such characters make code read differently from how it runs; where a
  // test needs one, it writes it as an escape (\u202E), never as itself.
  const text = /\.(js|json|md|yml|html|css)$/
  const docs = fs.readdirSync(ROOT).filter(f => text.test(f))
  for (const file of [...files('src'), ...files('test'), ...files('examples'), ...files('e2e'), ...files('.github'), ...docs]) {
    if (!text.test(file)) continue
    const src = fs.readFileSync(path.join(ROOT, file), 'utf8')
    assert.ok(!/[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/.test(src), `${file}: bidirectional control character`)
  }
})

test('every own file carries the Apache-2.0 SPDX line, and no file names a person', () => {
  const own = [...js('src'), ...js('test'), ...js('examples'), ...js('e2e')]
  for (const file of own) {
    const src = fs.readFileSync(path.join(ROOT, file), 'utf8')
    assert.ok(src.startsWith('// SPDX-License-Identifier: Apache-2.0\n'), `${file}: SPDX line first`)
  }
  for (const file of [...own, 'LICENSE', 'package.json']) {
    if (file.endsWith('structure.test.js')) continue  // holds the patterns themselves
    const src = fs.readFileSync(path.join(ROOT, file), 'utf8')
    assert.ok(!/@author\b|@created\b/.test(src), `${file}: no author tags`)
    assert.ok(!/copyright \(c\) \d{4}/i.test(src), `${file}: no copyright line`)
  }
  assert.equal(PKG.license, 'Apache-2.0')
})
