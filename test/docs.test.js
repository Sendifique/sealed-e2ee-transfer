// SPDX-License-Identifier: Apache-2.0
/**
 * test/docs.test.js
 *
 * Keeps the README's API section in step with the code, in both
 * directions: every export of the browser and the server entry point is
 * listed there, and every name listed there is a real export. A new
 * function without documentation, or documentation of a removed one,
 * fails the suite.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

const README = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8')
const PKG = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'))

/** The README's "## API" section, up to the next "## " heading. */
const API = (() => {
  const start = README.indexOf('\n## API\n')
  assert.ok(start >= 0, 'README has an "## API" section')
  const end = README.indexOf('\n## ', start + 1)
  return README.slice(start, end < 0 ? undefined : end)
})()

const browser = Object.keys(await import('../src/browser/index.js'))
const server = Object.keys(await import('../src/server/index.js'))

/** Whether the API section names `name` as code: `name` or `name(…)`. */
const listed = (name) => new RegExp('`' + name + '[`(]').test(API)

test('every export is listed in the README\'s API section', () => {
  for (const name of browser) assert.ok(listed(name), `browser export ${name}`)
  for (const name of server) assert.ok(listed(name), `server export ${name}`)
})

test('every name the API section lists is a real export', () => {
  const exported = new Set([...browser, ...server])
  // The first column of each table row names the export(s) it documents.
  const firstCells = [...API.matchAll(/^\| ([^|]+) \|/gm)].map(m => m[1]).filter(c => c.includes('`'))
  assert.ok(firstCells.length > 40, 'the tables were read')
  for (const cell of firstCells) {
    for (const [, name] of cell.matchAll(/`([A-Za-z_][A-Za-z0-9_]*)[`(]/g)) {
      assert.ok(exported.has(name), `README lists ${name}, which is not exported`)
    }
  }
})

test('the files served as they are are listed too', () => {
  for (const subpath of Object.keys(PKG.exports)) {
    if (!subpath.endsWith('.js')) continue
    assert.ok(API.includes(`${PKG.name}/${subpath.slice(2)}`), `${subpath} in the API section`)
  }
})
