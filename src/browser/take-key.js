// SPDX-License-Identifier: Apache-2.0
/**
 * src/browser/take-key.js
 *
 * The first script on a page that opens a transfer. Load it as a classic,
 * synchronous script at the top of <head> — before any other script, and
 * before any module (modules are deferred and would run too late).
 *
 * It takes the transfer key out of the #fragment and removes it from the
 * address bar and the history entry, so the key is not in a bookmark, a
 * screenshot of the URL bar, or the reach of any later script that reads
 * location. The page's module gets the key exactly once:
 *
 *     const key = window.__sealedKey()   // the key, or null; later calls: null
 *
 * The function cannot be replaced by a later script (non-writable,
 * non-configurable).
 */

;(function () {
  'use strict'

  var key = location.hash && location.hash.length > 1 ? location.hash.slice(1) : null
  if (location.hash) history.replaceState(null, '', location.pathname + location.search)
  Object.defineProperty(window, '__sealedKey', {
    value: function () { var k = key; key = null; return k }
  })
})()
