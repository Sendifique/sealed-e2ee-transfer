// SPDX-License-Identifier: Apache-2.0
/**
 * src/browser/index.js
 *
 * The browser API of this package: encryption (sealed.js), the format
 * constants (format.js) and saving downloads (save.js). Two more files are
 * served as they are rather than imported: take-key.js (classic
 * script, first on the opening page) and sw.js (the service worker).
 */

export * from './sealed.js'
export * from './save.js'
export {
  RECORD_SIZE, HEADER_LENGTH, SALT_LENGTH, READER_TOKEN_LENGTH, KDF_BOUNDS, plaintextSize
} from '../format.js'
