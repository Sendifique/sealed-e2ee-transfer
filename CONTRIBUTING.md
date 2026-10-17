# Contributing

Thank you for looking closely — for a library like this, careful readers
are the most valuable contributors.

## Security issues

**Never in a public issue.** See [SECURITY.md](SECURITY.md).

## Issues

Welcome: bugs, unclear documentation, questions about the format, gaps in
the threat model, problems with your own implementation of the format
(the test vectors in `test/vectors/` are the place to start).

## Pull requests

Please **open an issue first** and describe the change. This code holds
users' keys; every change is reviewed line by line, and changes to the
format, the key handling or the dependencies need a reason that outweighs
the risk of changing them at all. Small fixes to documentation or tests
are fine without asking.

A pull request:

- keeps the library generic — no application, host or URL scheme in the
  code (`test/structure.test.js`);
- adds no dependency and no build step;
- comes with tests — for anything security-relevant, a positive and a
  negative case;
- updates `README.md` (including its API section), `PROTOCOL.md` and
  `THREAT-MODEL.md` where it changes what they say;
- passes `npm test` on Node 22 or later, and `npm run test:e2e` if it
  touches the browser side;
- uses LF line endings and two-space indentation (`.editorconfig`).

A format change is never an edit to an existing format: it is a new format
number, discussed in an issue before any code. `test/vectors/format-1.json`
never changes.

## Licence

Contributions are accepted under the Apache License 2.0 of this repository
(its section 5). Please do not add names, copyright lines or author tags to
files — Git records authorship. New files start with
`// SPDX-License-Identifier: Apache-2.0`.
