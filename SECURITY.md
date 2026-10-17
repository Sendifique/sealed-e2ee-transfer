# Security policy

This library holds the key of every transfer while it is in the browser.
Reports are welcome and taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use one of:

- **GitHub private vulnerability reporting:** the "Report a vulnerability"
  button on this repository's *Security* tab.
- **E-mail:** security@sendifique.com — subject starting with `[security]`.

Helpful: what is affected (file, function, format detail), how to
reproduce it, and what an attacker gains. You will get an answer within a
few working days.

## Scope

In scope:

- everything in `src/` and the format in `PROTOCOL.md`;
- how this library uses its dependencies (issues in `@noble/hashes` or
  `client-zip` themselves are best reported to those projects as well);
- documentation that would lead an application to deploy it unsafely
  (`THREAT-MODEL.md`).

Known limits are described in `THREAT-MODEL.md` and are not
vulnerabilities in themselves — for example that the browser runs whatever
code the server delivers. A new way to exploit one of them is in scope.

Out of scope: applications that use this library. Please report to them.

## Supported versions

The latest release. A fix ships as a new release; applications pin
versions and update on their side.
