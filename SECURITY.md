# Security policy

## Report a vulnerability

Report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/0xMattijs/passkeytool/security/advisories/new).
Don't open a public issue or pull request.

Include the affected component, the steps to reproduce, and the impact. You
can expect a first response within 7 days.

## Scope

In scope:

- **Generated apps:** flaws in the code that `codegen` and the Developer tab
  generate, such as missing verification steps, challenge reuse, or session
  handling bugs. People copy this code into real projects, so these reports
  matter most.
- **The `key` command:** flaws in how it handles PINs, PIN tokens, or
  credentials on a security key.

Out of scope:

- **The `serve` test server** isn't a production relying party. It keeps
  sessions in memory, stores data as plain JSON, and is meant to run on
  `localhost`. Weaknesses that follow from that design aren't
  vulnerabilities, but report anything that lets a remote site attack a
  developer running it.

## Supported versions

Only the latest commit on `master` gets fixes.
