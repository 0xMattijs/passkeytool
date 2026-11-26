# Contributing to passkeytool

Thanks for helping. This guide explains how to propose a change and what a
pull request needs before it's merged.

## Before you start

- **Small fixes**, such as typos, clear bugs, and documentation, can go
  straight to a pull request.
- **Larger changes**, such as a new feature, a new command, or a new code
  generator language, start with an issue. Agree on the approach there before
  you write the code, so your work doesn't get turned down at review.
- **Security vulnerabilities** go through
  [private reporting](https://github.com/0xMattijs/passkeytool/security/advisories/new),
  never a public issue. See [SECURITY.md](SECURITY.md).

## Set up

You need Go 1.26 or later. The end-to-end tests also need Node.js 22.13 or
later, and the runtime of each language you test: Python 3.11, Java 17 with
Maven, or .NET 10.

```sh
go build -o passkeytool .
go test ./...

cd e2e
npm ci
npx playwright install chromium
npm test -- go node   # or leave out the languages to run all five
```

## Make a change

1. Fork the repository and create a branch from `master`.
2. Keep each pull request to one change. Split unrelated fixes into separate
   pull requests.
3. Run `gofmt`, `go vet ./...`, and `go test ./...`.
4. Update the README when you change behavior, flags, or output.
5. Write commit messages in the imperative mood, such as "Add PHP code
   generator", with a body that explains why.

### Code generator changes

All generated apps implement the same HTTP API and share the same client
(`codegen/common/public/`). A change to one language usually applies to all
of them.

- Keep the generated apps behaviorally identical. If a library can't support
  an option, add a note to that target's `unsupported` function in
  `codegen.go` rather than silently dropping the option.
- Pin exact library versions in the version constants in `codegen.go`.
- Make sure `npm test` in `e2e/` passes for every language you touched.
- A new language needs templates under `codegen/<lang>/`, an entry in
  `codegenTargets`, build and start commands in `e2e/run.mjs`, a matrix entry
  in `.github/workflows/ci.yml`, and a row in the README language table.

## Review and merge

- CI must pass: the Go checks and the end-to-end tests for every language.
- The maintainer reviews every pull request. Expect questions and requested
  changes. They're part of the normal process.
- The maintainer may close pull requests that are out of scope, that go
  unanswered for 30 days after review, or that skip the issue step for a
  large change.

## Licensing

passkeytool is licensed under the [MIT License](LICENSE). By submitting a
pull request, you agree to license your contribution under the MIT License.

Code that the generator writes into apps is licensed under 0BSD, so people
can copy it without attribution. By contributing to the templates under
`codegen/`, you also agree that the code they generate is licensed under
0BSD.

## Code of conduct

Be respectful and constructive. Discuss the code, not the person. The
maintainer may hide comments, lock threads, or block users who don't follow
this.
