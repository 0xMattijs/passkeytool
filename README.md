# passkeytool

[![CI](https://github.com/0xMattijs/passkeytool/actions/workflows/ci.yml/badge.svg)](https://github.com/0xMattijs/passkeytool/actions/workflows/ci.yml)

A self-contained WebAuthn / passkeys test relying party. It's a single Go
binary: the `serve` command runs a web app for registering and signing in with
passkeys, and the other commands manage the data file.

Use it to see how browsers, platform authenticators, password managers, and
security keys behave with different ceremony options.

Try it at **<https://passkeytool.alcyon.nl>**, a public test server whose
accounts reset regularly, or [download a release](https://github.com/0xMattijs/passkeytool/releases/latest)
and run it locally.

![passkeytool signed in with a security key: the account's passkey with its
authenticator, AAGUID, and flags, next to the ceremony log](docs/screenshot.png)

## Features

- Registration with configurable `residentKey`, `userVerification`,
  `authenticatorAttachment`, `attestation`, hints, and the `credProps` and
  `prf` extensions.
- Sign-in by username (allow list), discoverable (usernameless), or
  conditional UI (passkeys in username autofill), with optional hints
  (`security-key`, `client-device`, `hybrid`).
- PRF evaluation at sign-in with a salt you choose. Registration requests
  the `prf` extension by default, which security keys need to support PRF
  later. The derived secret is shown in the log and stripped before the
  response goes to the server.
- Multiple passkeys per account, with rename and delete.
- Per-passkey details: provider name and icon (from the AAGUID), attachment,
  transports, attestation format, backup eligibility and state (synced or
  device-bound), UV, sign count, and clone warnings.
- A ceremony log showing the server options, the decoded `clientDataJSON`,
  the parsed authenticator data flags (UP, UV, BE, BS, AT, ED), extension
  results, and the server's verdict.
- An attestation viewer: format, statement type, algorithm, and the
  certificate chain (subject, issuer, validity, AAGUID extension, PEM).
- An options editor that lets you change the options JSON before each
  `navigator.credentials` call, to test edge cases and server checks.
- Log export as JSON, with the browser, server settings, and capabilities,
  for bug reports. PRF outputs are redacted.
- Client capability detection (`getClientCapabilities()`, UVPAA, conditional
  mediation). Each capability has a **(?)** button that explains what it
  means and which part of the page uses it.
- A Developer tab that generates a complete, tested passkey app (Go,
  Node.js, Python, Java, or C#) for the options you choose. See
  [Developer tab and code generator](#developer-tab-and-code-generator).
- A "Manage passkeys" card that detects your browser and OS and lists their
  built-in pages for managing passkeys and security keys, such as
  `chrome://settings/securityKeys`, `about:webauthn`, or Windows passkey
  settings.
- Signal API calls (`signalUnknownCredential`,
  `signalAllAcceptedCredentials`) when passkeys are deleted or rejected.
- Failed API requests are logged by the server with the reason, such as an
  unknown credential ID.
- A `key` command that lists, deletes, and resets the passkeys on a USB
  security key, and sets its PIN (Linux). See [Security keys](#security-keys).

## Install

Download the archive for your platform from the
[latest release](https://github.com/0xMattijs/passkeytool/releases/latest).
Builds are available for Linux and macOS (amd64 and arm64) and Windows
(amd64). The `key` command works only on Linux.

```sh
tar -xzf passkeytool_*_linux_amd64.tar.gz
cd passkeytool_*_linux_amd64
./passkeytool serve
```

Each release includes `SHA256SUMS` and a signed build provenance
attestation. To check that an archive was built by this repository's
release workflow, run:

```sh
gh attestation verify passkeytool_*_linux_amd64.tar.gz --repo 0xMattijs/passkeytool
```

On macOS, a downloaded binary is quarantined. To allow it to run, run
`xattr -d com.apple.quarantine passkeytool`.

### Build from source

Requires Go 1.26 or later.

```sh
go build -o passkeytool .
```

## Run

```sh
./passkeytool serve
```

Open <http://localhost:8080>.

WebAuthn requires a secure context. `http://localhost` qualifies; any other
host needs HTTPS with a certificate the browser trusts, because self-signed
certificates don't work. To test from a phone or another machine, put the
server behind a tunnel and set the origin to the public URL:

```sh
cloudflared tunnel --url http://localhost:8080
./passkeytool serve -origin https://example-name.trycloudflare.com
```

The RP ID defaults to the hostname of the first origin.

### `serve` flags

| Flag        | Default              | Description                                   |
|-------------|----------------------|-----------------------------------------------|
| `-addr`     | `localhost:8080`     | Listen address                                |
| `-origin`   | derived from `-addr` | Allowed origins, comma-separated              |
| `-rp-id`    | origin hostname      | Relying party ID                              |
| `-rp-name`  | `passkeytool`        | Relying party display name                    |
| `-data`     | `passkeys-data.json` | Data file (also `PASSKEYS_DATA`)              |
| `-tls-cert`, `-tls-key` | —        | Serve HTTPS directly                          |
| `-aaguids`  | user cache dir       | AAGUID name list, or `off`                    |
| `-max-users` | `0` (unlimited)     | Maximum number of accounts                    |
| `-max-passkeys` | `0` (unlimited)  | Maximum passkeys per account                  |
| `-rate-limit` | `0` (off)          | State-changing API requests per minute per IP |
| `-trust-proxy` | off               | Take the client IP from the last `X-Forwarded-For` entry |
| `-notice`   | —                    | Notice shown at the top of the web app        |

If the `PORT` environment variable is set, the default listen address is
`:PORT`. The server always caps request bodies at 1 MB, sessions at 10,000,
and names at 64 characters.

## Host it publicly

Running `serve` on the internet needs HTTPS on a real hostname, because
WebAuthn refuses plain HTTP outside localhost. It also needs the limits
above, so strangers can't fill the server's disk or memory. Use
`-trust-proxy` only behind a proxy that appends the client address to
`X-Forwarded-For`; otherwise clients can forge it.

`deploy.sh` deploys the container image to
[Cloud Run](https://cloud.google.com/run), which provides HTTPS and a
`run.app` hostname and fits in the free tier. It builds the image locally
with Docker, so it doesn't need Cloud Build.

```sh
PROJECT=my-project ./deploy.sh
```

The project needs billing enabled and the Cloud Run and Artifact Registry
APIs turned on. Set `REGION` (default `europe-west4`) or `GCLOUD_ACCOUNT` to
override the defaults. To serve on your own domain, map it to the service
(see [Cloud Run domain mapping](https://cloud.google.com/run/docs/mapping-custom-domains))
and set `ORIGIN=https://passkeys.example.com`. The `run.app` URL then keeps
working as a related origin. The service runs one instance at most, because
sessions live in memory, and scales to zero when idle. Data lives in the
container's `/tmp`, so accounts disappear when the container stops. The
notice on the page tells visitors so.

## Manage data

```sh
./passkeytool users            # list users
./passkeytool users -v         # list users and every passkey
./passkeytool delete-user alice
./passkeytool delete-credential <credential-id>
./passkeytool reset -y         # delete everything
./passkeytool update-aaguids   # refresh the provider name list
```

The CLI reads and writes the same JSON file as the server, so changes show
up in a running server immediately. Deleting a passkey on the server doesn't
remove it from the authenticator; the web UI sends a Signal API hint where
the browser supports it.

## Security keys

On Linux, the `key` command manages the passkeys stored on a USB security
key directly over HID, without a browser. Use it to remove passkeys that the
server no longer knows, which otherwise keep showing up in the browser's
account picker.

```sh
./passkeytool key devices                  # list connected keys
./passkeytool key info                     # supported features, free slots, PIN retries
./passkeytool key ls                       # list passkeys (asks for the PIN)
./passkeytool key ls -rp localhost         # only this RP ID
./passkeytool key rm <credential-id>       # delete a passkey (asks for the PIN)
./passkeytool key rm -server <id>          # also delete it from the data file
./passkeytool key pin                      # set or change the PIN
./passkeytool key reset                    # erase all passkeys and the PIN
```

CTAP can't remove a PIN, only change it; a reset is the only way to clear
it. Keys accept a reset only within a few seconds of being plugged in, so
`key reset` asks you to unplug and replug the key, sends the reset as soon
as the key reappears, and then waits for you to touch it.

`key ls` compares each passkey with the data file and shows whether the
server can sign you in with it. With several keys connected, choose one with
`-device /dev/hidrawN`. The key must support CTAP 2.1 credential management
and have a PIN set. If you get a permission error, install your
distribution's FIDO udev rules, for example from the `libfido2` package.

## Developer tab and code generator

The **Developer** tab generates a complete passkey app for the options you
choose: a server, a dependency-free browser client, and a SQLite schema. It
shows the files in **Server**, **Client**, and **Docs** tabs; the client is
the same for every server language. It lists warnings about risky option combinations, keeps the configuration in
the URL so you can share a link, and downloads the project as a zip. The
generated code is licensed 0BSD.

| Server | Library | Stack |
|--------|---------|-------|
| Go | go-webauthn/webauthn | net/http, modernc.org/sqlite |
| Node.js | @simplewebauthn/server | Express 5, node:sqlite |
| Python | py_webauthn | FastAPI, sqlite3 |
| Java | Yubico java-webauthn-server | Spring Boot 4, SQLite JDBC |
| C# | fido2-net-lib | ASP.NET Core minimal API, Microsoft.Data.Sqlite |

The same generator is on the command line:

```sh
./passkeytool codegen -lang node -out ./my-app -spec '{"prf":true,"hints":["security-key"]}'
```

Every server implements the same HTTP API, so one client and one test
cover them all. `go test` renders every option combination for every
language, and the end-to-end suite builds and runs generated apps, then
registers and signs in with Chromium's virtual authenticator:

```sh
cd e2e && npm install && npm test          # all languages
npm test -- go                             # one language
```

## Related origins

`serve` publishes a
[Related Origin Requests](https://passkeys.dev/docs/advanced/related-origins/)
document at `/.well-known/webauthn`, listing every `-origin`. Browsers fetch
it from `https://<rp-id>/.well-known/webauthn` when a page on another origin
uses this RP ID. To test it, serve the same instance on two HTTPS hosts (for
example, two tunnels to one port) and set the RP ID to the first:

```sh
./passkeytool serve -rp-id rp.example.com \
  -origin https://rp.example.com,https://other.example.net
```

## Provider names

Passkey provider names and icons come from the community
[passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids)
list. `serve` downloads it to your user cache directory the first time it
runs; `update-aaguids` refreshes it. Without the list, a few built-in names
are used.

## Notes

- This is a test tool. Sessions are in memory and the data file is plain
  JSON. Don't use it as a production relying party.
- Server-side verification uses
  [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn).

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before you
open a pull request, and report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## License

passkeytool is licensed under the [MIT License](LICENSE). Code that the
generator writes is licensed under 0BSD, so you can copy it into your own
project without attribution.
