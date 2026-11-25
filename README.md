# passkeys-test

A self-contained WebAuthn / passkeys test relying party. It's a single Go
binary: the `serve` command runs a web app for registering and signing in with
passkeys, and the other commands manage the data file.

Use it to see how browsers, platform authenticators, password managers, and
security keys behave with different ceremony options.

## Features

- Registration with configurable `residentKey`, `userVerification`,
  `authenticatorAttachment`, `attestation`, hints, and the `credProps` and
  `prf` extensions.
- Sign-in by username (allow list), discoverable (usernameless), or
  conditional UI (passkeys in username autofill).
- PRF evaluation at sign-in with a salt you choose. The derived secret is
  shown in the log and stripped before the response goes to the server.
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
- Client capability detection (`getClientCapabilities()`, UVPAA, conditional
  mediation).
- Signal API calls (`signalUnknownCredential`,
  `signalAllAcceptedCredentials`) when passkeys are deleted or rejected.

## Build

Requires Go 1.26 or later.

```sh
go build -o passkeys-test .
```

## Run

```sh
./passkeys-test serve
```

Open <http://localhost:8080>.

WebAuthn requires a secure context. `http://localhost` qualifies; any other
host needs HTTPS with a certificate the browser trusts, because self-signed
certificates don't work. To test from a phone or another machine, put the
server behind a tunnel and set the origin to the public URL:

```sh
cloudflared tunnel --url http://localhost:8080
./passkeys-test serve -origin https://example-name.trycloudflare.com
```

The RP ID defaults to the hostname of the first origin.

### `serve` flags

| Flag        | Default              | Description                                   |
|-------------|----------------------|-----------------------------------------------|
| `-addr`     | `localhost:8080`     | Listen address                                |
| `-origin`   | derived from `-addr` | Allowed origins, comma-separated              |
| `-rp-id`    | origin hostname      | Relying party ID                              |
| `-rp-name`  | `Passkeys Test`      | Relying party display name                    |
| `-data`     | `passkeys-data.json` | Data file (also `PASSKEYS_DATA`)              |
| `-tls-cert`, `-tls-key` | —        | Serve HTTPS directly                          |
| `-aaguids`  | user cache dir       | AAGUID name list, or `off`                    |

## Manage data

```sh
./passkeys-test users            # list users
./passkeys-test users -v         # list users and every passkey
./passkeys-test delete-user alice
./passkeys-test delete-credential <credential-id>
./passkeys-test reset -y         # delete everything
./passkeys-test update-aaguids   # refresh the provider name list
```

The CLI reads and writes the same JSON file as the server, so changes show
up in a running server immediately. Deleting a passkey on the server doesn't
remove it from the authenticator; the web UI sends a Signal API hint where
the browser supports it.

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
