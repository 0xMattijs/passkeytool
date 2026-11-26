// Command passkeytool is a WebAuthn / passkeys test tool. Its serve
// subcommand runs a relying party with a web UI; the other subcommands
// inspect and manage the data file.
package main

import (
	"flag"
	"fmt"
	"github.com/0xMattijs/passkeytool/internal/aaguid"
	"log"
	"os"
)

var version = "dev"

const defaultDataFile = "passkeys-data.json"

func main() {
	aaguid.UserAgent = "passkeytool/" + version
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "users", "ls":
		err = cmdUsers(args)
	case "delete-user":
		err = cmdDeleteUser(args)
	case "delete-credential":
		err = cmdDeleteCredential(args)
	case "reset":
		err = cmdReset(args)
	case "update-aaguids":
		err = cmdUpdateAAGUIDs(args)
	case "key":
		err = cmdKey(args)
	case "codegen":
		err = cmdCodegen(args)
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `passkeytool: a WebAuthn / passkeys test relying party

Usage:
  passkeytool <command> [flags]

Commands:
  serve               Run the web app and WebAuthn API
  users               List users and their passkeys (-v for details)
  delete-user NAME    Delete a user and all their passkeys
  delete-credential ID
                      Delete one passkey by credential ID (base64url)
  reset               Delete all data
  update-aaguids      Download the passkey provider (AAGUID) name list
  key                 Manage passkeys on a USB security key (devices, info,
                      ls, rm, pin, reset)
  codegen             Generate a complete passkey app (server, client, schema)
  version             Print the version

Run 'passkeytool <command> -h' for command flags.
`)
}

func dataFlag(fs *flag.FlagSet) *string {
	def := defaultDataFile
	if v := os.Getenv("PASSKEYS_DATA"); v != "" {
		def = v
	}
	return fs.String("data", def, "path to the JSON data file (env PASSKEYS_DATA)")
}
