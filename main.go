// Command passkeytool is a WebAuthn / passkeys test tool. Its serve
// subcommand runs a relying party with a web UI; the other subcommands
// inspect and manage the data file.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

var version = "dev"

const defaultDataFile = "passkeys-data.json"

func main() {
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

// ---------- serve ----------

type serveConfig struct {
	Addr    string
	RPID    string
	RPName  string
	Origins []string
	Data    string
	TLSCert string
	TLSKey  string
	AAGUIDs string
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "localhost:8080", "listen address")
	origin := fs.String("origin", "", "allowed origin(s), comma-separated (default: derived from -addr)")
	rpID := fs.String("rp-id", "", "relying party ID (default: hostname of the first origin)")
	rpName := fs.String("rp-name", "passkeytool", "relying party display name")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	tlsKey := fs.String("tls-key", "", "TLS key file")
	data := dataFlag(fs)
	aaguids := fs.String("aaguids", defaultAAGUIDPath(), `AAGUID name list; downloaded on first use ("off" to disable)`)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: passkeytool serve [flags]

WebAuthn needs a secure context. http://localhost works out of the box.
For any other host, serve over HTTPS with a certificate the browser trusts
(for example through a tunnel), and set -origin to the public URL.

Flags:
`)
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	if (*tlsCert == "") != (*tlsKey == "") {
		return errors.New("-tls-cert and -tls-key must be used together")
	}

	cfg := serveConfig{Addr: *addr, RPName: *rpName, Data: *data, TLSCert: *tlsCert, TLSKey: *tlsKey, AAGUIDs: *aaguids}
	if *origin == "" {
		host, port, err := net.SplitHostPort(*addr)
		if err != nil {
			return fmt.Errorf("bad -addr: %w", err)
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "localhost"
		}
		scheme := "http"
		if cfg.TLSCert != "" {
			scheme = "https"
		}
		*origin = fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, port))
	}
	for _, o := range strings.Split(*origin, ",") {
		o = strings.TrimRight(strings.TrimSpace(o), "/")
		if o == "" {
			continue
		}
		u, err := url.Parse(o)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("bad origin %q: want scheme://host[:port]", o)
		}
		cfg.Origins = append(cfg.Origins, o)
	}
	if len(cfg.Origins) == 0 {
		return errors.New("no origins configured")
	}
	cfg.RPID = *rpID
	if cfg.RPID == "" {
		u, _ := url.Parse(cfg.Origins[0])
		cfg.RPID = u.Hostname()
	}

	srv, err := NewServer(cfg, NewStore(cfg.Data))
	if err != nil {
		return err
	}
	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.AAGUIDs != "off" {
		go initAAGUIDs(ctx, cfg.AAGUIDs)
	}
	errc := make(chan error, 1)
	go func() {
		if cfg.TLSCert != "" {
			errc <- httpSrv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			errc <- httpSrv.ListenAndServe()
		}
	}()

	log.Printf("passkeytool %s listening on %s", version, cfg.Addr)
	log.Printf("  RP ID:   %s", cfg.RPID)
	log.Printf("  origins: %s", strings.Join(cfg.Origins, ", "))
	log.Printf("  data:    %s", cfg.Data)
	log.Printf("open %s in your browser", cfg.Origins[0])

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Print("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}

// ---------- data management ----------

func cmdUsers(args []string) error {
	fs := flag.NewFlagSet("users", flag.ExitOnError)
	data := dataFlag(fs)
	verbose := fs.Bool("v", false, "show each passkey")
	_ = fs.Parse(args)

	_, _ = loadAAGUIDs(defaultAAGUIDPath())
	return NewStore(*data).View(func(d *storeData) error {
		if len(d.Users) == 0 {
			fmt.Println("no users")
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		if !*verbose {
			fmt.Fprintln(tw, "USER\tDISPLAY NAME\tPASSKEYS\tCREATED")
			for _, u := range d.Users {
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", u.Name, u.DisplayName, len(u.Credentials), u.CreatedAt.Local().Format(time.DateTime))
			}
			return tw.Flush()
		}
		for _, u := range d.Users {
			fmt.Fprintf(tw, "%s (%s)  id=%s  created %s\n", u.Name, u.DisplayName, b64(u.ID), u.CreatedAt.Local().Format(time.DateTime))
			for _, c := range u.Credentials {
				name := c.Nickname
				if name == "" {
					name = "-"
				}
				fmt.Fprintf(tw, "  %s\n", b64(c.ID))
				fmt.Fprintf(tw, "    name\t%s\n", name)
				fmt.Fprintf(tw, "    aaguid\t%s %s\n", formatAAGUID(c.Authenticator.AAGUID), aaguidName(c.Authenticator.AAGUID))
				fmt.Fprintf(tw, "    attachment\t%s\n", orDefault(string(c.Authenticator.Attachment), "-"))
				fmt.Fprintf(tw, "    transports\t%v\n", c.Transport)
				fmt.Fprintf(tw, "    attestation\t%s / %s\n", orDefault(c.AttestationFormat, "-"), orDefault(c.AttestationType, "-"))
				if a := summarizeAttestation(c.Attestation.Object); a != nil {
					for i, cert := range a.Certificates {
						fmt.Fprintf(tw, "    cert[%d]\t%s (issuer: %s)\n", i, cert.Subject, cert.Issuer)
					}
				}
				fmt.Fprintf(tw, "    flags\tUV=%t BE=%t BS=%t\n", c.Flags.UserVerified, c.Flags.BackupEligible, c.Flags.BackupState)
				fmt.Fprintf(tw, "    signCount\t%d\n", c.Authenticator.SignCount)
				last := "never"
				if !c.LastUsedAt.IsZero() {
					last = c.LastUsedAt.Local().Format(time.DateTime)
				}
				fmt.Fprintf(tw, "    used\t%d times, last %s\n", c.UseCount, last)
			}
			fmt.Fprintln(tw)
		}
		return tw.Flush()
	})
}

func cmdDeleteUser(args []string) error {
	fs := flag.NewFlagSet("delete-user", flag.ExitOnError)
	data := dataFlag(fs)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: passkeytool delete-user [-data FILE] NAME")
	}
	name := fs.Arg(0)
	return NewStore(*data).Update(func(d *storeData) error {
		if !d.deleteUser(name) {
			return fmt.Errorf("user %q not found", name)
		}
		fmt.Printf("deleted user %q\n", name)
		return nil
	})
}

func cmdDeleteCredential(args []string) error {
	fs := flag.NewFlagSet("delete-credential", flag.ExitOnError)
	data := dataFlag(fs)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: passkeytool delete-credential [-data FILE] CREDENTIAL_ID")
	}
	id, err := decodeB64(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("bad credential id: %w", err)
	}
	return NewStore(*data).Update(func(d *storeData) error {
		u, _ := d.credential(id)
		if u == nil {
			return errors.New("credential not found")
		}
		u.deleteCredential(id)
		fmt.Printf("deleted credential from user %q\n", u.Name)
		return nil
	})
}

func cmdReset(args []string) error {
	fs := flag.NewFlagSet("reset", flag.ExitOnError)
	data := dataFlag(fs)
	yes := fs.Bool("y", false, "do not ask for confirmation")
	_ = fs.Parse(args)
	if !*yes {
		fmt.Printf("Delete all users and passkeys in %s? [y/N] ", *data)
		var answer string
		_, _ = fmt.Scanln(&answer)
		if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
			return errors.New("aborted")
		}
	}
	if err := os.Remove(*data); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Println("all data deleted")
	return nil
}

// initAAGUIDs loads the AAGUID list, downloading it first if it's missing.
func initAAGUIDs(ctx context.Context, path string) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		log.Printf("downloading AAGUID list to %s", path)
		if err := downloadAAGUIDs(ctx, path); err != nil {
			log.Printf("AAGUID list download failed, using built-in names: %v", err)
			return
		}
	}
	n, err := loadAAGUIDs(path)
	if err != nil {
		log.Printf("AAGUID list not loaded, using built-in names: %v", err)
		return
	}
	log.Printf("loaded %d AAGUID names from %s", n, path)
}

func cmdUpdateAAGUIDs(args []string) error {
	fs := flag.NewFlagSet("update-aaguids", flag.ExitOnError)
	path := fs.String("file", defaultAAGUIDPath(), "where to store the list")
	_ = fs.Parse(args)
	if err := downloadAAGUIDs(context.Background(), *path); err != nil {
		return err
	}
	n, err := loadAAGUIDs(*path)
	if err != nil {
		return err
	}
	fmt.Printf("saved %d AAGUID names to %s\n", n, *path)
	return nil
}
