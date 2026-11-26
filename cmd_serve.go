package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/0xMattijs/passkeytool/internal/aaguid"
	"github.com/0xMattijs/passkeytool/internal/server"
	"github.com/0xMattijs/passkeytool/internal/store"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	defAddr := "localhost:8080"
	if p := os.Getenv("PORT"); p != "" {
		defAddr = ":" + p // Cloud Run and similar platforms
	}
	addr := fs.String("addr", defAddr, "listen address (env PORT sets :PORT)")
	origin := fs.String("origin", "", "allowed origin(s), comma-separated (default: derived from -addr)")
	rpID := fs.String("rp-id", "", "relying party ID (default: hostname of the first origin)")
	rpName := fs.String("rp-name", "passkeytool", "relying party display name")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	tlsKey := fs.String("tls-key", "", "TLS key file")
	data := dataFlag(fs)
	aaguids := fs.String("aaguids", aaguid.DefaultPath(), `AAGUID name list; downloaded on first use ("off" to disable)`)
	maxUsers := fs.Int("max-users", 0, "maximum number of accounts (0: unlimited)")
	maxPasskeys := fs.Int("max-passkeys", 0, "maximum passkeys per account (0: unlimited)")
	rateLimit := fs.Int("rate-limit", 0, "state-changing API requests per minute per client IP (0: off)")
	trustProxy := fs.Bool("trust-proxy", false, "take the client IP from the last X-Forwarded-For entry (only behind a proxy that sets it)")
	notice := fs.String("notice", "", "notice shown at the top of the web app, such as data retention for a public server")
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

	cfg := server.Config{
		Addr: *addr, RPName: *rpName, Data: *data, TLSCert: *tlsCert, TLSKey: *tlsKey, AAGUIDs: *aaguids,
		MaxUsers: *maxUsers, MaxPasskeys: *maxPasskeys, RateLimit: *rateLimit, TrustProxy: *trustProxy, Notice: *notice,
		Version: version,
	}
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

	srv, err := server.New(cfg, store.New(cfg.Data))
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

// initAAGUIDs loads the AAGUID list, downloading it first if it's missing.
func initAAGUIDs(ctx context.Context, path string) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		log.Printf("downloading AAGUID list to %s", path)
		if err := aaguid.Download(ctx, path); err != nil {
			log.Printf("AAGUID list download failed, using built-in names: %v", err)
			return
		}
	}
	n, err := aaguid.Load(path)
	if err != nil {
		log.Printf("AAGUID list not loaded, using built-in names: %v", err)
		return
	}
	log.Printf("loaded %d AAGUID names from %s", n, path)
}

func cmdUpdateAAGUIDs(args []string) error {
	fs := flag.NewFlagSet("update-aaguids", flag.ExitOnError)
	path := fs.String("file", aaguid.DefaultPath(), "where to store the list")
	_ = fs.Parse(args)
	if err := aaguid.Download(context.Background(), *path); err != nil {
		return err
	}
	n, err := aaguid.Load(*path)
	if err != nil {
		return err
	}
	fmt.Printf("saved %d AAGUID names to %s\n", n, *path)
	return nil
}
