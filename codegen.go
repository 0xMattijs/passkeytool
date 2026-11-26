package main

import (
	"archive/zip"
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"text/template"
)

// The code generator turns a ceremony configuration into a complete, small
// passkey app: a browser client, a server in the chosen language, and a SQL
// schema. Every target implements the same HTTP API, so one client and one
// end-to-end test (e2e/) cover them all.

//go:embed all:codegen
var codegenFS embed.FS

// codegenSpec is the language-neutral description of what to generate.
type codegenSpec struct {
	Language         string   `json:"language"`
	RPID             string   `json:"rpId"`
	RPName           string   `json:"rpName"`
	Origin           string   `json:"origin"`
	ResidentKey      string   `json:"residentKey"`
	UserVerification string   `json:"userVerification"`
	Attachment       string   `json:"attachment"`
	Attestation      string   `json:"attestation"`
	Hints            []string `json:"hints"`
	CredProps        bool     `json:"credProps"`
	PRF              bool     `json:"prf"`
	ExcludeExisting  bool     `json:"excludeExisting"`
	ConditionalUI    bool     `json:"conditionalUI"`
}

func defaultCodegenSpec() codegenSpec {
	return codegenSpec{
		Language:         "go",
		RPID:             "localhost",
		RPName:           "Example",
		Origin:           "http://localhost:3000",
		ResidentKey:      "required",
		UserVerification: "preferred",
		Attestation:      "none",
		CredProps:        true,
		ExcludeExisting:  true,
		ConditionalUI:    true,
	}
}

// codegenTarget is one server language and library.
type codegenTarget struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Library    string   `json:"library"`
	LibraryURL string   `json:"libraryUrl"`
	Version    string   `json:"version"`
	Framework  string   `json:"framework"`
	Run        []string `json:"run"`
	// unsupported maps spec features to how the template works around them.
	unsupported func(s codegenSpec) []string
}

// Library versions the templates are written and tested against.
const (
	goWebAuthnVersion   = "v0.18.2"
	goSQLiteVersion     = "v1.63.0"
	simpleWebAuthnVer   = "14.1.0"
	expressVersion      = "5.3.0"
	codegenNodeMinimum  = "22.13"
	codegenGoMinVersion = "1.25"
	pyWebAuthnVersion   = "3.0.1"
	fastapiVersion      = "0.165.0"
	uvicornVersion      = "0.54.0"
	codegenPythonMin    = "3.11"
	yubicoVersion       = "2.10.1"
	springBootVersion   = "4.2.0"
	sqliteJDBCVersion   = "3.54.1.0"
	codegenJavaMin      = "17"
)

var codegenTargets = []codegenTarget{
	{
		ID: "go", Name: "Go", Library: "go-webauthn/webauthn",
		LibraryURL: "https://github.com/go-webauthn/webauthn", Version: goWebAuthnVersion,
		Framework: "net/http, SQLite (modernc.org/sqlite, no cgo)",
		Run:       []string{"go mod tidy", "go run ."},
		unsupported: func(s codegenSpec) []string {
			return nil
		},
	},
	{
		ID: "node", Name: "Node.js", Library: "@simplewebauthn/server",
		LibraryURL: "https://simplewebauthn.dev", Version: simpleWebAuthnVer,
		Framework: "Express 5, node:sqlite (Node " + codegenNodeMinimum + " or later)",
		Run:       []string{"npm install", "npm start"},
		unsupported: func(s codegenSpec) []string {
			var out []string
			if s.Attestation == "indirect" {
				out = append(out, `@simplewebauthn/server has no "indirect" attestation; the generated code sets it on the options JSON directly.`)
			}
			if len(s.Hints) > 0 {
				out = append(out, "@simplewebauthn/server only takes one preferred authenticator type, and none at sign-in; the generated code sets hints on the options JSON directly.")
			}
			if s.PRF {
				out = append(out, "The PRF salt is added to the sign-in options JSON directly, because the library passes extensions through unconverted.")
			}
			return out
		},
	},
	{
		ID: "python", Name: "Python", Library: "py_webauthn",
		LibraryURL: "https://github.com/duo-labs/py_webauthn", Version: pyWebAuthnVersion,
		Framework: "FastAPI, sqlite3 (Python " + codegenPythonMin + " or later)",
		Run:       []string{"python3 -m venv .venv", ".venv/bin/pip install -r requirements.txt", ".venv/bin/python server.py"},
		unsupported: func(s codegenSpec) []string {
			var out []string
			if s.CredProps || s.PRF {
				out = append(out, "py_webauthn has no extensions parameter; the generated code adds credProps and prf to the options JSON directly.")
			}
			if len(s.Hints) > 0 {
				out = append(out, "py_webauthn takes hints at registration only; the generated code adds them to the sign-in options JSON directly.")
			}
			return out
		},
	},
	{
		ID: "java", Name: "Java", Library: "Yubico java-webauthn-server",
		LibraryURL: "https://github.com/Yubico/java-webauthn-server", Version: yubicoVersion,
		Framework: "Spring Boot " + springBootVersion + ", SQLite JDBC (Java " + codegenJavaMin + " or later, Maven)",
		Run:       []string{"mvn -q package -DskipTests", "java -jar target/passkeys.jar"},
		unsupported: func(s codegenSpec) []string {
			if s.Attestation != "none" {
				return []string{"The Yubico library sets the attestation preference on the RelyingParty, so it applies to every registration."}
			}
			return nil
		},
	},
}

func codegenTargetByID(id string) (*codegenTarget, bool) {
	for i := range codegenTargets {
		if codegenTargets[i].ID == id {
			return &codegenTargets[i], true
		}
	}
	return nil, false
}

var (
	validResidentKey = []string{"required", "preferred", "discouraged"}
	validUV          = []string{"required", "preferred", "discouraged"}
	validAttachment  = []string{"", "platform", "cross-platform"}
	validAttestation = []string{"none", "indirect", "direct", "enterprise"}
	validHints       = []string{"security-key", "client-device", "hybrid"}
)

// validate checks the spec and returns the origin's port.
func (s *codegenSpec) validate() (string, error) {
	if _, ok := codegenTargetByID(s.Language); !ok {
		return "", fmt.Errorf("unknown language %q", s.Language)
	}
	check := func(name, v string, allowed []string) error {
		if !slices.Contains(allowed, v) {
			return fmt.Errorf("%s must be one of %q, not %q", name, allowed, v)
		}
		return nil
	}
	if err := errors.Join(
		check("residentKey", s.ResidentKey, validResidentKey),
		check("userVerification", s.UserVerification, validUV),
		check("attachment", s.Attachment, validAttachment),
		check("attestation", s.Attestation, validAttestation),
	); err != nil {
		return "", err
	}
	seen := map[string]bool{}
	for _, h := range s.Hints {
		if err := check("hint", h, validHints); err != nil {
			return "", err
		}
		if seen[h] {
			return "", fmt.Errorf("hint %q is listed twice", h)
		}
		seen[h] = true
	}
	if strings.TrimSpace(s.RPName) == "" {
		return "", errors.New("rpName is required")
	}
	u, err := url.Parse(s.Origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("origin must look like https://example.com or http://localhost:3000, not %q", s.Origin)
	}
	s.Origin = u.Scheme + "://" + u.Host
	host := u.Hostname()
	if s.RPID == "" {
		s.RPID = host
	}
	if host != s.RPID && !strings.HasSuffix(host, "."+s.RPID) {
		return "", fmt.Errorf("the RP ID %q must be the origin's host %q or a parent domain of it", s.RPID, host)
	}
	if u.Scheme == "http" && host != "localhost" && !strings.HasSuffix(host, ".localhost") {
		return "", errors.New("browsers only allow WebAuthn over http on localhost; use an https origin")
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return port, nil
}

// codegenNote is a lint finding or library note shown with the code.
type codegenNote struct {
	Level string `json:"level"` // "warn" or "info"
	Text  string `json:"text"`
}

// lint flags option combinations that tend to surprise developers.
func (s codegenSpec) lint() []codegenNote {
	var out []codegenNote
	warn := func(t string) { out = append(out, codegenNote{"warn", t}) }
	info := func(t string) { out = append(out, codegenNote{"info", t}) }

	if s.ResidentKey == "discouraged" {
		warn("With residentKey discouraged, authenticators may create non-discoverable credentials. Sign-in without a username and autofill (conditional UI) won't find them; users must type their username.")
		if s.ConditionalUI {
			warn("Autofill sign-in needs discoverable credentials, which residentKey discouraged doesn't ask for.")
		}
	}
	if s.Attachment == "platform" && slices.Contains(s.Hints, "security-key") {
		warn(`The "security-key" hint contradicts authenticatorAttachment "platform"; browsers will follow the attachment.`)
	}
	if s.Attachment == "cross-platform" && slices.Contains(s.Hints, "client-device") {
		warn(`The "client-device" hint contradicts authenticatorAttachment "cross-platform"; browsers will follow the attachment.`)
	}
	if s.Attachment == "platform" {
		info("authenticatorAttachment platform excludes security keys and phones. On a computer without a built-in authenticator (for example most Linux desktops), registration fails.")
	}
	if s.UserVerification == "required" {
		info("userVerification required: security keys without a PIN will be asked to set one, and some can't register at all.")
	}
	if s.UserVerification == "discouraged" {
		info("userVerification discouraged: the passkey proves possession only, not who is holding it. Fine as a second factor; weak as the only one.")
	}
	if s.Attestation != "none" {
		info("The generated server stores the attestation but doesn't check it against the FIDO Metadata Service. Only ask for attestation if you'll verify it; some browsers show an extra privacy prompt.")
	}
	if s.PRF {
		info("PRF output is a secret for client-side encryption. The generated client removes it before sending the response to the server. Not every authenticator supports PRF; check the result before relying on it.")
	}
	if !s.ExcludeExisting {
		info("Without excludeCredentials, a user can register the same authenticator twice, which creates duplicate entries in their passkey list.")
	}
	if strings.HasPrefix(s.Origin, "http://") {
		info("http://localhost is fine for development. In production, serve over HTTPS and set the session cookie's Secure flag (the generated code does this for https origins).")
	}
	return out
}

// codegenFile is one generated file.
type codegenFile struct {
	Path     string `json:"path"`
	Language string `json:"language"` // for syntax labels in the UI
	Content  string `json:"content"`
}

type codegenResult struct {
	Spec   codegenSpec    `json:"spec"`
	Target *codegenTarget `json:"target"`
	Files  []codegenFile  `json:"files"`
	Notes  []codegenNote  `json:"notes"`
}

// codegenData is what the templates see.
type codegenData struct {
	codegenSpec
	Port         string
	Secure       bool
	Target       *codegenTarget
	Versions     map[string]string
	PRFSalt      string
	Discoverable bool
}

var codegenFuncs = template.FuncMap{
	"json": func(v any) (string, error) {
		b, err := json.Marshal(v)
		return string(b), err
	},
	"has": func(list []string, v string) bool { return slices.Contains(list, v) },
	// enum turns an option value into a Java enum constant: cross-platform -> CROSS_PLATFORM.
	"enum": func(v string) string { return strings.ToUpper(strings.ReplaceAll(v, "-", "_")) },
	"goHints": func(hints []string) string {
		var parts []string
		for _, h := range hints {
			parts = append(parts, fmt.Sprintf("protocol.PublicKeyCredentialHints(%q)", h))
		}
		return strings.Join(parts, ", ")
	},
}

// generateCode renders the shared files and the target's files.
func generateCode(spec codegenSpec) (*codegenResult, error) {
	port, err := spec.validate()
	if err != nil {
		return nil, err
	}
	target, _ := codegenTargetByID(spec.Language)
	data := codegenData{
		codegenSpec: spec,
		Port:        port,
		Secure:      strings.HasPrefix(spec.Origin, "https://"),
		Target:      target,
		Versions: map[string]string{
			"goWebAuthn": goWebAuthnVersion, "goSQLite": goSQLiteVersion, "go": codegenGoMinVersion,
			"simpleWebAuthn": simpleWebAuthnVer, "express": expressVersion, "node": codegenNodeMinimum,
			"pyWebAuthn": pyWebAuthnVersion, "fastapi": fastapiVersion, "uvicorn": uvicornVersion,
			"yubico": yubicoVersion, "springBoot": springBootVersion, "sqliteJdbc": sqliteJDBCVersion, "java": codegenJavaMin,
		},
		PRFSalt:      "passkey-encryption-key-v1",
		Discoverable: spec.ResidentKey != "discouraged",
	}

	res := &codegenResult{Spec: spec, Target: target, Notes: spec.lint()}
	for _, n := range target.unsupported(spec) {
		res.Notes = append(res.Notes, codegenNote{"info", n})
	}
	for _, dir := range []string{"codegen/common", "codegen/" + target.ID} {
		err := fs.WalkDir(codegenFS, dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			src, err := codegenFS.ReadFile(p)
			if err != nil {
				return err
			}
			tmpl, err := template.New(p).Funcs(codegenFuncs).Parse(string(src))
			if err != nil {
				return fmt.Errorf("template %s: %w", p, err)
			}
			var buf bytes.Buffer
			if err := tmpl.Execute(&buf, data); err != nil {
				return fmt.Errorf("template %s: %w", p, err)
			}
			rel := strings.TrimSuffix(strings.TrimPrefix(p, dir+"/"), ".tmpl")
			content := tidyBlankLines(buf.String())
			if path.Ext(rel) == ".go" {
				formatted, err := format.Source([]byte(content))
				if err != nil {
					return fmt.Errorf("generated %s doesn't parse: %w", rel, err)
				}
				content = string(formatted)
			}
			res.Files = append(res.Files, codegenFile{Path: rel, Language: fileLanguage(rel), Content: content})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	// Server code first, then the client, then supporting files.
	order := func(f codegenFile) int {
		switch {
		case f.Path == "main.go" || f.Path == "server.js" || f.Path == "server.py" || strings.HasSuffix(f.Path, "Controller.java"):
			return 0
		case strings.HasSuffix(f.Path, ".java"):
			return 1
		case strings.HasPrefix(f.Path, "public/"):
			return 2
		case f.Path == "schema.sql":
			return 3
		case f.Path == "README.md":
			return 5
		case f.Path == "LICENSE":
			return 6
		}
		return 4
	}
	slices.SortStableFunc(res.Files, func(a, b codegenFile) int { return order(a) - order(b) })
	return res, nil
}

func fileLanguage(p string) string {
	switch path.Ext(p) {
	case ".go":
		return "go"
	case ".js", ".mjs":
		return "javascript"
	case ".py":
		return "python"
	case ".java":
		return "java"
	case ".xml":
		return "xml"
	case ".properties":
		return "properties"
	case ".html":
		return "html"
	case ".sql":
		return "sql"
	case ".json":
		return "json"
	case ".md":
		return "markdown"
	case ".mod":
		return "go.mod"
	}
	return "text"
}

// tidyBlankLines collapses the runs of blank lines that template
// conditionals leave behind.
func tidyBlankLines(s string) string {
	lines := strings.Split(s, "\n")
	out := lines[:0]
	blank := 0
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			blank++
			if blank > 1 {
				continue
			}
			l = ""
		} else {
			blank = 0
		}
		out = append(out, l)
	}
	return strings.TrimLeft(strings.Join(out, "\n"), "\n")
}

// writeZip writes the generated files into a zip archive under dir/.
func (r *codegenResult) writeZip(w io.Writer, dir string) error {
	zw := zip.NewWriter(w)
	for _, f := range r.Files {
		fw, err := zw.Create(dir + "/" + f.Path)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(fw, f.Content); err != nil {
			return err
		}
	}
	return zw.Close()
}

// ---------- CLI ----------

func cmdCodegen(args []string) error {
	fs := flag.NewFlagSet("codegen", flag.ExitOnError)
	lang := fs.String("lang", "go", "server language: "+codegenLanguageList())
	specJSON := fs.String("spec", "", `options as JSON, merged over the defaults, e.g. '{"residentKey":"preferred","prf":true}'`)
	out := fs.String("out", "", "directory to write the project to (must not exist or be empty)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: passkeys-test codegen -lang LANG -out DIR [-spec JSON]

Generate a complete passkey app: a server, a browser client, and a SQL
schema. Without -out, prints the files to stdout.

Default options:
`)
		b, _ := json.MarshalIndent(defaultCodegenSpec(), "  ", "  ")
		fmt.Fprintf(os.Stderr, "  %s\n\nFlags:\n", b)
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	spec := defaultCodegenSpec()
	if *specJSON != "" {
		dec := json.NewDecoder(strings.NewReader(*specJSON))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&spec); err != nil {
			return fmt.Errorf("-spec: %w", err)
		}
	}
	spec.Language = *lang
	res, err := generateCode(spec)
	if err != nil {
		return err
	}
	for _, n := range res.Notes {
		fmt.Fprintf(os.Stderr, "%s: %s\n", n.Level, n.Text)
	}
	if *out == "" {
		for _, f := range res.Files {
			fmt.Printf("==> %s <==\n%s\n", f.Path, f.Content)
		}
		return nil
	}
	if entries, err := os.ReadDir(*out); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s is not empty", *out)
	}
	for _, f := range res.Files {
		p := filepath.Join(*out, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(f.Content), 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("wrote %d files to %s; run:\n  cd %s\n", len(res.Files), *out, *out)
	for _, c := range res.Target.Run {
		fmt.Printf("  %s\n", c)
	}
	return nil
}

func codegenLanguageList() string {
	var ids []string
	for _, t := range codegenTargets {
		ids = append(ids, t.ID)
	}
	return strings.Join(ids, ", ")
}

// ---------- HTTP ----------

func (s *Server) handleCodegenTargets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"targets": codegenTargets, "defaults": defaultCodegenSpec()})
}

// handleCodegen returns the generated files as JSON, or as a zip with
// ?format=zip.
func (s *Server) handleCodegen(w http.ResponseWriter, r *http.Request) {
	spec := defaultCodegenSpec()
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	res, err := generateCode(spec)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if r.URL.Query().Get("format") != "zip" {
		writeJSON(w, http.StatusOK, res)
		return
	}
	name := "passkeys-" + spec.Language
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.zip"`)
	if err := res.writeZip(w, name); err != nil {
		log.Printf("codegen zip: %v", err)
	}
}
