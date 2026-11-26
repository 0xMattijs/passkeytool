package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xMattijs/passkeytool/internal/codegen"
)

func cmdCodegen(args []string) error {
	fs := flag.NewFlagSet("codegen", flag.ExitOnError)
	lang := fs.String("lang", "go", "server language: "+codegenLanguageList())
	specJSON := fs.String("spec", "", `options as JSON, merged over the defaults, e.g. '{"residentKey":"preferred","prf":true}'`)
	out := fs.String("out", "", "directory to write the project to (must not exist or be empty)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: passkeytool codegen -lang LANG -out DIR [-spec JSON]

Generate a complete passkey app: a server, a browser client, and a SQL
schema. Without -out, prints the files to stdout.

Default options:
`)
		b, _ := json.MarshalIndent(codegen.DefaultSpec(), "  ", "  ")
		fmt.Fprintf(os.Stderr, "  %s\n\nFlags:\n", b)
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	spec := codegen.DefaultSpec()
	if *specJSON != "" {
		dec := json.NewDecoder(strings.NewReader(*specJSON))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&spec); err != nil {
			return fmt.Errorf("-spec: %w", err)
		}
	}
	spec.Language = *lang
	res, err := codegen.Generate(spec)
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
	for _, t := range codegen.Targets {
		ids = append(ids, t.ID)
	}
	return strings.Join(ids, ", ")
}
