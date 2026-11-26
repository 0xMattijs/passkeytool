package codegen

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// codegenCombos returns every combination of the options that change the
// generated code's structure.
func codegenCombos(lang string) []Spec {
	var out []Spec
	hintSets := [][]string{nil, {"security-key"}, {"client-device", "hybrid"}}
	for _, rk := range validResidentKey {
		for _, uv := range validUV {
			for _, att := range validAttachment {
				for _, attest := range validAttestation {
					for _, hints := range hintSets {
						for _, flags := range []int{0, 1, 2, 3} {
							s := DefaultSpec()
							s.Language, s.ResidentKey, s.UserVerification, s.Attachment, s.Attestation, s.Hints = lang, rk, uv, att, attest, hints
							s.PRF = flags&1 != 0
							s.ConditionalUI = flags&2 != 0
							s.CredProps = flags != 1
							s.ExcludeExisting = flags != 2
							out = append(out, s)
						}
					}
				}
			}
		}
	}
	return out
}

func TestCodegenAllCombinations(t *testing.T) {
	for _, target := range Targets {
		n := 0
		for _, spec := range codegenCombos(target.ID) {
			res, err := Generate(spec)
			if err != nil {
				t.Fatalf("%s %+v: %v", target.ID, spec, err)
			}
			for _, f := range res.Files {
				if strings.Contains(f.Content, "<no value>") {
					t.Fatalf("%s %+v: %s has an unresolved template field", target.ID, spec, f.Path)
				}
			}
			n++
		}
		t.Logf("%s: %d combinations", target.ID, n)
	}
}

// TestCodegenScriptsParse checks the syntax of generated JavaScript (node
// --check) and Python (py_compile) for a sample of combinations. Compiled
// languages are checked by the e2e suite.
func TestCodegenScriptsParse(t *testing.T) {
	checkers := map[string][]string{}
	if node, err := exec.LookPath("node"); err == nil {
		checkers[".js"] = []string{node, "--check"}
	}
	if py, err := exec.LookPath("python3"); err == nil {
		checkers[".py"] = []string{py, "-I", "-m", "py_compile"}
	}
	if len(checkers) == 0 {
		t.Skip("neither node nor python3 installed")
	}
	for _, target := range Targets {
		combos := codegenCombos(target.ID)
		for i := 0; i < len(combos); i += 97 {
			res, err := Generate(combos[i])
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			for _, f := range res.Files {
				ext := filepath.Ext(f.Path)
				check, ok := checkers[ext]
				if !ok {
					continue
				}
				name := filepath.Base(f.Path)
				if ext == ".js" {
					name += ".mjs" // parse as an ES module
				}
				p := filepath.Join(dir, name)
				if err := os.WriteFile(p, []byte(f.Content), 0o644); err != nil {
					t.Fatal(err)
				}
				if out, err := exec.Command(check[0], append(check[1:], p)...).CombinedOutput(); err != nil {
					t.Fatalf("%s %s %+v:\n%s", target.ID, f.Path, combos[i], out)
				}
			}
		}
	}
}

func TestCodegenValidation(t *testing.T) {
	bad := []func(*Spec){
		func(s *Spec) { s.Language = "cobol" },
		func(s *Spec) { s.ResidentKey = "always" },
		func(s *Spec) { s.Hints = []string{"usb"} },
		func(s *Spec) { s.Hints = []string{"hybrid", "hybrid"} },
		func(s *Spec) { s.Origin = "http://example.com" },
		func(s *Spec) { s.Origin = "https://example.com"; s.RPID = "other.com" },
		func(s *Spec) { s.Origin = "https://example.com/path" },
		func(s *Spec) { s.RPName = " " },
	}
	for i, mutate := range bad {
		s := DefaultSpec()
		mutate(&s)
		if _, err := Generate(s); err == nil {
			t.Errorf("case %d: invalid spec accepted: %+v", i, s)
		}
	}
	s := DefaultSpec()
	s.Origin, s.RPID = "https://login.example.com", "example.com"
	if _, err := Generate(s); err != nil {
		t.Errorf("parent-domain RP ID rejected: %v", err)
	}
}
