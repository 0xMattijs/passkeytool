package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// codegenCombos returns every combination of the options that change the
// generated code's structure.
func codegenCombos(lang string) []codegenSpec {
	var out []codegenSpec
	hintSets := [][]string{nil, {"security-key"}, {"client-device", "hybrid"}}
	for _, rk := range validResidentKey {
		for _, uv := range validUV {
			for _, att := range validAttachment {
				for _, attest := range validAttestation {
					for _, hints := range hintSets {
						for _, flags := range []int{0, 1, 2, 3} {
							s := defaultCodegenSpec()
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
	for _, target := range codegenTargets {
		n := 0
		for _, spec := range codegenCombos(target.ID) {
			res, err := generateCode(spec)
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

// TestCodegenJavaScriptParses runs node --check on the generated JavaScript
// for a sample of combinations.
func TestCodegenJavaScriptParses(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	for _, target := range codegenTargets {
		combos := codegenCombos(target.ID)
		for i := 0; i < len(combos); i += 97 {
			res, err := generateCode(combos[i])
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			for _, f := range res.Files {
				if !strings.HasSuffix(f.Path, ".js") {
					continue
				}
				p := filepath.Join(dir, filepath.Base(f.Path)+".mjs")
				if err := os.WriteFile(p, []byte(f.Content), 0o644); err != nil {
					t.Fatal(err)
				}
				if out, err := exec.Command(node, "--check", p).CombinedOutput(); err != nil {
					t.Fatalf("%s %s %+v:\n%s", target.ID, f.Path, combos[i], out)
				}
			}
		}
	}
}

func TestCodegenValidation(t *testing.T) {
	bad := []func(*codegenSpec){
		func(s *codegenSpec) { s.Language = "cobol" },
		func(s *codegenSpec) { s.ResidentKey = "always" },
		func(s *codegenSpec) { s.Hints = []string{"usb"} },
		func(s *codegenSpec) { s.Hints = []string{"hybrid", "hybrid"} },
		func(s *codegenSpec) { s.Origin = "http://example.com" },
		func(s *codegenSpec) { s.Origin = "https://example.com"; s.RPID = "other.com" },
		func(s *codegenSpec) { s.Origin = "https://example.com/path" },
		func(s *codegenSpec) { s.RPName = " " },
	}
	for i, mutate := range bad {
		s := defaultCodegenSpec()
		mutate(&s)
		if _, err := generateCode(s); err == nil {
			t.Errorf("case %d: invalid spec accepted: %+v", i, s)
		}
	}
	s := defaultCodegenSpec()
	s.Origin, s.RPID = "https://login.example.com", "example.com"
	if _, err := generateCode(s); err != nil {
		t.Errorf("parent-domain RP ID rejected: %v", err)
	}
}
