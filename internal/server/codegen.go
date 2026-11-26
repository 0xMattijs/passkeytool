package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/0xMattijs/passkeytool/internal/codegen"
)

func (s *Server) handleCodegenTargets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"targets": codegen.Targets, "defaults": codegen.DefaultSpec()})
}

// handleCodegen returns the generated files as JSON, or as a zip with
// ?format=zip.
func (s *Server) handleCodegen(w http.ResponseWriter, r *http.Request) {
	spec := codegen.DefaultSpec()
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	res, err := codegen.Generate(spec)
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
	if err := res.WriteZip(w, name); err != nil {
		log.Printf("codegen zip: %v", err)
	}
}
