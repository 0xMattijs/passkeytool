package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

var oidFIDOAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

type attestationSummary struct {
	Format        string     `json:"format"`
	StatementKeys []string   `json:"statementKeys"`
	Algorithm     string     `json:"algorithm,omitempty"`
	Kind          string     `json:"kind"`
	Certificates  []certInfo `json:"certificates,omitempty"`
	Error         string     `json:"error,omitempty"`
}

type certInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	Serial             string    `json:"serial"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	PublicKeyAlgorithm string    `json:"publicKeyAlgorithm"`
	IsCA               bool      `json:"isCA"`
	AAGUID             string    `json:"aaguid,omitempty"` // from the id-fido-gen-ce-aaguid extension
	SHA256             string    `json:"sha256"`
	PEM                string    `json:"pem"`
}

// coseAlgorithms names the COSE algorithm identifiers seen in practice.
var coseAlgorithms = map[int64]string{
	-7: "ES256", -8: "EdDSA", -35: "ES384", -36: "ES512",
	-37: "PS256", -38: "PS384", -39: "PS512",
	-257: "RS256", -258: "RS384", -259: "RS512", -65535: "RS1",
}

// summarizeAttestation decodes a raw attestation object for display. It
// doesn't verify anything; the library already did that at registration.
func summarizeAttestation(raw []byte) *attestationSummary {
	if len(raw) == 0 {
		return nil
	}
	var ao protocol.AttestationObject
	if err := webauthncbor.Unmarshal(raw, &ao); err != nil {
		return &attestationSummary{Error: fmt.Sprintf("decode attestation object: %v", err)}
	}
	s := &attestationSummary{Format: ao.Format}
	for k := range ao.AttStatement {
		s.StatementKeys = append(s.StatementKeys, k)
	}
	sort.Strings(s.StatementKeys)

	if alg, ok := ao.AttStatement["alg"].(int64); ok {
		s.Algorithm = fmt.Sprintf("%d", alg)
		if name, ok := coseAlgorithms[alg]; ok {
			s.Algorithm = fmt.Sprintf("%s (%d)", name, alg)
		}
	}

	x5c, _ := ao.AttStatement["x5c"].([]any)
	for _, item := range x5c {
		der, ok := item.([]byte)
		if !ok {
			continue
		}
		s.Certificates = append(s.Certificates, describeCert(der))
	}

	switch {
	case ao.Format == "none":
		s.Kind = "none"
	case len(s.Certificates) > 0:
		s.Kind = "basic or attestation CA (certificate chain)"
	case ao.Format == "packed":
		s.Kind = "self attestation (signed by the credential key)"
	default:
		s.Kind = "no certificate chain"
	}
	return s
}

func describeCert(der []byte) certInfo {
	sum := sha256.Sum256(der)
	ci := certInfo{
		SHA256: hex.EncodeToString(sum[:]),
		PEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		ci.Subject = fmt.Sprintf("(unparseable certificate: %v)", err)
		return ci
	}
	ci.Subject = cert.Subject.String()
	ci.Issuer = cert.Issuer.String()
	ci.Serial = strings.ToUpper(cert.SerialNumber.Text(16))
	ci.NotBefore = cert.NotBefore
	ci.NotAfter = cert.NotAfter
	ci.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	ci.PublicKeyAlgorithm = cert.PublicKeyAlgorithm.String()
	ci.IsCA = cert.IsCA
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidFIDOAAGUID) {
			var v []byte
			if _, err := asn1.Unmarshal(ext.Value, &v); err == nil && len(v) == 16 {
				ci.AAGUID = formatAAGUID(v)
			}
		}
	}
	return ci
}
