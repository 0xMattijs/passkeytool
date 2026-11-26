package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

func TestSummarizeAttestation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aaguid := []byte{0xea, 0x9b, 0x8d, 0x66, 0x4d, 0x01, 0x1d, 0x21, 0x3c, 0xe4, 0xb6, 0xb4, 0x8c, 0xb5, 0x75, 0xd4}
	extVal, _ := asn1.Marshal(aaguid)
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(0xABCD),
		Subject:         pkix.Name{CommonName: "Test Attestation", OrganizationalUnit: []string{"Authenticator Attestation"}},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidFIDOAAGUID, Value: extVal}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "packed",
		"authData": make([]byte, 37),
		"attStmt":  map[string]any{"alg": -7, "sig": []byte{1}, "x5c": []any{der}},
	})
	if err != nil {
		t.Fatal(err)
	}

	s := Summarize(raw)
	if s == nil || s.Error != "" {
		t.Fatalf("summary: %+v", s)
	}
	if s.Format != "packed" || s.Algorithm != "ES256 (-7)" || len(s.Certificates) != 1 {
		t.Fatalf("unexpected summary: %+v", s)
	}
	c := s.Certificates[0]
	if c.Subject != "CN=Test Attestation,OU=Authenticator Attestation" || c.Serial != "ABCD" || c.AAGUID != "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4" {
		t.Errorf("unexpected cert: %+v", c)
	}

	if Summarize(nil) != nil {
		t.Error("empty object should give nil")
	}
	if s := Summarize([]byte{0xff}); s == nil || s.Error == "" {
		t.Error("garbage should report an error")
	}
}
