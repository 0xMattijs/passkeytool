package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// User is a registered account. It implements webauthn.User.
type User struct {
	ID          []byte       `json:"id"`
	Name        string       `json:"name"`
	DisplayName string       `json:"displayName"`
	CreatedAt   time.Time    `json:"createdAt"`
	Credentials []Credential `json:"credentials"`
}

// Credential is a WebAuthn credential plus bookkeeping for the test UI.
type Credential struct {
	webauthn.Credential
	Nickname   string    `json:"nickname,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	LastUsedAt time.Time `json:"lastUsedAt,omitzero"`
	UseCount   int       `json:"useCount"`
}

func (u *User) WebAuthnID() []byte          { return u.ID }
func (u *User) WebAuthnName() string        { return u.Name }
func (u *User) WebAuthnDisplayName() string { return u.DisplayName }
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, len(u.Credentials))
	for i, c := range u.Credentials {
		out[i] = c.Credential
	}
	return out
}

type Data struct {
	Users []*User `json:"users"`
}

// Store is a JSON-file-backed user store. Every operation reads the file
// and every mutation writes it back, so CLI commands and a running server
// see each other's changes.
type Store struct {
	path string
	mu   sync.Mutex
}

var ErrNotFound = errors.New("not found")

func New(path string) *Store { return &Store{path: path} }

func (s *Store) load() (*Data, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return &Data{}, nil
	}
	if err != nil {
		return nil, err
	}
	var d Data
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.path, err)
	}
	return &d, nil
}

func (s *Store) save(d *Data) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// View runs fn against a read-only snapshot of the data.
func (s *Store) View(fn func(d *Data) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.load()
	if err != nil {
		return err
	}
	return fn(d)
}

// Update runs fn and saves the result if fn returns nil.
func (s *Store) Update(fn func(d *Data) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.load()
	if err != nil {
		return err
	}
	if err := fn(d); err != nil {
		return err
	}
	return s.save(d)
}

func (d *Data) UserByName(name string) *User {
	for _, u := range d.Users {
		if u.Name == name {
			return u
		}
	}
	return nil
}

func (d *Data) UserByID(id []byte) *User {
	for _, u := range d.Users {
		if bytes.Equal(u.ID, id) {
			return u
		}
	}
	return nil
}

// credential finds a credential by ID across all users.
func (d *Data) FindCredential(id []byte) (*User, int) {
	for _, u := range d.Users {
		for i := range u.Credentials {
			if bytes.Equal(u.Credentials[i].ID, id) {
				return u, i
			}
		}
	}
	return nil, -1
}

func (d *Data) DeleteUser(name string) bool {
	for i, u := range d.Users {
		if u.Name == name {
			d.Users = append(d.Users[:i], d.Users[i+1:]...)
			return true
		}
	}
	return false
}

func (u *User) DeleteCredential(id []byte) bool {
	for i := range u.Credentials {
		if bytes.Equal(u.Credentials[i].ID, id) {
			u.Credentials = append(u.Credentials[:i], u.Credentials[i+1:]...)
			return true
		}
	}
	return false
}

// UnmarshalJSON decodes both the embedded credential and the extra fields.
// Without it, webauthn.Credential's own UnmarshalJSON is promoted and the
// extra fields are silently dropped.
func (c *Credential) UnmarshalJSON(b []byte) error {
	if err := c.Credential.UnmarshalJSON(b); err != nil {
		return err
	}
	var extra struct {
		Nickname   string    `json:"nickname"`
		CreatedAt  time.Time `json:"createdAt"`
		LastUsedAt time.Time `json:"lastUsedAt"`
		UseCount   int       `json:"useCount"`
	}
	if err := json.Unmarshal(b, &extra); err != nil {
		return err
	}
	c.Nickname, c.CreatedAt, c.LastUsedAt, c.UseCount = extra.Nickname, extra.CreatedAt, extra.LastUsedAt, extra.UseCount
	return nil
}

// EncodeID encodes a credential or user ID the way the API and the CLI show
// it: base64url without padding.
func EncodeID(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// DecodeID accepts base64url (padded or not) and standard base64.
func DecodeID(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
