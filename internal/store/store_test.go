package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestStoreRoundTripKeepsCredentialMetadata(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "data.json"))
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	err := s.Update(func(d *Data) error {
		d.Users = append(d.Users, &User{
			ID:   []byte{1, 2, 3},
			Name: "alice",
			Credentials: []Credential{{
				Credential: webauthn.Credential{ID: []byte{9, 9}, PublicKey: []byte{7}},
				Nickname:   "USB key",
				CreatedAt:  created,
				LastUsedAt: created.Add(time.Hour),
				UseCount:   3,
			}},
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = s.View(func(d *Data) error {
		c := d.UserByName("alice").Credentials[0]
		if c.Nickname != "USB key" || !c.CreatedAt.Equal(created) || c.UseCount != 3 || !c.LastUsedAt.Equal(created.Add(time.Hour)) {
			t.Errorf("metadata lost: %+v", c)
		}
		if string(c.ID) != string([]byte{9, 9}) || string(c.PublicKey) != string([]byte{7}) {
			t.Errorf("credential lost: %+v", c.Credential)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
