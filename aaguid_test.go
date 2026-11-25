package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLookupAAGUID(t *testing.T) {
	gpm := []byte{0xea, 0x9b, 0x8d, 0x66, 0x4d, 0x01, 0x1d, 0x21, 0x3c, 0xe4, 0xb6, 0xb4, 0x8c, 0xb5, 0x75, 0xd4}
	other := make([]byte, 16)
	other[0] = 0x42

	aaguidDB.Store(nil)
	if got := aaguidName(gpm); got != "Google Password Manager" {
		t.Errorf("built-in fallback: got %q", got)
	}

	path := filepath.Join(t.TempDir(), "list.json")
	list := `{"42000000-0000-0000-0000-000000000000": {"name": "Test Key", "icon_light": "data:x"}}`
	if err := os.WriteFile(path, []byte(list), 0o644); err != nil {
		t.Fatal(err)
	}
	if n, err := loadAAGUIDs(path); err != nil || n != 1 {
		t.Fatalf("load: n=%d err=%v", n, err)
	}
	t.Cleanup(func() { aaguidDB.Store(nil) })

	if e := lookupAAGUID(other); e.Name != "Test Key" || e.IconLight != "data:x" {
		t.Errorf("loaded list: got %+v", e)
	}
	if got := aaguidName(gpm); got != "Google Password Manager" {
		t.Errorf("fallback after load: got %q", got)
	}
}
