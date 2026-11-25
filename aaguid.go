package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// aaguidListURL is the community-maintained list of passkey provider AAGUIDs,
// combined with entries from the FIDO Metadata Service.
const aaguidListURL = "https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/combined_aaguid.json"

type aaguidEntry struct {
	Name      string `json:"name"`
	IconLight string `json:"icon_light,omitempty"`
	IconDark  string `json:"icon_dark,omitempty"`
}

// aaguidDB holds the downloaded list, if loaded.
var aaguidDB atomic.Pointer[map[string]aaguidEntry]

// builtinAAGUIDs is a small offline fallback used when the list isn't loaded.
var builtinAAGUIDs = map[string]string{
	"00000000-0000-0000-0000-000000000000": "(none / zeroed)",
	"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
	"adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
	"fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "Apple Passwords",
	"dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "Apple Passwords (Managed)",
	"08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
	"9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
	"6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
	"bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
	"d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
	"531126d6-e717-415c-9320-3d9aa6981239": "Dashlane",
	"53414d53-554e-4700-0000-000000000000": "Samsung Pass",
	"0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6": "Keeper",
	"b84e4048-15dc-4dd0-8640-f4f60813c8af": "NordPass",
	"b5397666-4885-aa6b-cebf-e52262a439a2": "Chromium Browser",
	"771b48fd-d3d4-4f74-9232-fc157ab0507a": "Edge on Mac",
}

func formatAAGUID(b []byte) string {
	if len(b) != 16 {
		return hex.EncodeToString(b)
	}
	h := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

func lookupAAGUID(b []byte) aaguidEntry {
	id := formatAAGUID(b)
	if db := aaguidDB.Load(); db != nil {
		if e, ok := (*db)[id]; ok {
			return e
		}
	}
	return aaguidEntry{Name: builtinAAGUIDs[id]}
}

func aaguidName(b []byte) string { return lookupAAGUID(b).Name }

func defaultAAGUIDPath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "passkeys-test", "combined_aaguid.json")
}

// loadAAGUIDs reads the list from path and makes it the active list.
func loadAAGUIDs(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var m map[string]aaguidEntry
	if err := json.Unmarshal(b, &m); err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	aaguidDB.Store(&m)
	return len(m), nil
}

// downloadAAGUIDs fetches the list to path, validating it before replacing
// any existing file.
func downloadAAGUIDs(ctx context.Context, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, aaguidListURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "passkeys-test/"+version)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", aaguidListURL, res.Status)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return err
	}
	var m map[string]aaguidEntry
	if err := json.Unmarshal(b, &m); err != nil || len(m) == 0 {
		return fmt.Errorf("downloaded list is not valid: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
