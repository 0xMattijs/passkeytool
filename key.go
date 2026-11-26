package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"
)

// The key command manages discoverable credentials stored on a USB security
// key, talking CTAP2 over HID directly. It's an alternative to the browser
// pages (chrome://settings/securityKeys, about:webauthn) for cleaning up
// passkeys that the server no longer knows.

func cmdKey(args []string) error {
	if len(args) == 0 {
		keyUsage()
		return errors.New("missing key subcommand")
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "devices":
		return cmdKeyDevices(args)
	case "info":
		return cmdKeyInfo(args)
	case "ls", "list":
		return cmdKeyList(args)
	case "rm", "delete":
		return cmdKeyDelete(args)
	case "pin":
		return cmdKeyPIN(args)
	case "reset":
		return cmdKeyReset(args)
	case "help", "-h", "--help":
		keyUsage()
		return nil
	}
	keyUsage()
	return fmt.Errorf("unknown key subcommand %q", sub)
}

func keyUsage() {
	fmt.Fprint(os.Stderr, `Usage: passkeys-test key <subcommand> [flags]

Manage passkeys stored on a USB security key (Linux, CTAP 2.1).

Subcommands:
  devices             List connected FIDO security keys
  info                Show what the key supports (no PIN needed)
  ls                  List the passkeys on the key (asks for the PIN)
  rm CREDENTIAL_ID    Delete a passkey from the key (asks for the PIN);
                      -server also deletes it from the data file
  pin                 Set the key's PIN, or change it
  reset               Erase all passkeys and the PIN (factory reset)

Flags:
  -device PATH        The key to use, such as /dev/hidraw2 (default: the
                      only connected key)
`)
}

func deviceFlag(fs *flag.FlagSet) *string {
	return fs.String("device", "", "hidraw device of the key (default: the only connected key)")
}

func cmdKeyDevices(args []string) error {
	fs := flag.NewFlagSet("key devices", flag.ExitOnError)
	_ = fs.Parse(args)
	devs, err := findFIDODevices()
	if err != nil {
		return err
	}
	if len(devs) == 0 {
		fmt.Println("no FIDO security keys found")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "DEVICE\tUSB ID\tNAME")
	for _, d := range devs {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", d.Path, orDefault(d.USBID, "-"), orDefault(d.Name, "-"))
	}
	return tw.Flush()
}

// openKey opens the given device, or the only connected FIDO key.
func openKey(path string) (*ctapDevice, hidDeviceInfo, error) {
	var info hidDeviceInfo
	devs, err := findFIDODevices()
	if err != nil {
		return nil, info, err
	}
	if path == "" {
		switch len(devs) {
		case 0:
			return nil, info, errors.New("no FIDO security key found; plug one in or pass -device")
		case 1:
			info = devs[0]
		default:
			var paths []string
			for _, d := range devs {
				paths = append(paths, fmt.Sprintf("%s (%s)", d.Path, d.Name))
			}
			return nil, info, fmt.Errorf("several keys connected, choose one with -device: %s", strings.Join(paths, ", "))
		}
	} else {
		info = hidDeviceInfo{Path: path}
		for _, d := range devs {
			if d.Path == path {
				info = d
			}
		}
	}
	t, err := openHID(info.Path)
	if err != nil {
		return nil, info, err
	}
	d, err := newCTAPDevice(t)
	if err != nil {
		t.Close()
		return nil, info, fmt.Errorf("%s: %w", info.Path, err)
	}
	return d, info, nil
}

func keyLabel(dev hidDeviceInfo, info *authenticatorInfo) string {
	name := aaguidName(info.AAGUID)
	if name == "" {
		name = orDefault(dev.Name, "security key")
	}
	return fmt.Sprintf("%s (%s)", name, dev.Path)
}

func cmdKeyInfo(args []string) error {
	fs := flag.NewFlagSet("key info", flag.ExitOnError)
	device := deviceFlag(fs)
	_ = fs.Parse(args)

	d, dev, err := openKey(*device)
	if err != nil {
		return err
	}
	defer d.Close()
	info, err := d.getInfo()
	if err != nil {
		return err
	}
	_, _ = loadAAGUIDs(defaultAAGUIDPath())

	var opts []string
	for k, v := range info.Options {
		opts = append(opts, fmt.Sprintf("%s=%t", k, v))
	}
	slices.Sort(opts)
	var algs []string
	for _, a := range info.Algorithms {
		name := coseAlgorithms[a.Alg]
		if name == "" {
			name = fmt.Sprint(a.Alg)
		}
		algs = append(algs, name)
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "device\t%s\n", dev.Path)
	fmt.Fprintf(tw, "name\t%s\n", orDefault(dev.Name, "-"))
	fmt.Fprintf(tw, "usb id\t%s\n", orDefault(dev.USBID, "-"))
	fmt.Fprintf(tw, "aaguid\t%s %s\n", formatAAGUID(info.AAGUID), aaguidName(info.AAGUID))
	fmt.Fprintf(tw, "versions\t%s\n", strings.Join(info.Versions, " "))
	fmt.Fprintf(tw, "extensions\t%s\n", orDefault(strings.Join(info.Extensions, " "), "-"))
	fmt.Fprintf(tw, "options\t%s\n", strings.Join(opts, " "))
	fmt.Fprintf(tw, "pin protocols\t%v\n", info.PinUvAuthProtocols)
	if len(algs) > 0 {
		fmt.Fprintf(tw, "algorithms\t%s\n", strings.Join(algs, " "))
	}
	if info.MinPINLength > 0 {
		fmt.Fprintf(tw, "min PIN length\t%d\n", info.MinPINLength)
	}
	if info.FirmwareVersion > 0 {
		fmt.Fprintf(tw, "firmware\t%d\n", info.FirmwareVersion)
	}
	if info.RemainingDiscoverable != nil {
		fmt.Fprintf(tw, "free passkey slots\t%d\n", *info.RemainingDiscoverable)
	}
	if info.Options["clientPin"] {
		if n, err := d.pinRetries(); err == nil {
			fmt.Fprintf(tw, "PIN retries left\t%d\n", n)
		}
	}
	cm := "not supported"
	switch info.credMgmtCommand() {
	case ctapCredMgmt:
		cm = "supported"
	case ctapCredMgmtPreview:
		cm = "supported (CTAP 2.1 preview)"
	}
	fmt.Fprintf(tw, "credential management\t%s\n", cm)
	return tw.Flush()
}

var stdin = bufio.NewReader(os.Stdin)

func readPIN(prompt string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := stdin.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// openCredManager opens the key and authenticates with its PIN.
func openCredManager(device string) (*ctapDevice, *credManager, string, error) {
	d, dev, err := openKey(device)
	if err != nil {
		return nil, nil, "", err
	}
	info, err := d.getInfo()
	if err != nil {
		d.Close()
		return nil, nil, "", err
	}
	_, _ = loadAAGUIDs(defaultAAGUIDPath())
	label := keyLabel(dev, info)
	cmd := info.credMgmtCommand()
	if cmd == 0 {
		d.Close()
		return nil, nil, "", fmt.Errorf("%s doesn't support credential management (it needs CTAP 2.1)", label)
	}
	if !info.Options["clientPin"] {
		d.Close()
		return nil, nil, "", fmt.Errorf("%s has no PIN set; set one with: passkeys-test key pin", label)
	}
	if info.ForcePINChange {
		d.Close()
		return nil, nil, "", fmt.Errorf("%s requires a new PIN before use; change it with: passkeys-test key pin", label)
	}
	pin, err := readPIN("PIN for " + label)
	if err != nil {
		d.Close()
		return nil, nil, "", err
	}
	token, err := d.getPinToken(info, pin)
	if err != nil {
		d.Close()
		return nil, nil, "", err
	}
	return d, &credManager{d: d, cmd: cmd, token: token}, label, nil
}

func cmdKeyList(args []string) error {
	fs := flag.NewFlagSet("key ls", flag.ExitOnError)
	device := deviceFlag(fs)
	rpFlag := fs.String("rp", "", "only list passkeys for this RP ID")
	data := dataFlag(fs)
	_ = fs.Parse(args)

	d, m, label, err := openCredManager(*device)
	if err != nil {
		return err
	}
	defer d.Close()

	var rps []keyRPEntry
	if *rpFlag != "" {
		rps = []keyRPEntry{{RP: keyRP{ID: *rpFlag}, IDHash: rpIDHash(*rpFlag)}}
	} else if rps, err = m.relyingParties(); err != nil {
		return fmt.Errorf("list relying parties: %w", err)
	}

	var server *storeData
	_ = NewStore(*data).View(func(sd *storeData) error { server = sd; return nil })

	existing, remaining, err := m.metadata()
	if err == nil {
		fmt.Printf("%s: %d passkeys stored, room for %d more\n\n", label, existing, remaining)
	} else {
		fmt.Printf("%s\n\n", label)
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "RP ID\tUSER\tCREDENTIAL ID\tPROTECTION\tON SERVER")
	n := 0
	for _, rp := range rps {
		creds, err := m.credentials(rp.IDHash)
		if err != nil {
			return fmt.Errorf("list passkeys for %s: %w", orDefault(rp.RP.ID, b64(rp.IDHash)), err)
		}
		for _, c := range creds {
			n++
			user := orDefault(c.User.Name, b64(c.User.ID))
			if c.User.DisplayName != "" && c.User.DisplayName != c.User.Name {
				user += " (" + c.User.DisplayName + ")"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", orDefault(rp.RP.ID, "sha256:"+b64(rp.IDHash)), user, b64(c.ID), credProtectName(c.CredProtect), serverStatus(server, c))
		}
	}
	if n == 0 {
		if *rpFlag != "" {
			fmt.Printf("no passkeys for %s on this key\n", *rpFlag)
		} else {
			fmt.Println("no passkeys on this key")
		}
		return nil
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Printf("\nPROTECTION is the credProtect level: when the key releases the passkey without UV.\n")
	fmt.Printf("ON SERVER compares with %s. \"no\" means the server can't sign you in with that passkey.\n", *data)
	return nil
}

// credProtectName describes a credProtect level (CTAP 2.1 §12.1).
func credProtectName(level uint) string {
	switch level {
	case 1:
		return "UV optional"
	case 2:
		return "UV or ID list"
	case 3:
		return "UV required"
	}
	return "-"
}

// serverStatus says whether the server's data file knows a credential.
func serverStatus(server *storeData, c keyCredential) string {
	if server == nil {
		return "?"
	}
	if u, _ := server.credential(c.ID); u != nil {
		return "yes (" + u.Name + ")"
	}
	if u := server.userByID(c.User.ID); u != nil {
		return "no (account " + u.Name + " exists)"
	}
	return "no"
}

func cmdKeyDelete(args []string) error {
	fs := flag.NewFlagSet("key rm", flag.ExitOnError)
	device := deviceFlag(fs)
	yes := fs.Bool("y", false, "do not ask for confirmation")
	alsoServer := fs.Bool("server", false, "also delete the passkey from the data file")
	data := dataFlag(fs)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: passkeys-test key rm [-device PATH] [-y] [-server] CREDENTIAL_ID")
	}
	id, err := decodeB64(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("bad credential id: %w", err)
	}

	d, m, label, err := openCredManager(*device)
	if err != nil {
		return err
	}
	defer d.Close()

	rp, cred, err := m.findCredential(id)
	if err != nil {
		return err
	}
	if cred == nil {
		return fmt.Errorf("passkey %s isn't on %s; it may be stored in a password manager instead", b64(id), label)
	}
	desc := fmt.Sprintf("the passkey for %s at %s", orDefault(cred.User.Name, b64(cred.User.ID)), orDefault(rp.RP.ID, "sha256:"+b64(rp.IDHash)))
	if !*yes {
		fmt.Printf("Delete %s from %s? This can't be undone. [y/N] ", desc, label)
		answer, _ := stdin.ReadString('\n')
		answer = strings.TrimSpace(answer)
		if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
			return errors.New("aborted")
		}
	}
	if err := m.deleteCredential(id); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	fmt.Printf("deleted %s from the key\n", desc)

	store := NewStore(*data)
	if !*alsoServer {
		var owner string
		_ = store.View(func(d *storeData) error {
			if u, _ := d.credential(id); u != nil {
				owner = u.Name
			}
			return nil
		})
		if owner != "" {
			fmt.Printf("the server still lists it for %s; remove it with: passkeys-test delete-credential %s\n", owner, b64(id))
		}
		return nil
	}
	return store.Update(func(d *storeData) error {
		u, _ := d.credential(id)
		if u == nil {
			fmt.Printf("%s has no record of it\n", *data)
			return nil
		}
		u.deleteCredential(id)
		fmt.Printf("deleted it from user %q in %s\n", u.Name, *data)
		return nil
	})
}

func cmdKeyPIN(args []string) error {
	fs := flag.NewFlagSet("key pin", flag.ExitOnError)
	device := deviceFlag(fs)
	_ = fs.Parse(args)

	d, dev, err := openKey(*device)
	if err != nil {
		return err
	}
	defer d.Close()
	info, err := d.getInfo()
	if err != nil {
		return err
	}
	_, _ = loadAAGUIDs(defaultAAGUIDPath())
	label := keyLabel(dev, info)
	if _, ok := info.Options["clientPin"]; !ok {
		return fmt.Errorf("%s doesn't support a PIN", label)
	}

	var oldPIN string
	if info.Options["clientPin"] {
		if oldPIN, err = readPIN("current PIN for " + label); err != nil {
			return err
		}
	}
	newPIN, err := readPIN("new PIN")
	if err != nil {
		return err
	}
	if err := checkNewPIN(newPIN, info.MinPINLength); err != nil {
		return err
	}
	again, err := readPIN("new PIN again")
	if err != nil {
		return err
	}
	if again != newPIN {
		return errors.New("the PINs don't match")
	}
	if err := d.setPIN(info, oldPIN, newPIN); err != nil {
		return err
	}
	if oldPIN == "" {
		fmt.Printf("PIN set on %s\n", label)
	} else {
		fmt.Printf("PIN changed on %s\n", label)
	}
	return nil
}

func cmdKeyReset(args []string) error {
	fs := flag.NewFlagSet("key reset", flag.ExitOnError)
	device := deviceFlag(fs)
	yes := fs.Bool("y", false, "do not ask for confirmation")
	noReplug := fs.Bool("no-replug", false, "send the reset right away instead of waiting for the key to be replugged")
	_ = fs.Parse(args)

	d, dev, err := openKey(*device)
	if err != nil {
		return err
	}
	info, err := d.getInfo()
	d.Close()
	if err != nil {
		return err
	}
	_, _ = loadAAGUIDs(defaultAAGUIDPath())
	label := keyLabel(dev, info)

	fmt.Printf(`This erases every passkey on %s and clears its PIN.
Sites where you registered this key, including this server, won't accept it
anymore. Other functions of the key, such as PIV smart-card certificates,
aren't affected.
`, label)
	if !*yes {
		fmt.Print(`Type "reset" to continue: `)
		answer, _ := stdin.ReadString('\n')
		if strings.TrimSpace(answer) != "reset" {
			return errors.New("aborted")
		}
	}

	if !*noReplug {
		// Keys accept a reset only within a few seconds of power-up, so
		// send it as soon as the key comes back.
		if dev, err = waitForReplug(dev, time.Minute); err != nil {
			return err
		}
	}
	d, err = openReplugged(dev.Path)
	if err != nil {
		return err
	}
	defer d.Close()
	fmt.Println("Touch the key to confirm the reset.")
	if err := d.reset(); err != nil {
		if *noReplug {
			return fmt.Errorf("%w; run the command again without -no-replug", err)
		}
		return err
	}
	fmt.Println("Reset done. The key has no passkeys and no PIN. Set a PIN with: passkeys-test key pin")
	return nil
}

// waitForReplug waits for the key to disappear and come back, matching it
// by USB ID because its device path may change.
func waitForReplug(dev hidDeviceInfo, timeout time.Duration) (hidDeviceInfo, error) {
	deadline := time.Now().Add(timeout)
	fmt.Println("Unplug the key.")
	for {
		devs, err := findFIDODevices()
		if err != nil {
			return dev, err
		}
		if !slices.ContainsFunc(devs, func(d hidDeviceInfo) bool { return d.Path == dev.Path }) {
			break
		}
		if time.Now().After(deadline) {
			return dev, errors.New("the key wasn't unplugged in time")
		}
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Println("Plug it back in.")
	for {
		devs, err := findFIDODevices()
		if err != nil {
			return dev, err
		}
		for _, d := range devs {
			if dev.USBID == "" || d.USBID == dev.USBID {
				return d, nil
			}
		}
		if time.Now().After(deadline) {
			return dev, errors.New("the key wasn't plugged back in time")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// openReplugged opens a key that just appeared, retrying while udev is
// still setting the device's permissions.
func openReplugged(path string) (*ctapDevice, error) {
	deadline := time.Now().Add(3 * time.Second)
	for {
		t, err := openHID(path)
		if err == nil {
			d, err := newCTAPDevice(t)
			if err != nil {
				t.Close()
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			return d, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}
}
