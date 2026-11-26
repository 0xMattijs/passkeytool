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
  rm CREDENTIAL_ID    Delete a passkey from the key (asks for the PIN)

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

func readPIN(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "PIN for %s: ", label)
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
		return nil, nil, "", fmt.Errorf("%s has no PIN set; set one first, for example in chrome://settings/securityKeys", label)
	}
	pin, err := readPIN(label)
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
	fmt.Fprintln(tw, "RP ID\tUSER\tCREDENTIAL ID\tON SERVER")
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
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", orDefault(rp.RP.ID, "sha256:"+b64(rp.IDHash)), user, b64(c.ID), serverStatus(server, c))
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
	fmt.Printf("\nON SERVER compares with %s. \"no\" means the server can't sign you in with that passkey.\n", *data)
	return nil
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
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: passkeys-test key rm [-device PATH] [-y] CREDENTIAL_ID")
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
	fmt.Printf("deleted %s\n", desc)
	return nil
}
