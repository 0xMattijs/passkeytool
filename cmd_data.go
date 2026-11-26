package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/0xMattijs/passkeytool/internal/aaguid"
	"github.com/0xMattijs/passkeytool/internal/attestation"
	"github.com/0xMattijs/passkeytool/internal/store"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

func cmdUsers(args []string) error {
	fs := flag.NewFlagSet("users", flag.ExitOnError)
	data := dataFlag(fs)
	verbose := fs.Bool("v", false, "show each passkey")
	_ = fs.Parse(args)

	_, _ = aaguid.Load(aaguid.DefaultPath())
	return store.New(*data).View(func(d *store.Data) error {
		if len(d.Users) == 0 {
			fmt.Println("no users")
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		if !*verbose {
			fmt.Fprintln(tw, "USER\tDISPLAY NAME\tPASSKEYS\tCREATED")
			for _, u := range d.Users {
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", u.Name, u.DisplayName, len(u.Credentials), u.CreatedAt.Local().Format(time.DateTime))
			}
			return tw.Flush()
		}
		for _, u := range d.Users {
			fmt.Fprintf(tw, "%s (%s)  id=%s  created %s\n", u.Name, u.DisplayName, store.EncodeID(u.ID), u.CreatedAt.Local().Format(time.DateTime))
			for _, c := range u.Credentials {
				name := c.Nickname
				if name == "" {
					name = "-"
				}
				fmt.Fprintf(tw, "  %s\n", store.EncodeID(c.ID))
				fmt.Fprintf(tw, "    name\t%s\n", name)
				fmt.Fprintf(tw, "    aaguid\t%s %s\n", aaguid.Format(c.Authenticator.AAGUID), aaguid.Name(c.Authenticator.AAGUID))
				fmt.Fprintf(tw, "    attachment\t%s\n", orDefault(string(c.Authenticator.Attachment), "-"))
				fmt.Fprintf(tw, "    transports\t%v\n", c.Transport)
				fmt.Fprintf(tw, "    attestation\t%s / %s\n", orDefault(c.AttestationFormat, "-"), orDefault(c.AttestationType, "-"))
				if a := attestation.Summarize(c.Attestation.Object); a != nil {
					for i, cert := range a.Certificates {
						fmt.Fprintf(tw, "    cert[%d]\t%s (issuer: %s)\n", i, cert.Subject, cert.Issuer)
					}
				}
				fmt.Fprintf(tw, "    flags\tUV=%t BE=%t BS=%t\n", c.Flags.UserVerified, c.Flags.BackupEligible, c.Flags.BackupState)
				fmt.Fprintf(tw, "    signCount\t%d\n", c.Authenticator.SignCount)
				last := "never"
				if !c.LastUsedAt.IsZero() {
					last = c.LastUsedAt.Local().Format(time.DateTime)
				}
				fmt.Fprintf(tw, "    used\t%d times, last %s\n", c.UseCount, last)
			}
			fmt.Fprintln(tw)
		}
		return tw.Flush()
	})
}

func cmdDeleteUser(args []string) error {
	fs := flag.NewFlagSet("delete-user", flag.ExitOnError)
	data := dataFlag(fs)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: passkeytool delete-user [-data FILE] NAME")
	}
	name := fs.Arg(0)
	return store.New(*data).Update(func(d *store.Data) error {
		if !d.DeleteUser(name) {
			return fmt.Errorf("user %q not found", name)
		}
		fmt.Printf("deleted user %q\n", name)
		return nil
	})
}

func cmdDeleteCredential(args []string) error {
	fs := flag.NewFlagSet("delete-credential", flag.ExitOnError)
	data := dataFlag(fs)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: passkeytool delete-credential [-data FILE] CREDENTIAL_ID")
	}
	id, err := store.DecodeID(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("bad credential id: %w", err)
	}
	return store.New(*data).Update(func(d *store.Data) error {
		u, _ := d.FindCredential(id)
		if u == nil {
			return errors.New("credential not found")
		}
		u.DeleteCredential(id)
		fmt.Printf("deleted credential from user %q\n", u.Name)
		return nil
	})
}

func cmdReset(args []string) error {
	fs := flag.NewFlagSet("reset", flag.ExitOnError)
	data := dataFlag(fs)
	yes := fs.Bool("y", false, "do not ask for confirmation")
	_ = fs.Parse(args)
	if !*yes {
		fmt.Printf("Delete all users and passkeys in %s? [y/N] ", *data)
		var answer string
		_, _ = fmt.Scanln(&answer)
		if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
			return errors.New("aborted")
		}
	}
	if err := os.Remove(*data); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Println("all data deleted")
	return nil
}
