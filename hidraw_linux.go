package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// hidDeviceInfo describes a FIDO HID device found under /sys/class/hidraw.
type hidDeviceInfo struct {
	Path  string // /dev/hidrawN
	Name  string
	USBID string // vendor:product
}

// findFIDODevices lists hidraw devices whose report descriptor declares the
// FIDO usage page (0xF1D0).
func findFIDODevices() ([]hidDeviceInfo, error) {
	dirs, err := filepath.Glob("/sys/class/hidraw/hidraw*")
	if err != nil {
		return nil, err
	}
	var out []hidDeviceInfo
	for _, dir := range dirs {
		desc, err := os.ReadFile(filepath.Join(dir, "device", "report_descriptor"))
		if err != nil || !hasFIDOUsagePage(desc) {
			continue
		}
		info := hidDeviceInfo{Path: "/dev/" + filepath.Base(dir)}
		if f, err := os.Open(filepath.Join(dir, "device", "uevent")); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				k, v, _ := strings.Cut(sc.Text(), "=")
				switch k {
				case "HID_NAME":
					info.Name = v
				case "HID_ID": // bus:vendor:product, zero-padded to 8 digits
					if p := strings.Split(v, ":"); len(p) == 3 && len(p[1]) >= 4 && len(p[2]) >= 4 {
						info.USBID = strings.ToLower(p[1][len(p[1])-4:] + ":" + p[2][len(p[2])-4:])
					}
				}
			}
			f.Close()
		}
		out = append(out, info)
	}
	return out, nil
}

// hidrawTransport talks to a /dev/hidrawN device.
type hidrawTransport struct{ f *os.File }

func openHID(path string) (hidTransport, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if errors.Is(err, os.ErrPermission) {
		return nil, fmt.Errorf("%w (install your distribution's FIDO udev rules, for example from the libfido2 package)", err)
	}
	if err != nil {
		return nil, err
	}
	return &hidrawTransport{f: f}, nil
}

func (t *hidrawTransport) writeReport(report []byte) error {
	// hidraw expects the report ID first; FIDO devices use none (0).
	_, err := t.f.Write(append([]byte{0}, report...))
	return err
}

func (t *hidrawTransport) readReport(timeout time.Duration) ([]byte, error) {
	if err := t.f.SetReadDeadline(time.Now().Add(timeout)); err != nil && !errors.Is(err, os.ErrNoDeadline) {
		return nil, err
	}
	buf := make([]byte, hidReportLen)
	n, err := t.f.Read(buf)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, errors.New("timed out waiting for the security key")
	}
	if err != nil {
		return nil, err
	}
	return bytes.Clone(buf[:n]), nil
}

func (t *hidrawTransport) Close() error { return t.f.Close() }
