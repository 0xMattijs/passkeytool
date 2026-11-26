//go:build !linux

package ctap

import "errors"

type DeviceInfo struct {
	Path  string
	Name  string
	USBID string
}

var errHIDUnsupported = errors.New("security key management is only supported on Linux")

func FindDevices() ([]DeviceInfo, error) { return nil, errHIDUnsupported }

func OpenHID(path string) (Transport, error) { return nil, errHIDUnsupported }
