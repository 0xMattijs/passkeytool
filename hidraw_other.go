//go:build !linux

package main

import "errors"

type hidDeviceInfo struct {
	Path  string
	Name  string
	USBID string
}

var errHIDUnsupported = errors.New("security key management is only supported on Linux")

func findFIDODevices() ([]hidDeviceInfo, error) { return nil, errHIDUnsupported }

func openHID(path string) (hidTransport, error) { return nil, errHIDUnsupported }
