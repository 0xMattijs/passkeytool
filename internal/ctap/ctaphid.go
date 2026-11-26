package ctap

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// CTAPHID framing (CTAP 2.1 §11.2): messages travel in 64-byte HID reports.
// The first report carries the channel ID, command, and total length; the
// rest carry the channel ID and a sequence number.

const (
	hidReportLen   = 64
	hidInitPayload = hidReportLen - 7
	hidContPayload = hidReportLen - 5

	ctapHIDInit      = 0x06
	ctapHIDCBOR      = 0x10
	ctapHIDKeepalive = 0x3b
	ctapHIDError     = 0x3f

	broadcastCID = 0xffffffff
)

// Transport sends and receives raw 64-byte HID reports.
type Transport interface {
	writeReport(report []byte) error
	readReport(timeout time.Duration) ([]byte, error)
	Close() error
}

// Device is an open CTAPHID channel to one authenticator.
type Device struct {
	t       Transport
	cid     uint32
	timeout time.Duration
}

func NewDevice(t Transport) (*Device, error) {
	d := &Device{t: t, cid: broadcastCID, timeout: 5 * time.Second}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if err := d.send(ctapHIDInit, nonce); err != nil {
		return nil, err
	}
	for {
		cmd, data, err := d.recv()
		if err != nil {
			return nil, fmt.Errorf("CTAPHID_INIT: %w", err)
		}
		// Other clients may be initializing on the broadcast channel too.
		if cmd != ctapHIDInit || len(data) < 17 || !bytes.Equal(data[:8], nonce) {
			continue
		}
		d.cid = binary.BigEndian.Uint32(data[8:12])
		return d, nil
	}
}

func (d *Device) Close() error { return d.t.Close() }

func (d *Device) send(cmd byte, data []byte) error {
	if len(data) > hidInitPayload+0x80*hidContPayload {
		return errors.New("CTAPHID message too long")
	}
	pkt := make([]byte, hidReportLen)
	binary.BigEndian.PutUint32(pkt, d.cid)
	pkt[4] = cmd | 0x80
	binary.BigEndian.PutUint16(pkt[5:], uint16(len(data)))
	n := copy(pkt[7:], data)
	if err := d.t.writeReport(pkt); err != nil {
		return err
	}
	for seq := byte(0); n < len(data); seq++ {
		pkt = make([]byte, hidReportLen)
		binary.BigEndian.PutUint32(pkt, d.cid)
		pkt[4] = seq
		n += copy(pkt[5:], data[n:])
		if err := d.t.writeReport(pkt); err != nil {
			return err
		}
	}
	return nil
}

// recv reads one complete message on this channel, skipping keepalives and
// reports for other channels.
func (d *Device) recv() (byte, []byte, error) {
	for {
		pkt, err := d.t.readReport(d.timeout)
		if err != nil {
			return 0, nil, err
		}
		if len(pkt) < 7 || binary.BigEndian.Uint32(pkt) != d.cid || pkt[4]&0x80 == 0 {
			continue
		}
		cmd := pkt[4] & 0x7f
		if cmd == ctapHIDKeepalive {
			continue
		}
		total := int(binary.BigEndian.Uint16(pkt[5:]))
		buf := make([]byte, 0, total)
		buf = append(buf, pkt[7:7+min(total, len(pkt)-7)]...)
		for seq := byte(0); len(buf) < total; {
			pkt, err := d.t.readReport(d.timeout)
			if err != nil {
				return 0, nil, err
			}
			if len(pkt) < 5 || binary.BigEndian.Uint32(pkt) != d.cid {
				continue
			}
			if pkt[4] != seq {
				return 0, nil, fmt.Errorf("CTAPHID: expected sequence %d, got %#x", seq, pkt[4])
			}
			seq++
			buf = append(buf, pkt[5:5+min(total-len(buf), len(pkt)-5)]...)
		}
		if cmd == ctapHIDError {
			code := byte(0)
			if len(buf) > 0 {
				code = buf[0]
			}
			return 0, nil, ctapError(code)
		}
		return cmd, buf, nil
	}
}

func (d *Device) transact(cmd byte, data []byte) ([]byte, error) {
	if err := d.send(cmd, data); err != nil {
		return nil, err
	}
	got, resp, err := d.recv()
	if err != nil {
		return nil, err
	}
	if got != cmd {
		return nil, fmt.Errorf("CTAPHID: sent command %#x, got response %#x", cmd, got)
	}
	return resp, nil
}

// hasFIDOUsagePage walks the short items of a HID report descriptor looking
// for a Usage Page item with the FIDO Alliance page.
func hasFIDOUsagePage(desc []byte) bool {
	for i := 0; i < len(desc); {
		prefix := desc[i]
		if prefix == 0xfe { // long item: 0xfe, size, tag, data
			if i+1 >= len(desc) {
				return false
			}
			i += 3 + int(desc[i+1])
			continue
		}
		size := int(prefix & 0x03)
		if size == 3 {
			size = 4
		}
		if i+1+size > len(desc) {
			return false
		}
		if prefix&0xfc == 0x04 { // global item, tag 0: Usage Page
			var v uint32
			for j := size - 1; j >= 0; j-- {
				v = v<<8 | uint32(desc[i+1+j])
			}
			if v == 0xf1d0 {
				return true
			}
		}
		i += 1 + size
	}
	return false
}
