package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// fakeKey is an in-memory CTAP 2.1 authenticator behind CTAPHID framing.
type fakeKey struct {
	t         *testing.T
	protocols []uint
	pin       string
	retries   uint
	rps       []*fakeRP

	priv  *ecdh.PrivateKey
	proto *pinProtocol
	token []byte

	// reassembly of the current request
	cmd  byte
	want int
	buf  []byte
	seq  byte

	out      [][]byte
	rpCursor int
	crCursor int
	crRP     *fakeRP
}

type fakeRP struct {
	id    string
	creds []keyCredential
}

const fakeCID = 0x01020304

func newFakeKey(t *testing.T, protocols ...uint) *fakeKey {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKey{
		t: t, protocols: protocols, pin: "1234", retries: 8, priv: priv,
		rps: []*fakeRP{
			{id: "localhost", creds: []keyCredential{
				{ID: []byte("cred-alice"), User: keyUser{ID: []byte("uid-alice"), Name: "alice", DisplayName: "Alice"}},
				{ID: []byte("cred-bob"), User: keyUser{ID: []byte("uid-bob"), Name: "bob"}},
			}},
			{id: "example.com", creds: []keyCredential{
				{ID: bytes.Repeat([]byte{0xab}, 64), User: keyUser{ID: []byte("u3"), Name: "a-rather-long-user-name@example.com"}},
			}},
		},
	}
}

func (k *fakeKey) Close() error { return nil }

func (k *fakeKey) readReport(time.Duration) ([]byte, error) {
	if len(k.out) == 0 {
		return nil, errors.New("fake: no response queued")
	}
	r := k.out[0]
	k.out = k.out[1:]
	return r, nil
}

func (k *fakeKey) writeReport(pkt []byte) error {
	if len(pkt) != hidReportLen {
		k.t.Fatalf("report length %d", len(pkt))
	}
	if pkt[4]&0x80 != 0 {
		k.cmd = pkt[4] & 0x7f
		k.want = int(binary.BigEndian.Uint16(pkt[5:]))
		k.buf = append([]byte(nil), pkt[7:7+min(k.want, hidInitPayload)]...)
		k.seq = 0
	} else {
		if pkt[4] != k.seq {
			k.t.Fatalf("continuation sequence %d, want %d", pkt[4], k.seq)
		}
		k.seq++
		k.buf = append(k.buf, pkt[5:5+min(k.want-len(k.buf), hidContPayload)]...)
	}
	if len(k.buf) < k.want {
		return nil
	}
	switch k.cmd {
	case ctapHIDInit:
		// Noise first: a report for another channel and a keepalive.
		k.queue(0x0badcafe, ctapHIDCBOR, []byte{0})
		k.queue(broadcastCID, ctapHIDInit, bytes.Join([][]byte{k.buf, {1, 2, 3, 4}, {2, 1, 0, 0, 0x0c}}, nil))
	case ctapHIDCBOR:
		k.queue(fakeCID, ctapHIDKeepalive, []byte{1})
		k.queue(fakeCID, ctapHIDCBOR, k.handle(k.buf[0], k.buf[1:]))
	default:
		k.queue(fakeCID, ctapHIDError, []byte{0x01})
	}
	return nil
}

func (k *fakeKey) queue(cid uint32, cmd byte, data []byte) {
	pkt := make([]byte, hidReportLen)
	binary.BigEndian.PutUint32(pkt, cid)
	pkt[4] = cmd | 0x80
	binary.BigEndian.PutUint16(pkt[5:], uint16(len(data)))
	n := copy(pkt[7:], data)
	k.out = append(k.out, pkt)
	for seq := byte(0); n < len(data); seq++ {
		pkt = make([]byte, hidReportLen)
		binary.BigEndian.PutUint32(pkt, cid)
		pkt[4] = seq
		n += copy(pkt[5:], data[n:])
		k.out = append(k.out, pkt)
	}
}

func (k *fakeKey) ok(v any) []byte {
	b, err := webauthncbor.Marshal(v)
	if err != nil {
		k.t.Fatal(err)
	}
	return append([]byte{0}, b...)
}

func (k *fakeKey) handle(cmd byte, body []byte) []byte {
	switch cmd {
	case ctapGetInfo:
		return k.ok(map[int]any{
			1: []string{"FIDO_2_0", "FIDO_2_1"},
			3: bytes.Repeat([]byte{0x11}, 16),
			4: map[string]bool{"clientPin": true, "credMgmt": true, "pinUvAuthToken": true, "rk": true},
			6: k.protocols,
		})
	case ctapClientPIN:
		var req clientPINReq
		if err := webauthncbor.Unmarshal(body, &req); err != nil {
			k.t.Fatalf("clientPIN request: %v", err)
		}
		return k.clientPIN(req)
	case ctapCredMgmt:
		var req credMgmtReq
		if err := webauthncbor.Unmarshal(body, &req); err != nil {
			k.t.Fatalf("credMgmt request: %v", err)
		}
		return k.credMgmt(req)
	}
	return []byte{0x01}
}

func (k *fakeKey) clientPIN(req clientPINReq) []byte {
	switch req.SubCommand {
	case pinGetRetries:
		return k.ok(map[int]any{3: k.retries})
	case pinGetKeyAgreement:
		return k.ok(map[int]any{1: coseFromECDH(k.priv.PublicKey())})
	case pinGetPinUvAuthTokenWithPerms:
		if req.Permissions&permCredentialManagement == 0 {
			k.t.Errorf("token requested without the cm permission")
		}
		peer, err := req.KeyAgreement.ecdh()
		if err != nil {
			k.t.Fatal(err)
		}
		z, err := k.priv.ECDH(peer)
		if err != nil {
			k.t.Fatal(err)
		}
		proto, err := newPinProtocol(req.Protocol, z)
		if err != nil {
			k.t.Fatal(err)
		}
		got, err := proto.decrypt(req.PinHashEnc)
		if err != nil {
			k.t.Fatal(err)
		}
		want := sha256.Sum256([]byte(k.pin))
		if !bytes.Equal(got, want[:16]) {
			k.retries--
			return []byte{0x31}
		}
		k.proto = proto
		k.token = make([]byte, 32)
		_, _ = rand.Read(k.token)
		enc, err := proto.encrypt(k.token)
		if err != nil {
			k.t.Fatal(err)
		}
		return k.ok(map[int]any{2: enc})
	}
	return []byte{0x02}
}

func (k *fakeKey) checkAuth(req credMgmtReq) bool {
	msg := []byte{byte(req.SubCommand)}
	if req.Params != nil {
		b, _ := webauthncbor.Marshal(req.Params)
		msg = append(msg, b...)
	}
	return k.token != nil && req.Protocol == k.proto.version &&
		hmac.Equal(req.PinUvAuthParam, k.proto.authenticate(k.token, msg))
}

func (k *fakeKey) credResp(total int) []byte {
	c := k.crRP.creds[k.crCursor]
	m := map[int]any{
		6: map[string]any{"id": c.User.ID, "name": c.User.Name, "displayName": c.User.DisplayName},
		7: map[string]any{"id": c.ID, "type": "public-key"},
	}
	if total > 0 {
		m[9] = total
	}
	return k.ok(m)
}

func (k *fakeKey) credMgmt(req credMgmtReq) []byte {
	switch req.SubCommand {
	case cmGetCredsMetadata, cmEnumerateRPsBegin, cmEnumerateCredsBegin, cmDeleteCredential:
		if !k.checkAuth(req) {
			return []byte{0x33}
		}
	}
	rpResp := func(withTotal bool) []byte {
		rp := k.rps[k.rpCursor]
		m := map[int]any{3: map[string]any{"id": rp.id}, 4: rpIDHash(rp.id)}
		if withTotal {
			m[5] = len(k.rps)
		}
		return k.ok(m)
	}
	switch req.SubCommand {
	case cmGetCredsMetadata:
		n := 0
		for _, rp := range k.rps {
			n += len(rp.creds)
		}
		return k.ok(map[int]any{1: n, 2: 50})
	case cmEnumerateRPsBegin:
		if len(k.rps) == 0 {
			return []byte{0x2e}
		}
		k.rpCursor = 0
		return rpResp(true)
	case cmEnumerateRPsGetNext:
		k.rpCursor++
		return rpResp(false)
	case cmEnumerateCredsBegin:
		k.crRP = nil
		for _, rp := range k.rps {
			if bytes.Equal(rpIDHash(rp.id), req.Params.RPIDHash) {
				k.crRP = rp
			}
		}
		if k.crRP == nil || len(k.crRP.creds) == 0 {
			return []byte{0x2e}
		}
		k.crCursor = 0
		return k.credResp(len(k.crRP.creds))
	case cmEnumerateCredsGetNext:
		k.crCursor++
		return k.credResp(0)
	case cmDeleteCredential:
		for _, rp := range k.rps {
			for i, c := range rp.creds {
				if bytes.Equal(c.ID, req.Params.CredentialID.ID) {
					rp.creds = append(rp.creds[:i], rp.creds[i+1:]...)
					return []byte{0}
				}
			}
		}
		return []byte{0x2e}
	}
	return []byte{0x02}
}

func TestKeyCredentialManagement(t *testing.T) {
	for _, protocols := range [][]uint{{2, 1}, {1}} {
		t.Run(fmt.Sprintf("protocols %v", protocols), func(t *testing.T) {
			k := newFakeKey(t, protocols...)
			d, err := newCTAPDevice(k)
			if err != nil {
				t.Fatal(err)
			}
			if d.cid != fakeCID {
				t.Fatalf("cid = %#x", d.cid)
			}
			info, err := d.getInfo()
			if err != nil {
				t.Fatal(err)
			}
			if info.credMgmtCommand() != ctapCredMgmt {
				t.Fatal("credMgmt not detected")
			}

			if _, err := d.getPinToken(info, "0000"); err == nil || !strings.Contains(err.Error(), "7 attempts left") {
				t.Fatalf("wrong PIN: err = %v", err)
			}
			token, err := d.getPinToken(info, "1234")
			if err != nil {
				t.Fatal(err)
			}
			if token.proto.version != protocols[0] {
				t.Errorf("protocol %d, want %d", token.proto.version, protocols[0])
			}
			m := &credManager{d: d, cmd: ctapCredMgmt, token: token}

			if n, _, err := m.metadata(); err != nil || n != 3 {
				t.Fatalf("metadata = %d, %v", n, err)
			}
			rps, err := m.relyingParties()
			if err != nil || len(rps) != 2 || rps[1].RP.ID != "example.com" {
				t.Fatalf("relyingParties = %+v, %v", rps, err)
			}
			creds, err := m.credentials(rpIDHash("localhost"))
			if err != nil || len(creds) != 2 || creds[0].User.Name != "alice" || creds[0].User.DisplayName != "Alice" {
				t.Fatalf("credentials = %+v, %v", creds, err)
			}
			long, err := m.credentials(rpIDHash("example.com"))
			if err != nil || len(long) != 1 || len(long[0].ID) != 64 {
				t.Fatalf("multi-report credential = %+v, %v", long, err)
			}
			if none, err := m.credentials(rpIDHash("nowhere.test")); err != nil || len(none) != 0 {
				t.Fatalf("unknown RP = %+v, %v", none, err)
			}

			rp, c, err := m.findCredential([]byte("cred-alice"))
			if err != nil || c == nil || rp.RP.ID != "localhost" {
				t.Fatalf("findCredential = %v, %v, %v", rp, c, err)
			}
			if err := m.deleteCredential([]byte("cred-alice")); err != nil {
				t.Fatal(err)
			}
			if _, c, _ := m.findCredential([]byte("cred-alice")); c != nil {
				t.Fatal("credential still present after delete")
			}
			if err := m.deleteCredential([]byte("cred-alice")); !errors.Is(err, ctapError(0x2e)) {
				t.Fatalf("second delete: %v", err)
			}
		})
	}
}

func TestPinProtocolRoundTrip(t *testing.T) {
	z := bytes.Repeat([]byte{7}, 32)
	for _, v := range []uint{1, 2} {
		p, err := newPinProtocol(v, z)
		if err != nil {
			t.Fatal(err)
		}
		plain := bytes.Repeat([]byte{0x42}, 32)
		ct, err := p.encrypt(plain)
		if err != nil {
			t.Fatal(err)
		}
		if want := 32 + 16*int(v-1); len(ct) != want {
			t.Errorf("v%d ciphertext length %d, want %d", v, len(ct), want)
		}
		got, err := p.decrypt(ct)
		if err != nil || !bytes.Equal(got, plain) {
			t.Errorf("v%d round trip: %x, %v", v, got, err)
		}
		if n := len(p.authenticate([]byte("key"), []byte("msg"))); n != 16*int(v) {
			t.Errorf("v%d auth param length %d", v, n)
		}
	}
}

func TestHasFIDOUsagePage(t *testing.T) {
	fido := []byte{0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0xc0}
	keyboard := []byte{0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0xc0}
	// 0xd0 0xf1 appearing as data of another item must not match.
	tricky := []byte{0x26, 0xd0, 0xf1, 0x05, 0x01}
	if !hasFIDOUsagePage(fido) {
		t.Error("FIDO descriptor not detected")
	}
	if hasFIDOUsagePage(keyboard) || hasFIDOUsagePage(tricky) {
		t.Error("non-FIDO descriptor detected as FIDO")
	}
}
