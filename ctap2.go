package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// CTAP2 commands used here (CTAP 2.1 §6).
const (
	ctapGetInfo         = 0x04
	ctapClientPIN       = 0x06
	ctapReset           = 0x07
	ctapCredMgmt        = 0x0a
	ctapCredMgmtPreview = 0x41 // CTAP 2.1 prototype, still used by some keys
)

// ctapError is a CTAP status code (CTAP 2.1 §8.2), also used for CTAPHID errors.
type ctapError byte

var ctapErrorNames = map[ctapError]string{
	0x01: "invalid command",
	0x02: "invalid parameter",
	0x03: "invalid length",
	0x05: "timeout",
	0x06: "channel busy: another program is using the key",
	0x11: "CBOR unexpected type",
	0x12: "invalid CBOR",
	0x14: "missing parameter",
	0x27: "operation denied",
	0x2e: "no credentials",
	0x2f: "user action timeout",
	0x30: "not allowed",
	0x31: "PIN invalid",
	0x32: "PIN blocked: reset the key to use it again",
	0x33: "PIN auth invalid",
	0x34: "PIN auth blocked: unplug and replug the key, then retry",
	0x35: "PIN not set",
	0x36: "PIN required",
	0x37: "PIN policy violation",
	0x39: "request too large",
	0x3c: "unsupported option",
	0x40: "unauthorized permission",
}

func (e ctapError) Error() string {
	if name, ok := ctapErrorNames[e]; ok {
		return fmt.Sprintf("CTAP error %#02x: %s", byte(e), name)
	}
	return fmt.Sprintf("CTAP error %#02x", byte(e))
}

// cbor sends a CTAP2 command with an optional CBOR request and decodes the
// response into resp, if given.
func (d *ctapDevice) cbor(cmd byte, req, resp any) error {
	msg := []byte{cmd}
	if req != nil {
		b, err := webauthncbor.Marshal(req)
		if err != nil {
			return err
		}
		msg = append(msg, b...)
	}
	out, err := d.transact(ctapHIDCBOR, msg)
	if err != nil {
		return err
	}
	if len(out) == 0 {
		return errors.New("empty CTAP2 response")
	}
	if out[0] != 0 {
		return ctapError(out[0])
	}
	if resp == nil || len(out) == 1 {
		return nil
	}
	return webauthncbor.Unmarshal(out[1:], resp)
}

// ---------- authenticatorGetInfo ----------

type authenticatorInfo struct {
	Versions           []string        `cbor:"1,keyasint"`
	Extensions         []string        `cbor:"2,keyasint"`
	AAGUID             []byte          `cbor:"3,keyasint"`
	Options            map[string]bool `cbor:"4,keyasint"`
	MaxMsgSize         uint            `cbor:"5,keyasint"`
	PinUvAuthProtocols []uint          `cbor:"6,keyasint"`
	Transports         []string        `cbor:"9,keyasint"`
	Algorithms         []struct {
		Alg  int64  `cbor:"alg"`
		Type string `cbor:"type"`
	} `cbor:"10,keyasint"`
	ForcePINChange        bool   `cbor:"12,keyasint"`
	MinPINLength          uint   `cbor:"13,keyasint"`
	FirmwareVersion       uint64 `cbor:"14,keyasint"`
	RemainingDiscoverable *uint  `cbor:"20,keyasint"`
}

func (d *ctapDevice) getInfo() (*authenticatorInfo, error) {
	var info authenticatorInfo
	if err := d.cbor(ctapGetInfo, nil, &info); err != nil {
		return nil, fmt.Errorf("getInfo: %w", err)
	}
	return &info, nil
}

// credMgmtCommand returns the credential management command the key
// supports, or 0.
func (info *authenticatorInfo) credMgmtCommand() byte {
	switch {
	case info.Options["credMgmt"]:
		return ctapCredMgmt
	case info.Options["credentialMgmtPreview"]:
		return ctapCredMgmtPreview
	}
	return 0
}

// reset wipes the key's FIDO credentials and PIN (CTAP 2.1 §6.6). Keys
// accept it only shortly after power-up, and wait for a touch.
func (d *ctapDevice) reset() error {
	defer func(t time.Duration) { d.timeout = t }(d.timeout)
	d.timeout = 30 * time.Second
	err := d.cbor(ctapReset, nil, nil)
	switch {
	case errors.Is(err, ctapError(0x30)):
		return errors.New("the key refused: it only accepts a reset within a few seconds of being plugged in")
	case errors.Is(err, ctapError(0x27)):
		return errors.New("the reset was declined on the key")
	case errors.Is(err, ctapError(0x2f)):
		return errors.New("the key wasn't touched in time")
	}
	return err
}

// ---------- PIN/UV auth protocols (CTAP 2.1 §6.5.6, §6.5.7) ----------

type coseEC2Key struct {
	Kty int64  `cbor:"1,keyasint"`
	Alg int64  `cbor:"3,keyasint"`
	Crv int64  `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

func coseFromECDH(pub *ecdh.PublicKey) *coseEC2Key {
	b := pub.Bytes() // 0x04 || X || Y
	// The spec fixes alg to -25 (ECDH-ES+HKDF-256) for both protocols.
	return &coseEC2Key{Kty: 2, Alg: -25, Crv: 1, X: b[1:33], Y: b[33:65]}
}

func (k *coseEC2Key) ecdh() (*ecdh.PublicKey, error) {
	if k == nil || k.Kty != 2 || k.Crv != 1 || len(k.X) != 32 || len(k.Y) != 32 {
		return nil, errors.New("authenticator key agreement key is not a P-256 key")
	}
	return ecdh.P256().NewPublicKey(slices.Concat([]byte{4}, k.X, k.Y))
}

// pinProtocol holds the keys of one PIN/UV auth protocol session.
type pinProtocol struct {
	version uint
	hmacKey []byte
	aesKey  []byte
}

// newPinProtocol derives the shared secret from an ECDH result (the X
// coordinate of the shared point).
func newPinProtocol(version uint, z []byte) (*pinProtocol, error) {
	switch version {
	case 1:
		k := sha256.Sum256(z)
		return &pinProtocol{version: 1, hmacKey: k[:], aesKey: k[:]}, nil
	case 2:
		salt := make([]byte, 32)
		hk, err := hkdf.Key(sha256.New, z, salt, "CTAP2 HMAC key", 32)
		if err != nil {
			return nil, err
		}
		ak, err := hkdf.Key(sha256.New, z, salt, "CTAP2 AES key", 32)
		if err != nil {
			return nil, err
		}
		return &pinProtocol{version: 2, hmacKey: hk, aesKey: ak}, nil
	}
	return nil, fmt.Errorf("unsupported PIN/UV auth protocol %d", version)
}

func (p *pinProtocol) encrypt(plain []byte) ([]byte, error) {
	if len(plain)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext is not a multiple of the AES block size")
	}
	block, err := aes.NewCipher(p.aesKey)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if p.version == 2 {
		if _, err := rand.Read(iv); err != nil {
			return nil, err
		}
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	if p.version == 2 {
		out = append(iv, out...)
	}
	return out, nil
}

func (p *pinProtocol) decrypt(ct []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if p.version == 2 {
		if len(ct) < aes.BlockSize {
			return nil, errors.New("ciphertext too short")
		}
		iv, ct = ct[:aes.BlockSize], ct[aes.BlockSize:]
	}
	if len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the AES block size")
	}
	block, err := aes.NewCipher(p.aesKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	return out, nil
}

// authenticate computes a pinUvAuthParam over msg with key, which is the
// shared HMAC key or a pinUvAuthToken.
func (p *pinProtocol) authenticate(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	sum := m.Sum(nil)
	if p.version == 1 {
		return sum[:16]
	}
	return sum
}

// ---------- authenticatorClientPIN ----------

const (
	pinGetRetries                      = 0x01
	pinSetPIN                          = 0x03
	pinChangePIN                       = 0x04
	pinGetKeyAgreement                 = 0x02
	pinGetPinToken                     = 0x05
	pinGetPinUvAuthTokenWithPerms      = 0x09
	permCredentialManagement      uint = 0x04
)

type clientPINReq struct {
	Protocol       uint        `cbor:"1,keyasint,omitempty"`
	SubCommand     uint        `cbor:"2,keyasint"`
	KeyAgreement   *coseEC2Key `cbor:"3,keyasint,omitempty"`
	PinUvAuthParam []byte      `cbor:"4,keyasint,omitempty"`
	NewPinEnc      []byte      `cbor:"5,keyasint,omitempty"`
	PinHashEnc     []byte      `cbor:"6,keyasint,omitempty"`
	Permissions    uint        `cbor:"9,keyasint,omitempty"`
}

type clientPINResp struct {
	KeyAgreement   *coseEC2Key `cbor:"1,keyasint"`
	PinUvAuthToken []byte      `cbor:"2,keyasint"`
	PinRetries     *uint       `cbor:"3,keyasint"`
}

// pinRetries returns how many PIN attempts are left before the key locks.
func (d *ctapDevice) pinRetries() (uint, error) {
	var resp clientPINResp
	if err := d.cbor(ctapClientPIN, clientPINReq{SubCommand: pinGetRetries}, &resp); err != nil {
		return 0, err
	}
	if resp.PinRetries == nil {
		return 0, errors.New("authenticator did not report PIN retries")
	}
	return *resp.PinRetries, nil
}

// pinToken is a pinUvAuthToken and the protocol it was issued under.
type pinToken struct {
	proto *pinProtocol
	token []byte
}

func (t *pinToken) authenticate(msg []byte) []byte { return t.proto.authenticate(t.token, msg) }

// getPinToken exchanges the PIN for a pinUvAuthToken with the credential
// management permission.
func (d *ctapDevice) getPinToken(info *authenticatorInfo, pin string) (*pinToken, error) {
	proto, platformKey, err := d.keyAgreement(info)
	if err != nil {
		return nil, err
	}
	pinHashEnc, err := proto.pinHashEnc(pin)
	if err != nil {
		return nil, err
	}
	req := clientPINReq{
		Protocol:     proto.version,
		SubCommand:   pinGetPinToken,
		KeyAgreement: platformKey,
		PinHashEnc:   pinHashEnc,
	}
	// CTAP 2.1 keys scope tokens with permissions; older ones issue
	// all-powerful tokens through getPinToken.
	if info.Options["pinUvAuthToken"] {
		req.SubCommand = pinGetPinUvAuthTokenWithPerms
		req.Permissions = permCredentialManagement
	}
	var resp clientPINResp
	if err := d.cbor(ctapClientPIN, req, &resp); err != nil {
		return nil, d.explainPINError(err)
	}
	token, err := proto.decrypt(resp.PinUvAuthToken)
	if err != nil {
		return nil, fmt.Errorf("decrypt PIN token: %w", err)
	}
	return &pinToken{proto: proto, token: token}, nil
}

// keyAgreement runs the ECDH exchange that every clientPIN operation
// starts with, returning the shared protocol keys and the platform's public
// key to send along.
func (d *ctapDevice) keyAgreement(info *authenticatorInfo) (*pinProtocol, *coseEC2Key, error) {
	version := uint(1)
	if slices.Contains(info.PinUvAuthProtocols, 2) {
		version = 2
	} else if len(info.PinUvAuthProtocols) > 0 && !slices.Contains(info.PinUvAuthProtocols, 1) {
		return nil, nil, fmt.Errorf("no supported PIN/UV auth protocol in %v", info.PinUvAuthProtocols)
	}
	var ka clientPINResp
	if err := d.cbor(ctapClientPIN, clientPINReq{Protocol: version, SubCommand: pinGetKeyAgreement}, &ka); err != nil {
		return nil, nil, fmt.Errorf("getKeyAgreement: %w", err)
	}
	peer, err := ka.KeyAgreement.ecdh()
	if err != nil {
		return nil, nil, err
	}
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	z, err := priv.ECDH(peer)
	if err != nil {
		return nil, nil, err
	}
	proto, err := newPinProtocol(version, z)
	if err != nil {
		return nil, nil, err
	}
	return proto, coseFromECDH(priv.PublicKey()), nil
}

func (p *pinProtocol) pinHashEnc(pin string) ([]byte, error) {
	h := sha256.Sum256([]byte(pin))
	return p.encrypt(h[:16])
}

// explainPINError adds the remaining attempts to a wrong-PIN error.
func (d *ctapDevice) explainPINError(err error) error {
	if errors.Is(err, ctapError(0x31)) {
		if n, rerr := d.pinRetries(); rerr == nil {
			return fmt.Errorf("wrong PIN, %d attempts left before the key locks", n)
		}
	}
	return err
}

// checkNewPIN applies the CTAP rules for a new PIN: at least minLen Unicode
// code points (4 if the key doesn't say) and at most 63 bytes.
func checkNewPIN(pin string, minLen uint) error {
	if minLen == 0 {
		minLen = 4
	}
	if n := utf8.RuneCountInString(pin); uint(n) < minLen {
		return fmt.Errorf("the PIN must be at least %d characters", minLen)
	}
	if len(pin) > 63 {
		return errors.New("the PIN must be at most 63 bytes")
	}
	return nil
}

// setPIN sets the first PIN on a key, or changes it when oldPIN isn't empty
// (CTAP 2.1 §6.5.5.5, §6.5.5.6).
func (d *ctapDevice) setPIN(info *authenticatorInfo, oldPIN, newPIN string) error {
	if err := checkNewPIN(newPIN, info.MinPINLength); err != nil {
		return err
	}
	proto, platformKey, err := d.keyAgreement(info)
	if err != nil {
		return err
	}
	padded := make([]byte, 64)
	copy(padded, newPIN)
	newPinEnc, err := proto.encrypt(padded)
	if err != nil {
		return err
	}
	req := clientPINReq{
		Protocol:     proto.version,
		SubCommand:   pinSetPIN,
		KeyAgreement: platformKey,
		NewPinEnc:    newPinEnc,
	}
	msg := newPinEnc
	if oldPIN != "" {
		if req.PinHashEnc, err = proto.pinHashEnc(oldPIN); err != nil {
			return err
		}
		req.SubCommand = pinChangePIN
		msg = slices.Concat(newPinEnc, req.PinHashEnc)
	}
	req.PinUvAuthParam = proto.authenticate(proto.hmacKey, msg)
	if err := d.cbor(ctapClientPIN, req, nil); err != nil {
		return d.explainPINError(err)
	}
	return nil
}

// ---------- authenticatorCredentialManagement (CTAP 2.1 §6.8) ----------

const (
	cmGetCredsMetadata      = 0x01
	cmEnumerateRPsBegin     = 0x02
	cmEnumerateRPsGetNext   = 0x03
	cmEnumerateCredsBegin   = 0x04
	cmEnumerateCredsGetNext = 0x05
	cmDeleteCredential      = 0x06
)

type credDescriptor struct {
	ID   []byte `cbor:"id"`
	Type string `cbor:"type"`
}

type credMgmtParams struct {
	RPIDHash     []byte          `cbor:"1,keyasint,omitempty"`
	CredentialID *credDescriptor `cbor:"2,keyasint,omitempty"`
}

type credMgmtReq struct {
	SubCommand     uint            `cbor:"1,keyasint"`
	Params         *credMgmtParams `cbor:"2,keyasint,omitempty"`
	Protocol       uint            `cbor:"3,keyasint,omitempty"`
	PinUvAuthParam []byte          `cbor:"4,keyasint,omitempty"`
}

type keyRP struct {
	ID   string `cbor:"id"`
	Name string `cbor:"name"`
}

type keyUser struct {
	ID          []byte `cbor:"id"`
	Name        string `cbor:"name"`
	DisplayName string `cbor:"displayName"`
}

type credMgmtResp struct {
	ExistingCount    *uint                   `cbor:"1,keyasint"`
	MaxRemaining     *uint                   `cbor:"2,keyasint"`
	RP               *keyRP                  `cbor:"3,keyasint"`
	RPIDHash         []byte                  `cbor:"4,keyasint"`
	TotalRPs         uint                    `cbor:"5,keyasint"`
	User             *keyUser                `cbor:"6,keyasint"`
	CredentialID     *credDescriptor         `cbor:"7,keyasint"`
	PublicKey        webauthncbor.RawMessage `cbor:"8,keyasint"`
	TotalCredentials uint                    `cbor:"9,keyasint"`
	CredProtect      uint                    `cbor:"10,keyasint"`
}

// credManager runs credential management subcommands with one PIN token.
type credManager struct {
	d     *ctapDevice
	cmd   byte
	token *pinToken
}

func (m *credManager) call(sub uint, params *credMgmtParams, auth bool) (*credMgmtResp, error) {
	req := credMgmtReq{SubCommand: sub, Params: params}
	if auth {
		msg := []byte{byte(sub)}
		if params != nil {
			b, err := webauthncbor.Marshal(params)
			if err != nil {
				return nil, err
			}
			msg = append(msg, b...)
		}
		req.Protocol = m.token.proto.version
		req.PinUvAuthParam = m.token.authenticate(msg)
	}
	var resp credMgmtResp
	if err := m.d.cbor(m.cmd, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// metadata returns the number of stored discoverable credentials and how
// many more fit.
func (m *credManager) metadata() (existing, remaining uint, err error) {
	resp, err := m.call(cmGetCredsMetadata, nil, true)
	if err != nil {
		return 0, 0, err
	}
	if resp.ExistingCount != nil {
		existing = *resp.ExistingCount
	}
	if resp.MaxRemaining != nil {
		remaining = *resp.MaxRemaining
	}
	return existing, remaining, nil
}

type keyRPEntry struct {
	RP     keyRP
	IDHash []byte
}

func (m *credManager) relyingParties() ([]keyRPEntry, error) {
	resp, err := m.call(cmEnumerateRPsBegin, nil, true)
	if errors.Is(err, ctapError(0x2e)) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Only the first response carries the total.
	total := resp.TotalRPs
	var out []keyRPEntry
	for {
		e := keyRPEntry{IDHash: resp.RPIDHash}
		if resp.RP != nil {
			e.RP = *resp.RP
		}
		out = append(out, e)
		if uint(len(out)) >= total {
			return out, nil
		}
		if resp, err = m.call(cmEnumerateRPsGetNext, nil, false); err != nil {
			return nil, err
		}
	}
}

type keyCredential struct {
	ID          []byte
	User        keyUser
	CredProtect uint
}

func (m *credManager) credentials(rpIDHash []byte) ([]keyCredential, error) {
	resp, err := m.call(cmEnumerateCredsBegin, &credMgmtParams{RPIDHash: rpIDHash}, true)
	if errors.Is(err, ctapError(0x2e)) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	total := resp.TotalCredentials
	var out []keyCredential
	for {
		c := keyCredential{CredProtect: resp.CredProtect}
		if resp.CredentialID != nil {
			c.ID = resp.CredentialID.ID
		}
		if resp.User != nil {
			c.User = *resp.User
		}
		out = append(out, c)
		if uint(len(out)) >= total {
			return out, nil
		}
		if resp, err = m.call(cmEnumerateCredsGetNext, nil, false); err != nil {
			return nil, err
		}
	}
}

func (m *credManager) deleteCredential(id []byte) error {
	_, err := m.call(cmDeleteCredential, &credMgmtParams{CredentialID: &credDescriptor{ID: id, Type: "public-key"}}, true)
	return err
}

// rpIDHash is the SHA-256 of an RP ID, which keys index credentials by.
func rpIDHash(rpID string) []byte {
	h := sha256.Sum256([]byte(rpID))
	return h[:]
}

// findCredential locates a credential on the key by ID.
func (m *credManager) findCredential(id []byte) (*keyRPEntry, *keyCredential, error) {
	rps, err := m.relyingParties()
	if err != nil {
		return nil, nil, err
	}
	for _, rp := range rps {
		creds, err := m.credentials(rp.IDHash)
		if err != nil {
			return nil, nil, err
		}
		for _, c := range creds {
			if bytes.Equal(c.ID, id) {
				return &rp, &c, nil
			}
		}
	}
	return nil, nil, nil
}
