package tci1_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tci1"
)

func testKey() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(0x11 + i)
	}
	return k
}

func testDeviceID() [32]byte {
	var id [32]byte
	for i := range id {
		id[i] = byte(0xA0 + i)
	}
	return id
}

func makeValidTCC1(lenBytes int) []byte {
	b := make([]byte, lenBytes)
	binary.LittleEndian.PutUint32(b[0:4], tci1.CloudCmdMagic)
	b[4] = 1
	binary.LittleEndian.PutUint32(b[20:24], uint32(lenBytes))
	return b
}

func TestValidateBlobPath_ClosedRFC3986DFA(t *testing.T) {
	valid := []string{
		"/a",
		"/v1/blobs/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"/v1/blobs/app_v2.tbm1",
		"/v1/blobs/zephyr~2.0.0-rc_1.tbm1?sig=abc123&exp=1700000000",
		"/v1/.well-known/blob_1",
	}
	for _, p := range valid {
		if err := tci1.ValidateBlobPath(p); err != nil {
			t.Fatalf("expected valid path %q, got err=%v", p, err)
		}
	}

	invalid := []string{
		"",
		"/",
		"v1/blobs/x",
		"//evil.com/x",
		"/v1//blobs/x",
		"/v1/blobs/",
		"/.",
		"/..",
		"/v1/./x",
		"/v1/../x",
		"/v1/blobs/..",
		"/v1/blobs/.",
		"/v1/%2e%2e/x",
		"/v1/blobs/x?foo=1#frag",
		"/v1/blobs/x?",
		"/v1/blobs/x?foo=1?bar=2",
		"/v1/blobs\\x",
		"/v1:80/blobs/x",
		"/v1/blobs/x\r\nX-Injected: 1",
		"/v1/blobs/x y",
		"/" + strings.Repeat("a", tci1.MaxBlobPathLen),
	}
	for _, p := range invalid {
		if err := tci1.ValidateBlobPath(p); !errors.Is(err, tci1.ErrInvalidBlobPath) {
			t.Fatalf("expected ErrInvalidBlobPath for %q, got %v", p, err)
		}
	}
}

func TestAuthAndStdlibHMACEquivalence(t *testing.T) {
	key := testKey()
	devID := testDeviceID()
	var sha [32]byte
	var asgn [16]byte
	var rot [32]byte
	for i := range sha {
		sha[i] = byte(0x30 + i)
		rot[i] = byte(0x70 + i)
	}
	asgn[0] = 0x42

	m := tci1.Manifest{
		TargetSlot:      tci1.SlotStage1,
		SVN:             5,
		RemoteBuild:     105,
		TotalSize:       4096,
		SHA256:          sha,
		AssignmentID:    asgn,
		SeqEcho:         9,
		RetryAfterSec:   3600,
		BlobPath:        "/v1/blobs/stage1_v5.tbm1",
		HasRotatedToken: true,
		RotatedToken:    rot,
	}

	wire, err := tci1.Encode(m, key, devID)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Cross-verify stack HMAC-SHA256 against Go stdlib crypto/hmac.
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(tci1.AuthDomain))
	mac.Write(devID[:])
	mac.Write(wire[:len(wire)-tci1.AuthTagLen])
	wantTag := mac.Sum(nil)[:tci1.AuthTagLen]
	if !bytes.Equal(wire[len(wire)-tci1.AuthTagLen:], wantTag) {
		t.Fatalf("auth tag mismatch vs stdlib hmac:\ngot:  %x\nwant: %x", wire[len(wire)-16:], wantTag)
	}

	// Verify rotated_token is NOT plaintext on the wire!
	if bytes.Contains(wire, rot[:]) {
		t.Fatal("SECURITY VIOLATION: rotated_token appeared unmasked on wire!")
	}

	// Wrong tokenKey, wrong deviceID, wrong expectedSeq, or flipped bit must fail authentication/seq!
	wrongKey := key
	wrongKey[0] ^= 0x01
	if _, err := tci1.Parse(wire, wrongKey, devID, 9); !errors.Is(err, tci1.ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed on wrong key, got %v", err)
	}

	wrongDev := devID
	wrongDev[31] ^= 0x01
	if _, err := tci1.Parse(wire, key, wrongDev, 9); !errors.Is(err, tci1.ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed on wrong device_id, got %v", err)
	}

	if _, err := tci1.Parse(wire, key, devID, 10); !errors.Is(err, tci1.ErrSeqEchoMismatch) {
		t.Fatalf("expected ErrSeqEchoMismatch on replay seq, got %v", err)
	}

	corrupt := append([]byte(nil), wire...)
	corrupt[20] ^= 0x01
	if _, err := tci1.Parse(corrupt, key, devID, 9); !errors.Is(err, tci1.ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed on bit flip, got %v", err)
	}
}
