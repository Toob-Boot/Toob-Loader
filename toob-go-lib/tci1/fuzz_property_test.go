package tci1_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tci1"
)

func stdlibAuthTag(tokenKey, deviceID [32]byte, body []byte) [tci1.AuthTagLen]byte {
	mac := hmac.New(sha256.New, tokenKey[:])
	mac.Write([]byte(tci1.AuthDomain))
	mac.Write(deviceID[:])
	mac.Write(body)
	var out [tci1.AuthTagLen]byte
	copy(out[:], mac.Sum(nil)[:tci1.AuthTagLen])
	return out
}

func sealTCI1Auth(frame []byte, tokenKey, deviceID [32]byte) {
	if len(frame) < tci1.AuthTagLen {
		return
	}
	bodyLen := len(frame) - tci1.AuthTagLen
	tag := stdlibAuthTag(tokenKey, deviceID, frame[:bodyLen])
	copy(frame[bodyLen:], tag[:])
}

func isUnreservedByteRef(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// referenceRFC3986BlobPathOracle is an independent structural specification of ValidateBlobPath.
func referenceRFC3986BlobPathOracle(p string) bool {
	if len(p) < 2 || len(p) > tci1.MaxBlobPathLen || p[0] != '/' {
		return false
	}
	pathPart := p[1:]
	if qIdx := strings.IndexByte(pathPart, '?'); qIdx >= 0 {
		query := pathPart[qIdx+1:]
		pathPart = pathPart[:qIdx]
		if len(query) == 0 {
			return false
		}
		for i := range len(query) {
			c := query[i]
			if !isUnreservedByteRef(c) && c != '&' && c != '=' {
				return false
			}
		}
	}
	if len(pathPart) == 0 {
		return false
	}
	segments := strings.Split(pathPart, "/")
	for _, seg := range segments {
		if len(seg) == 0 || seg == "." || seg == ".." {
			return false
		}
		for i := range len(seg) {
			if !isUnreservedByteRef(seg[i]) {
				return false
			}
		}
	}
	return true
}

func isDegenerateKeyRef(b [32]byte) bool {
	allZero := true
	allFF := true
	for _, v := range b {
		if v != 0x00 {
			allZero = false
		}
		if v != 0xFF {
			allFF = false
		}
	}
	return allZero || allFF
}

func verifyTCI1TupleOracle(
	t *testing.T,
	frame []byte,
	tokenKey [32]byte,
	deviceID [32]byte,
	expectedSeq uint64,
) {
	t.Helper()

	origFrame := bytes.Clone(frame)
	parsedOwn, errOwn := tci1.Parse(frame, tokenKey, deviceID, expectedSeq)

	var parsedView tci1.Manifest
	errView := tci1.ParseView(frame, tokenKey, deviceID, expectedSeq, &parsedView)

	if !bytes.Equal(frame, origFrame) {
		t.Fatalf("Parse/ParseView mutated caller frame slice")
	}
	if (errOwn == nil) != (errView == nil) {
		t.Fatalf("Parse vs ParseView error mismatch: Parse=%v ParseView=%v", errOwn, errView)
	}

	// Pre-authentication & HMAC-SHA256-128 enforcement oracle.
	if isDegenerateKeyRef(tokenKey) {
		if !errors.Is(errView, tci1.ErrInvalidTokenKey) {
			t.Fatalf("expected ErrInvalidTokenKey on degenerate tokenKey, got %v", errView)
		}
		return
	}
	if expectedSeq == 0 {
		if !errors.Is(errView, tci1.ErrInvalidSeqEcho) {
			t.Fatalf("expected ErrInvalidSeqEcho for expectedSeq=0, got %v", errView)
		}
		return
	}
	if len(frame) < tci1.MinFrameSize {
		if !errors.Is(errView, tci1.ErrTruncated) {
			t.Fatalf("expected ErrTruncated, got %v", errView)
		}
		return
	}
	if len(frame) > tci1.MaxFrameSize {
		if !errors.Is(errView, tci1.ErrFrameTooLarge) {
			t.Fatalf("expected ErrFrameTooLarge, got %v", errView)
		}
		return
	}

	bodyLen := len(frame) - tci1.AuthTagLen
	wantTag := stdlibAuthTag(tokenKey, deviceID, frame[:bodyLen])
	if !bytes.Equal(wantTag[:], frame[bodyLen:]) {
		if !errors.Is(errView, tci1.ErrAuthFailed) {
			t.Fatalf("expected ErrAuthFailed on bad HMAC tag, got %v", errView)
		}
		return
	}

	if errView != nil {
		return
	}

	if !reflect.DeepEqual(parsedOwn, parsedView) {
		t.Fatalf("Parse vs ParseView Manifest mismatch:\nown:  %+v\nview: %+v", parsedOwn, parsedView)
	}

	// Control-Only vs Update-Frame bijection & closed RFC-3986 BlobPath oracle.
	if parsedOwn.TotalSize == 0 {
		if !parsedOwn.HasRotatedToken && len(parsedOwn.CloudCommand) == 0 {
			t.Fatalf("accepted empty control-only manifest")
		}
		if parsedOwn.TargetSlot != 0 || parsedOwn.SVN != 0 || parsedOwn.RemoteBuild != 0 ||
			parsedOwn.BlobPath != "" || parsedOwn.SHA256 != ([32]byte{}) || parsedOwn.AssignmentID != ([16]byte{}) {
			t.Fatalf("accepted control-only manifest with non-zero update fields: %+v", parsedOwn)
		}
	} else {
		if parsedOwn.TotalSize < tci1.MinTBM1TotalSize {
			t.Fatalf("accepted TotalSize < 576: %d", parsedOwn.TotalSize)
		}
		if !referenceRFC3986BlobPathOracle(parsedOwn.BlobPath) {
			t.Fatalf("accepted invalid BlobPath %q", parsedOwn.BlobPath)
		}
	}

	// Canonical wire re-encoding bijection.
	reencodedNil, err := tci1.AppendEncode(nil, parsedOwn, tokenKey, deviceID)
	if err != nil {
		t.Fatalf("AppendEncode(nil) failed on accepted Manifest: %v", err)
	}
	var scratch [tci1.MaxFrameSize]byte
	reencodedBuf, err := tci1.AppendEncode(scratch[:0], parsedView, tokenKey, deviceID)
	if err != nil {
		t.Fatalf("AppendEncode(scratch) failed on accepted Manifest: %v", err)
	}
	encodedHeap, err := tci1.Encode(parsedOwn, tokenKey, deviceID)
	if err != nil {
		t.Fatalf("Encode failed on accepted Manifest: %v", err)
	}
	if !bytes.Equal(reencodedNil, reencodedBuf) || !bytes.Equal(reencodedNil, encodedHeap) {
		t.Fatalf("AppendEncode/Encode outputs disagreed")
	}

	if allocs := testing.AllocsPerRun(1, func() {
		_, _ = tci1.AppendEncode(scratch[:0], parsedView, tokenKey, deviceID)
		_ = tci1.ParseView(frame, tokenKey, deviceID, expectedSeq, &parsedView)
	}); allocs != 0 {
		t.Fatalf("expected 0 allocs/op on AppendEncode+ParseView, got %v", allocs)
	}

	hdrSize := int(binary.LittleEndian.Uint16(frame[8:10]))
	if hdrSize == tci1.HeaderSize {
		if !bytes.Equal(reencodedNil, frame) {
			t.Fatalf("canonical TCI1 bijection violated:\ngot:  %x\nwant: %x", reencodedNil, frame)
		}
	} else {
		if (hdrSize%8) != 0 || hdrSize < tci1.HeaderSize {
			t.Fatalf("invalid accepted hdrSize %d", hdrSize)
		}
		if !bytes.Equal(reencodedNil[0:8], frame[0:8]) ||
			!bytes.Equal(reencodedNil[10:tci1.HeaderSize], frame[10:tci1.HeaderSize]) ||
			!bytes.Equal(reencodedNil[tci1.HeaderSize:len(reencodedNil)-tci1.AuthTagLen], frame[hdrSize:bodyLen]) {
			t.Fatalf("extended-header projection altered canonical fields or sections")
		}
		reparsed, err := tci1.Parse(reencodedNil, tokenKey, deviceID, expectedSeq)
		if err != nil || !reflect.DeepEqual(reparsed, parsedOwn) {
			t.Fatalf("canonical projection re-parse mismatch: err=%v", err)
		}
	}

	// Deterministic 1-bit flip rejection in frame, deviceID, and tokenKey.
	fBit := (len(frame)*11 + int(frame[0])) % (len(frame) * 8)
	corruptFrame := bytes.Clone(frame)
	corruptFrame[fBit/8] ^= 1 << (fBit % 8)
	if _, err := tci1.Parse(corruptFrame, tokenKey, deviceID, expectedSeq); !errors.Is(err, tci1.ErrAuthFailed) {
		t.Fatalf("1-bit flip in frame at bit %d not rejected with ErrAuthFailed: %v", fBit, err)
	}

	dBit := (len(frame)*7 + int(deviceID[0])) % 256
	corruptDev := deviceID
	corruptDev[dBit/8] ^= 1 << (dBit % 8)
	if _, err := tci1.Parse(frame, tokenKey, corruptDev, expectedSeq); !errors.Is(err, tci1.ErrAuthFailed) {
		t.Fatalf("1-bit flip in deviceID at bit %d not rejected with ErrAuthFailed: %v", dBit, err)
	}

	kBit := (len(frame)*5 + int(tokenKey[0])) % 256
	corruptKey := tokenKey
	corruptKey[kBit/8] ^= 1 << (kBit % 8)
	if _, err := tci1.Parse(frame, corruptKey, deviceID, expectedSeq); !errors.Is(err, tci1.ErrAuthFailed) && !errors.Is(err, tci1.ErrInvalidTokenKey) {
		t.Fatalf("1-bit flip in tokenKey at bit %d not rejected: %v", kBit, err)
	}
}

func derive32(b []byte, fill byte) [32]byte {
	var out [32]byte
	if len(b) >= 32 {
		copy(out[:], b[:32])
		return out
	}
	for i := range out {
		out[i] = fill
	}
	copy(out[:], b)
	return out
}

func FuzzTCI1CanonicalBijectionAndAuth(f *testing.F) {
	key := testKey()
	devID := testDeviceID()
	var sha [32]byte
	var asgn [16]byte
	var rot [32]byte
	for i := range sha {
		sha[i] = byte(0x21 + i)
		rot[i] = byte(0x61 + i)
	}
	for i := range asgn {
		asgn[i] = byte(0x90 + i)
	}

	updManifest := tci1.Manifest{
		TargetSlot:      tci1.SlotApp,
		SVN:             15,
		RemoteBuild:     1500,
		TotalSize:       8192,
		SHA256:          sha,
		AssignmentID:    asgn,
		SeqEcho:         101,
		RetryAfterSec:   3600,
		BlobPath:        "/v1/blobs/app_15.tbm1?rev=2&chan=prod",
		HasRotatedToken: true,
		RotatedToken:    rot,
		CloudCommand:    makeValidTCC1(128),
	}
	updFrame, err := tci1.Encode(updManifest, key, devID)
	if err != nil {
		f.Fatalf("Encode updManifest: %v", err)
	}

	ctrlManifest := tci1.Manifest{
		SeqEcho:         102,
		RetryAfterSec:   600,
		HasRotatedToken: true,
		RotatedToken:    rot,
	}
	ctrlFrame, err := tci1.Encode(ctrlManifest, key, devID)
	if err != nil {
		f.Fatalf("Encode ctrlManifest: %v", err)
	}

	ctrlCmdManifest := tci1.Manifest{
		SeqEcho:       103,
		RetryAfterSec: 120,
		CloudCommand:  makeValidTCC1(144),
	}
	ctrlCmdFrame, err := tci1.Encode(ctrlCmdManifest, key, devID)
	if err != nil {
		f.Fatalf("Encode ctrlCmdManifest: %v", err)
	}

	f.Add(updFrame, devID[:], key[:])
	f.Add(ctrlFrame, devID[:], key[:])
	f.Add(ctrlCmdFrame, devID[:], key[:])
	f.Add([]byte{}, devID[:], key[:])
	f.Add(updFrame[:tci1.MinFrameSize-1], devID[:], key[:])
	f.Add(updFrame, devID[:], make([]byte, 32))
	f.Add(updFrame, devID[:], bytes.Repeat([]byte{0xFF}, 32))

	f.Fuzz(func(t *testing.T, frame, deviceID, token []byte) {
		// 1. ValidateBlobPath closed RFC-3986 DFA vs independent reference specification.
		if len(frame) <= tci1.MaxBlobPathLen+16 {
			s := string(frame)
			gotOK := tci1.ValidateBlobPath(s) == nil
			wantOK := referenceRFC3986BlobPathOracle(s)
			if gotOK != wantOK {
				t.Fatalf("ValidateBlobPath(%q) = %v, reference oracle = %v", s, gotOK, wantOK)
			}
		}

		dev32 := derive32(deviceID, 0x00)
		tok32 := derive32(token, 0x5A)
		if len(token) == 0 {
			tok32 = [32]byte{}
		}

		expectedSeq := uint64(1)
		if len(frame) >= 80 {
			if s := binary.LittleEndian.Uint64(frame[72:80]); s != 0 {
				expectedSeq = s
			}
		}

		// 2. Direct untrusted (frame, deviceID, token) verification.
		verifyTCI1TupleOracle(t, frame, tok32, dev32, expectedSeq)

		// 3. Authenticated-MAC projection so fuzzing penetrates EtM gating into every structural check.
		if !isDegenerateKeyRef(tok32) && len(frame) >= tci1.MinFrameSize && len(frame) <= tci1.MaxFrameSize {
			sealed := bytes.Clone(frame)
			sealTCI1Auth(sealed, tok32, dev32)
			verifyTCI1TupleOracle(t, sealed, tok32, dev32, expectedSeq)
		}

		// 4. Structured Control-Only and Update candidate synthesis under fuzzer-driven section bytes.
		if !isDegenerateKeyRef(tok32) && len(frame) >= tci1.HeaderSize {
			isUpdate := (frame[0] & 1) != 0
			hasRot := (frame[0] & 2) != 0
			var flags uint16
			rotLen := 0
			if hasRot {
				flags |= tci1.FlagHasRotatedToken
				rotLen = tci1.RotatedTokenLen
			}
			var pathBytes []byte
			if isUpdate {
				pLen := int(frame[1]%40) + 1
				if tci1.HeaderSize+pLen <= len(frame) {
					pathBytes = frame[tci1.HeaderSize : tci1.HeaderSize+pLen]
				} else {
					pathBytes = []byte("/v1/b")
				}
			}
			bodyLen := tci1.HeaderSize + len(pathBytes) + rotLen
			if bodyLen+tci1.AuthTagLen <= tci1.MaxFrameSize {
				synth := make([]byte, bodyLen+tci1.AuthTagLen)
				copy(synth[:tci1.HeaderSize], frame[:tci1.HeaderSize])
				binary.LittleEndian.PutUint32(synth[0:4], tci1.Magic)
				synth[4] = tci1.Version
				binary.LittleEndian.PutUint16(synth[6:8], flags)
				binary.LittleEndian.PutUint16(synth[8:10], uint16(tci1.HeaderSize))
				binary.LittleEndian.PutUint16(synth[10:12], uint16(len(pathBytes)))
				binary.LittleEndian.PutUint16(synth[12:14], 0)
				if !isUpdate && (frame[2]&1) == 0 {
					// Clean control-only zeroed update fields so fuzzer exercises valid control-only frames too.
					synth[5] = 0
					clear(synth[14:72])
					clear(synth[80:84])
				}
				seq := binary.LittleEndian.Uint64(synth[72:80])
				if seq == 0 {
					seq = 1
					binary.LittleEndian.PutUint64(synth[72:80], seq)
				}
				retry := binary.LittleEndian.Uint32(synth[84:88])
				if retry > tci1.MaxRetryAfterSec && (frame[2]&2) == 0 {
					binary.LittleEndian.PutUint32(synth[84:88], retry%(tci1.MaxRetryAfterSec+1))
				}
				copy(synth[tci1.HeaderSize:], pathBytes)
				if hasRot {
					for i := range rotLen {
						synth[tci1.HeaderSize+len(pathBytes)+i] = frame[(i+3)%len(frame)] ^ byte(i+1)
					}
				}
				sealTCI1Auth(synth, tok32, dev32)
				verifyTCI1TupleOracle(t, synth, tok32, dev32, seq)
			}
		}
	})
}

func TestTCI1ExhaustiveBitFlipAndZeroAllocProperties(t *testing.T) {
	key := testKey()
	devID := testDeviceID()
	var sha [32]byte
	var asgn [16]byte
	var rot [32]byte
	for i := range sha {
		sha[i] = byte(0x41 + i)
		rot[i] = byte(0xA1 + i)
	}
	asgn[15] = 0x01

	manifests := []tci1.Manifest{
		{
			TargetSlot:      tci1.SlotStage1,
			SVN:             8,
			RemoteBuild:     800,
			TotalSize:       16384,
			SHA256:          sha,
			AssignmentID:    asgn,
			SeqEcho:         77,
			RetryAfterSec:   900,
			BlobPath:        "/v1/blobs/stage1_8.tbm1?token=ok_1",
			HasRotatedToken: true,
			RotatedToken:    rot,
			CloudCommand:    makeValidTCC1(160),
		},
		{
			SeqEcho:         78,
			RetryAfterSec:   0,
			HasRotatedToken: true,
			RotatedToken:    rot,
		},
	}

	var scratch [tci1.MaxFrameSize]byte
	var view tci1.Manifest

	for idx, m := range manifests {
		frame, err := tci1.Encode(m, key, devID)
		if err != nil {
			t.Fatalf("manifest %d Encode: %v", idx, err)
		}

		// Exhaustive single-bit flip across EVERY bit of frame, deviceID, and tokenKey.
		for bit := range len(frame) * 8 {
			corrupt := bytes.Clone(frame)
			corrupt[bit/8] ^= 1 << (bit % 8)
			if _, err := tci1.Parse(corrupt, key, devID, m.SeqEcho); !errors.Is(err, tci1.ErrAuthFailed) {
				t.Fatalf("manifest %d frame bit %d flip: expected ErrAuthFailed, got %v", idx, bit, err)
			}
		}
		for bit := range len(devID) * 8 {
			corruptDev := devID
			corruptDev[bit/8] ^= 1 << (bit % 8)
			if _, err := tci1.Parse(frame, key, corruptDev, m.SeqEcho); !errors.Is(err, tci1.ErrAuthFailed) {
				t.Fatalf("manifest %d deviceID bit %d flip: expected ErrAuthFailed, got %v", idx, bit, err)
			}
		}
		for bit := range len(key) * 8 {
			corruptKey := key
			corruptKey[bit/8] ^= 1 << (bit % 8)
			if _, err := tci1.Parse(frame, corruptKey, devID, m.SeqEcho); !errors.Is(err, tci1.ErrAuthFailed) && !errors.Is(err, tci1.ErrInvalidTokenKey) {
				t.Fatalf("manifest %d tokenKey bit %d flip: expected rejection, got %v", idx, bit, err)
			}
		}

		// Strict 0 allocs/op on AppendEncode and ParseView.
		encAllocs := testing.AllocsPerRun(100, func() {
			out, encErr := tci1.AppendEncode(scratch[:0], m, key, devID)
			if encErr != nil || !bytes.Equal(out, frame) {
				t.Fatalf("AppendEncode mismatch: err=%v", encErr)
			}
		})
		if encAllocs != 0 {
			t.Fatalf("manifest %d AppendEncode allocs=%v, want 0", idx, encAllocs)
		}
		decAllocs := testing.AllocsPerRun(100, func() {
			if decErr := tci1.ParseView(frame, key, devID, m.SeqEcho, &view); decErr != nil {
				t.Fatalf("ParseView failed: %v", decErr)
			}
		})
		if decAllocs != 0 {
			t.Fatalf("manifest %d ParseView allocs=%v, want 0", idx, decAllocs)
		}
	}
}
