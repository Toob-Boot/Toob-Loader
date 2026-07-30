package gateway_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/toob-boot/update-service/internal/assignment"
	"github.com/toob-boot/update-service/internal/gateway"
	"github.com/toob-boot/update-service/internal/resolver"
)

// mockGatewayDB implements gateway.CheckinDatabaseOps for integration testing.
type mockGatewayDB struct {
	devices     map[string]*gateway.DeviceRecord      // key: hex(device_id)
	assignments map[string]*assignment.AssignmentRecord // key: assignment_id
	openByDev   map[string]*assignment.AssignmentRecord // key: hex(device_id)
	artifacts   map[string]*resolver.Artifact
	candidates  []resolver.Artifact
	lastSeq     uint64
}

func newMockGatewayDB() *mockGatewayDB {
	return &mockGatewayDB{
		devices:     make(map[string]*gateway.DeviceRecord),
		assignments: make(map[string]*assignment.AssignmentRecord),
		openByDev:   make(map[string]*assignment.AssignmentRecord),
		artifacts:   make(map[string]*resolver.Artifact),
	}
}

func (m *mockGatewayDB) GetDeviceByIDHex(ctx context.Context, deviceIDHex string) (*gateway.DeviceRecord, error) {
	dev, exists := m.devices[deviceIDHex]
	if !exists {
		return nil, errors.New("device not found")
	}
	return dev, nil
}

func (m *mockGatewayDB) GetActiveCandidates(ctx context.Context, product, channel string) ([]resolver.Artifact, error) {
	return m.candidates, nil
}

func (m *mockGatewayDB) UpdateDeviceSeq(ctx context.Context, deviceID []byte, seq uint64) error {
	m.lastSeq = seq
	key := fmt.Sprintf("%x", deviceID)
	if dev, exists := m.devices[key]; exists {
		dev.LastSeq = seq
	}
	return nil
}

func (m *mockGatewayDB) GetOpenAssignment(ctx context.Context, deviceID []byte) (*assignment.AssignmentRecord, error) {
	key := fmt.Sprintf("%x", deviceID)
	rec, exists := m.openByDev[key]
	if !exists || rec.State.IsTerminal() {
		return nil, assignment.ErrAssignmentNotFound
	}
	return rec, nil
}

func (m *mockGatewayDB) GetArtifactByID(ctx context.Context, artifactID string) (*resolver.Artifact, error) {
	art, exists := m.artifacts[artifactID]
	if !exists {
		return nil, errors.New("artifact not found")
	}
	return art, nil
}

func (m *mockGatewayDB) InsertAssignment(ctx context.Context, deviceID []byte, artifactID string, initialState assignment.State, source string) (*assignment.AssignmentRecord, error) {
	key := fmt.Sprintf("%x", deviceID)
	rec := &assignment.AssignmentRecord{
		ID:         fmt.Sprintf("asgn-%d", len(m.assignments)+1),
		DeviceID:   deviceID,
		ArtifactID: artifactID,
		State:      initialState,
		Source:     source,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	m.assignments[rec.ID] = rec
	m.openByDev[key] = rec
	return rec, nil
}

func (m *mockGatewayDB) UpdateAssignmentState(ctx context.Context, assignmentID string, newState assignment.State) error {
	rec, exists := m.assignments[assignmentID]
	if !exists {
		return assignment.ErrAssignmentNotFound
	}
	rec.State = newState
	return nil
}

func (m *mockGatewayDB) IncrementAssignmentAttempts(ctx context.Context, assignmentID string) (int16, error) {
	rec, exists := m.assignments[assignmentID]
	if !exists {
		return 0, assignment.ErrAssignmentNotFound
	}
	rec.Attempts++
	return rec.Attempts, nil
}

func (m *mockGatewayDB) SupersedeOpenAssignment(ctx context.Context, deviceID []byte) error {
	key := fmt.Sprintf("%x", deviceID)
	if rec, exists := m.openByDev[key]; exists && !rec.State.IsTerminal() {
		rec.State = assignment.StateSuperseded
	}
	return nil
}

func (m *mockGatewayDB) UpdateDeviceHealth(ctx context.Context, deviceID []byte, health string) error {
	key := fmt.Sprintf("%x", deviceID)
	if dev, exists := m.devices[key]; exists {
		dev.Health = health
	}
	return nil
}

func (m *mockGatewayDB) LogDeviceEvent(ctx context.Context, deviceID []byte, eventType string, payload map[string]interface{}) error {
	return nil
}

// Helpers
func setupTestGateway(t *testing.T) (*mockGatewayDB, *gateway.CheckinHandler, string, []byte, []byte) {
	serverKey := []byte("SUPER_SECRET_SERVER_HMAC_KEY_12345")
	rawToken := "device_secret_token_val_9999"

	mac := hmac.New(sha256.New, serverKey)
	mac.Write([]byte(rawToken))
	tokenHMAC := mac.Sum(nil)

	devIDBytes, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	devHex := hex.EncodeToString(devIDBytes)

	db := newMockGatewayDB()
	db.devices[devHex] = &gateway.DeviceRecord{
		ID:              devIDBytes,
		ProductID:       "toob-lamp-01",
		TokenHMAC:       tokenHMAC,
		StagingCapacity: 1024 * 1024,
		ReaderMajor:     2,
		ReaderMinor:     0,
		Channel:         "stable",
		Health:          "ok",
		LastSeq:         0,
	}

	handler := gateway.NewCheckinHandler(db, serverKey, 300, "/v1/blobs")
	return db, handler, devHex, devIDBytes, []byte(rawToken)
}

// ---- Tests ----

func TestCBOR_512ByteMaxBufferCap(t *testing.T) {
	targetSlot := uint8(0)
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	longBlobPath := "/v1/blobs/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if len(longBlobPath) > 128 {
		longBlobPath = longBlobPath[:128]
	}

	resp := gateway.CheckinResponse{
		SVN:          999999,
		TotalSize:    1048576,
		SHA256:       digest,
		ImageType:    &targetSlot,
		BlobPath:     longBlobPath,
		AssignmentID: []byte("asgn-12345678901"),
		RotatedToken: make([]byte, 32),
		CloudCommand: make([]byte, 64),
	}

	cborBytes, err := gateway.EncodeCheckinResponse(resp)
	if err != nil {
		t.Fatalf("failed to encode full CBOR response: %v", err)
	}

	if len(cborBytes) > 512 {
		t.Fatalf("HARD SAFETY VIOLATION: Encoded CBOR size %d bytes exceeds 512-byte client buffer limit!", len(cborBytes))
	}
}

func TestCheckinGateway_MissingXToobSeqHeader400(t *testing.T) {
	_, handler, devHex, _, rawToken := setupTestGateway(t)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	urlPath := fmt.Sprintf("/v1/devices/%s/checkin", devHex)
	req := httptest.NewRequest(http.MethodPost, urlPath, strings.NewReader("dummy_cbor"))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(rawToken)))
	req.Header.Set("Content-Type", "application/cbor")
	// NO X-Toob-Seq header set!

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 Bad Request for missing X-Toob-Seq header, got %d", rec.Code)
	}
}

func TestCheckinGateway_204NoContentWithRetryAfter(t *testing.T) {
	db, handler, devHex, _, rawToken := setupTestGateway(t)
	db.candidates = nil

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	urlPath := fmt.Sprintf("/v1/devices/%s/checkin", devHex)
	req := httptest.NewRequest(http.MethodPost, urlPath, strings.NewReader("dummy_cbor"))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(rawToken)))
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("X-Toob-Seq", "1")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected HTTP 204 No Content, got %d. Body: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("expected 0-byte body for 204 response, got %d bytes", rec.Body.Len())
	}
	if rec.Header().Get("Retry-After") != "300" {
		t.Errorf("expected Retry-After: 300, got %q", rec.Header().Get("Retry-After"))
	}
}

func TestCheckinGateway_3xRepeatedCheckinIdempotency(t *testing.T) {
	db, handler, devHex, _, rawToken := setupTestGateway(t)

	digestBytes := sha256.Sum256([]byte("FIRMWARE_BLOB_PAYLOAD"))
	digestHex := hex.EncodeToString(digestBytes[:])

	art := resolver.Artifact{
		ID:             "art-101",
		Product:        "toob-lamp-01",
		BuildNumber:    101,
		Kind:           "full",
		SizeBytes:      512 * 1024,
		SVN:            11,
		HWRevMin:       1,
		HWRevMax:       5,
		MinReaderMajor: 2,
		MinReaderMinor: 0,
		TargetSlot:     0,
		DigestHex:      digestHex,
	}
	db.candidates = []resolver.Artifact{art}
	db.artifacts["art-101"] = &art

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	urlPath := fmt.Sprintf("/v1/devices/%s/checkin", devHex)

	var firstResponseBody []byte

	// Fire exact same check-in request 3 times with X-Toob-Seq: 100
	for i := 1; i <= 3; i++ {
		req := httptest.NewRequest(http.MethodPost, urlPath, strings.NewReader("dummy_cbor"))
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(rawToken)))
		req.Header.Set("Content-Type", "application/cbor")
		req.Header.Set("X-Toob-Seq", "100") // Identical sequence number!

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected HTTP 200 OK, got %d", i, rec.Code)
		}

		body := rec.Body.Bytes()
		if i == 1 {
			firstResponseBody = body
		} else {
			// IDEMPOTENCY PROOF: Responses MUST be 100% byte-identical!
			if !bytes.Equal(body, firstResponseBody) {
				t.Fatalf("request %d: response body mismatch with request 1! Idempotency violated.", i)
			}
		}
	}

	// Verify exactly 1 assignment row was created in DB
	if len(db.assignments) != 1 {
		t.Errorf("IDEMPOTENCY VIOLATION: expected 1 assignment record, got %d", len(db.assignments))
	}
}

func TestCheckinGateway_413RequestBodyTooLarge(t *testing.T) {
	_, handler, devHex, _, rawToken := setupTestGateway(t)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	oversizedBody := make([]byte, 1025)

	urlPath := fmt.Sprintf("/v1/devices/%s/checkin", devHex)
	req := httptest.NewRequest(http.MethodPost, urlPath, bytes.NewReader(oversizedBody))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(rawToken)))
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("X-Toob-Seq", "1")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected HTTP 413 Payload Too Large, got %d", rec.Code)
	}
}

func TestCheckinGateway_401Unauthorized(t *testing.T) {
	_, handler, devHex, _, _ := setupTestGateway(t)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	urlPath := fmt.Sprintf("/v1/devices/%s/checkin", devHex)
	req := httptest.NewRequest(http.MethodPost, urlPath, strings.NewReader("dummy"))
	req.Header.Set("Authorization", "Bearer WRONG_TOKEN_VALUE")
	req.Header.Set("X-Toob-Seq", "1")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected HTTP 401 Unauthorized, got %d", rec.Code)
	}
}

func TestCheckinGateway_404UnenrolledDevice(t *testing.T) {
	_, handler, _, _, rawToken := setupTestGateway(t)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	unknownDevHex := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	urlPath := fmt.Sprintf("/v1/devices/%s/checkin", unknownDevHex)
	req := httptest.NewRequest(http.MethodPost, urlPath, strings.NewReader("dummy"))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(rawToken)))
	req.Header.Set("X-Toob-Seq", "1")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected HTTP 404 Not Found for un-enrolled device, got %d", rec.Code)
	}
}
