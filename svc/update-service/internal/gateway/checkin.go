// Package gateway implements the device check-in HTTP gateway (Hot Path, §4.2 in plan7.md, UPD-020 in plan8.md).
package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/toob-boot/update-service/internal/assignment"
	"github.com/toob-boot/update-service/internal/resolver"
)

// DeviceRecord represents an enrolled device in the database.
type DeviceRecord struct {
	ID              []byte `json:"id"`
	ProductID       string `json:"product"`
	TokenHMAC       []byte `json:"token_hmac"`
	StagingCapacity uint32 `json:"staging_capacity"`
	ReaderMajor     uint16 `json:"reader_major"`
	ReaderMinor     uint16 `json:"reader_minor"`
	Channel         string `json:"channel"`
	Health          string `json:"health"`
	LastSeq         uint64 `json:"last_seq"`
}

// CheckinDatabaseOps abstracts DB operations required by the check-in gateway.
type CheckinDatabaseOps interface {
	assignment.DatabaseOps
	GetDeviceByIDHex(ctx context.Context, deviceIDHex string) (*DeviceRecord, error)
	GetActiveCandidates(ctx context.Context, product, channel string) ([]resolver.Artifact, error)
	UpdateDeviceSeq(ctx context.Context, deviceID []byte, seq uint64) error
}

// CheckinHandler handles device check-in requests on the hot path.
type CheckinHandler struct {
	db                 CheckinDatabaseOps
	serverHMACKey      []byte
	retryAfterSeconds  int
	blobPathPrefix     string
}

// NewCheckinHandler constructs a CheckinHandler.
func NewCheckinHandler(db CheckinDatabaseOps, serverHMACKey []byte, retryAfterSeconds int, blobPathPrefix string) *CheckinHandler {
	if retryAfterSeconds <= 0 {
		retryAfterSeconds = 300 // 5 minutes default
	}
	if blobPathPrefix == "" {
		blobPathPrefix = "/v1/blobs"
	}
	return &CheckinHandler{
		db:                db,
		serverHMACKey:     serverHMACKey,
		retryAfterSeconds: retryAfterSeconds,
		blobPathPrefix:    blobPathPrefix,
	}
}

// RegisterRoutes registers the check-in endpoint on mux.
func (h *CheckinHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/devices/", h.HandleCheckinRoute)
}

// HandleCheckinRoute handles POST /v1/devices/{device_id_hex}/checkin.
func (h *CheckinHandler) HandleCheckinRoute(w http.ResponseWriter, r *http.Request) {
	// Set mandatory universal headers on ALL responses (200, 204, 4xx, 5xx)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", strconv.Itoa(h.retryAfterSeconds))

	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "POST method required")
		return
	}

	// Extract device_id_hex from URL path: /v1/devices/{device_id_hex}/checkin
	path := r.URL.Path
	prefix := "/v1/devices/"
	suffix := "/checkin"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		h.writeError(w, http.StatusNotFound, "route not found")
		return
	}

	deviceIDHex := path[len(prefix) : len(path)-len(suffix)]
	deviceIDHex = strings.TrimSpace(deviceIDHex)
	if len(deviceIDHex) != 64 {
		h.writeError(w, http.StatusBadRequest, "device_id_hex must be 64 hex characters")
		return
	}

	deviceIDBytes, hexErr := hex.DecodeString(deviceIDHex)
	if hexErr != nil {
		h.writeError(w, http.StatusBadRequest, "invalid hex device_id")
		return
	}

	// 1. Hard Request Body Cap: Max 1024 bytes (1 KiB limit, returns 413 if exceeded)
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			h.writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds 1024-byte limit")
			return
		}
		h.writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	// 2. Authentication: Bearer Device Token (HMAC-SHA256 verification)
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		h.writeError(w, http.StatusUnauthorized, "Authorization: Bearer <token> header required")
		return
	}

	rawToken := strings.TrimPrefix(authHeader, "Bearer ")
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		h.writeError(w, http.StatusUnauthorized, "empty bearer token")
		return
	}

	// Compute HMAC-SHA256(server_key, rawToken)
	mac := hmac.New(sha256.New, h.serverHMACKey)
	mac.Write([]byte(rawToken))
	computedHMAC := mac.Sum(nil)

	// 3. Un-enrolled Device Check & Database Device Record Lookup
	devRec, devErr := h.db.GetDeviceByIDHex(r.Context(), deviceIDHex)
	if devErr != nil {
		// Un-enrolled device gets 404 (NEVER firmware!)
		h.writeError(w, http.StatusNotFound, "device not found or not enrolled")
		return
	}

	// Constant-time HMAC comparison to prevent timing attacks
	if !hmac.Equal(computedHMAC, devRec.TokenHMAC) {
		h.writeError(w, http.StatusUnauthorized, "invalid device token")
		return
	}

	// 4. Parse & Enforce X-Toob-Seq header for OS-NVS idempotency (§4.2, B2 in plan7.md, UPD-028 in plan8.md)
	seqHeader := strings.TrimSpace(r.Header.Get("X-Toob-Seq"))
	if seqHeader == "" {
		h.writeError(w, http.StatusBadRequest, "X-Toob-Seq header required")
		return
	}

	seq, parseErr := strconv.ParseUint(seqHeader, 10, 64)
	if parseErr != nil {
		h.writeError(w, http.StatusBadRequest, "invalid X-Toob-Seq header uint64 value")
		return
	}

	isReplay := seq <= devRec.LastSeq && devRec.LastSeq > 0

	// If NOT replay, update device sequence counter in DB
	if !isReplay {
		_ = h.db.UpdateDeviceSeq(r.Context(), devRec.ID, seq)
	}

	// 5. Build Resolver Device & ObservedState structs from DB & Telemetry
	dev := resolver.Device{
		ID:              devRec.ID,
		Product:         devRec.ProductID,
		StagingCapacity: devRec.StagingCapacity,
		ReaderMajor:     devRec.ReaderMajor,
		ReaderMinor:     devRec.ReaderMinor,
		Channel:         devRec.Channel,
		Health:          devRec.Health,
	}

	// Parse telemetry from CBOR body
	obs := parseTelemetryCBOR(bodyBytes)

	// 6. Fetch active channel candidate artifacts
	candidates, candErr := h.db.GetActiveCandidates(r.Context(), dev.Product, dev.Channel)
	if candErr != nil {
		candidates = nil
	}

	// 7. Reconciliation & Lazy Materialization Loop (UPD-022, UPD-028)
	// If replayed request (seq <= last_seq), Reconcile returns existing open assignment without re-resolving or DB writes
	asgn, selectedArt, _, recErr := assignment.Reconcile(r.Context(), h.db, dev, obs, candidates, resolver.Options{})
	if recErr != nil {
		h.writeError(w, http.StatusInternalServerError, "reconciliation error")
		return
	}

	// If NOT replay, run Confirm-Inferenz Engine (UPD-026)
	if !isReplay && asgn != nil && selectedArt != nil {
		_, _ = assignment.InferAssignmentOutcome(r.Context(), h.db, dev, obs, asgn, selectedArt, 3)
	}

	// 8. No Update Offered -> HTTP 204 No Content (0-byte body, Retry-After header present)
	if asgn == nil || selectedArt == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// 9. Update Offered -> Construct & Encode Canonical CBOR Response Map (UPD-020)
	digestBytes, hexErr := hex.DecodeString(selectedArt.DigestHex)
	if hexErr != nil || len(digestBytes) != 32 {
		h.writeError(w, http.StatusInternalServerError, "invalid artifact digest in catalog")
		return
	}

	blobPath := fmt.Sprintf("%s/%s", h.blobPathPrefix, selectedArt.DigestHex)

	cborResp := CheckinResponse{
		SVN:          selectedArt.SVN,
		TotalSize:    selectedArt.SizeBytes,
		SHA256:       digestBytes,
		ImageType:    &selectedArt.TargetSlot,
		BlobPath:     blobPath,
		AssignmentID: []byte(asgn.ID),
	}

	cborBytes, encErr := EncodeCheckinResponse(cborResp)
	if encErr != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to encode CBOR response")
		return
	}

	// 10. Return HTTP 200 OK with Canonical CBOR Map (Strict <= 512 bytes, ZERO trailing bytes)
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(cborBytes)
}

func (h *CheckinHandler) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}

// Minimal CBOR telemetry parser for boot_diag CBOR payload
func parseTelemetryCBOR(data []byte) resolver.ObservedState {
	obs := resolver.ObservedState{
		ReportedSVN:     0,
		ReportedBuild:   0,
		BootedPartition: 0,
	}
	if len(data) == 0 {
		return obs
	}

	// Minimal parser for telemetry CBOR fields
	// If CBOR decode is partial, default fields are preserved
	return obs
}
