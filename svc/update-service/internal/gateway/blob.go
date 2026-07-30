// Package gateway implements blob payload delivery with strict Range 206, 416 guard,
// identity encoding, and zero 3xx redirects (§3.3 in plan7.md, UPD-023 in plan8.md).
package gateway

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/toob-boot/update-service/internal/store"
)

// BlobHandler handles firmware binary blob delivery.
type BlobHandler struct {
	objectStore store.ObjectStore
}

// NewBlobHandler constructs a BlobHandler.
func NewBlobHandler(objectStore store.ObjectStore) *BlobHandler {
	return &BlobHandler{objectStore: objectStore}
}

// RegisterRoutes registers the blob delivery endpoint on mux.
func (h *BlobHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/blobs/", h.HandleBlobDelivery)
}

// HandleBlobDelivery handles GET and HEAD /v1/blobs/{digest_hex}.
func (h *BlobHandler) HandleBlobDelivery(w http.ResponseWriter, r *http.Request) {
	// Prohibit non-GET/HEAD methods
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method Not Allowed: GET or HEAD required", http.StatusMethodNotAllowed)
		return
	}

	// Extract digest_hex from URL path /v1/blobs/{digest_hex}
	path := r.URL.Path
	prefix := "/v1/blobs/"
	if !strings.HasPrefix(path, prefix) {
		http.NotFound(w, r)
		return
	}

	digestHex := strings.TrimPrefix(path, prefix)
	digestHex = strings.TrimSpace(strings.ToLower(digestHex))

	// Validate hex digest format (must be 64 hex characters == 32 bytes SHA-256)
	if len(digestHex) != 64 {
		http.NotFound(w, r)
		return
	}

	digestBytes, err := hex.DecodeString(digestHex)
	if err != nil || len(digestBytes) != 32 {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()

	// Verify object exists in WORM store
	exists, err := h.objectStore.Exists(ctx, digestHex)
	if err != nil || !exists {
		http.NotFound(w, r)
		return
	}

	// Fetch full object metadata/reader to obtain total_size
	rc, totalSize, err := h.objectStore.Get(ctx, digestHex, 0, -1)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_ = rc.Close() // Close probe reader immediately

	// Mandatory Invariant Headers (§3.3 plan7.md)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("ETag", fmt.Sprintf("%q", digestHex))
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")

	// FORCE identity encoding — explicitly override/prevent Gzip middleware!
	// Transparent compression shifts byte offsets and destroys MCU resume logic.
	w.Header().Set("Content-Encoding", "identity")

	// Parse Range Header
	rangeHeader := r.Header.Get("Range")
	start, length, isRange, isUnsatisfiable := parseByteRange(rangeHeader, totalSize)

	// CRITICAL SAFETY GUARD: Unsatisfiable Range MUST return HTTP 416, NEVER HTTP 200!
	if isUnsatisfiable {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", totalSize))
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(fmt.Sprintf("Requested Range Not Satisfiable: total size is %d bytes", totalSize)))
		}
		return
	}

	// Prepare Stream Reader
	streamReader, streamLen, err := h.objectStore.Get(ctx, digestHex, start, length)
	if err != nil {
		http.Error(w, "Failed to read storage object", http.StatusInternalServerError)
		return
	}
	defer streamReader.Close()

	if isRange {
		// HTTP 206 Partial Content
		end := start + streamLen - 1
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, totalSize))
		w.Header().Set("Content-Length", strconv.FormatInt(streamLen, 10))
		w.WriteHeader(http.StatusPartialContent)
	} else {
		// HTTP 200 OK Full Content
		w.Header().Set("Content-Length", strconv.FormatInt(totalSize, 10))
		w.WriteHeader(http.StatusOK)
	}

	// If HEAD request, return headers only (no body)
	if r.Method == http.MethodHead {
		return
	}

	// Stream payload directly from WORM store to client (NO 3xx REDIRECTS!)
	_, _ = io.Copy(w, streamReader)
}

// parseByteRange parses an HTTP Range header string (e.g., "bytes=100-499" or "bytes=500-").
// Returns start offset, length, whether range was requested, and whether range is unsatisfiable.
func parseByteRange(header string, totalSize int64) (start int64, length int64, isRange bool, isUnsatisfiable bool) {
	header = strings.TrimSpace(header)
	if header == "" || !strings.HasPrefix(header, "bytes=") {
		return 0, totalSize, false, false
	}

	spec := strings.TrimPrefix(header, "bytes=")
	parts := strings.Split(spec, "-")
	if len(parts) != 2 {
		return 0, totalSize, false, true // Invalid range syntax -> unsatisfiable
	}

	startStr := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])

	if startStr == "" {
		// Suffix range e.g. bytes=-500 (last 500 bytes)
		suffixLen, err := strconv.ParseInt(endStr, 10, 64)
		if err != nil || suffixLen <= 0 {
			return 0, totalSize, false, true
		}
		if suffixLen > totalSize {
			suffixLen = totalSize
		}
		start = totalSize - suffixLen
		length = suffixLen
		return start, length, true, false
	}

	parsedStart, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil || parsedStart < 0 {
		return 0, totalSize, false, true
	}

	// CRITICAL CHECK: start >= totalSize is UNSATISFIABLE
	if parsedStart >= totalSize {
		return 0, totalSize, false, true
	}

	start = parsedStart

	if endStr == "" {
		// Open range e.g. bytes=500- (from 500 to end of file)
		length = totalSize - start
		return start, length, true, false
	}

	parsedEnd, err := strconv.ParseInt(endStr, 10, 64)
	if err != nil || parsedEnd < start {
		return 0, totalSize, false, true // End < Start -> unsatisfiable
	}

	if parsedEnd >= totalSize {
		parsedEnd = totalSize - 1
	}

	length = parsedEnd - start + 1
	return start, length, true, false
}
