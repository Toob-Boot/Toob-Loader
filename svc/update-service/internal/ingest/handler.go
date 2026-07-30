package ingest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/toob-boot/update-service/internal/store"
	"github.com/toob-boot/update-service/internal/svn"
)

// Handler exposes the internal ingest and release HTTP administration API.
type Handler struct {
	svc *IngestService
}

// NewHandler constructs a mountable HTTP handler for the ingest API.
func NewHandler(svc *IngestService) *Handler {
	return &Handler{svc: svc}
}

// RegisterRoutes registers the ingest HTTP endpoints on mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/internal/artifacts", h.HandleIngestArtifact)
	mux.HandleFunc("/v1/internal/releases", h.HandleSetRelease)
}

// HandleIngestArtifact handles POST /v1/internal/artifacts.
// Supports multipart/form-data (file upload) and application/json.
func (h *Handler) HandleIngestArtifact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed: POST required")
		return
	}

	var req IngestRequest

	contentType := r.Header.Get("Content-Type")
	if len(contentType) >= 19 && contentType[:19] == "multipart/form-data" {
		// Multipart Form Upload
		if err := r.ParseMultipartForm(64 << 20); err != nil { // 64 MiB limit
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid multipart form: %v", err))
			return
		}

		file, _, err := r.FormFile("blob")
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "missing 'blob' file in form data")
			return
		}
		defer file.Close()

		blobBytes, err := io.ReadAll(file)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("failed to read blob file: %v", err))
			return
		}

		req.Blob = blobBytes
		req.Product = r.FormValue("product")
		req.Channel = r.FormValue("channel")
		req.Kind = r.FormValue("kind")
		req.AuditReason = r.FormValue("audit_reason")
		req.ForceSVN = r.FormValue("force_svn") == "true"

		if baseStr := r.FormValue("base_build"); baseStr != "" {
			val, err := strconv.ParseInt(baseStr, 10, 32)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid base_build integer")
				return
			}
			v32 := int32(val)
			req.BaseBuild = &v32
		}

		// Optional Operator Metadata JSON string
		if metaJSON := r.FormValue("operator_metadata"); metaJSON != "" {
			var meta OperatorMetadata
			if err := json.Unmarshal([]byte(metaJSON), &meta); err != nil {
				writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid operator_metadata JSON: %v", err))
				return
			}
			req.OperatorMetadata = &meta
		}
	} else {
		// JSON Payload
		var jsonReq struct {
			Product          string            `json:"product"`
			Channel          string            `json:"channel,omitempty"`
			Kind             string            `json:"kind"`
			BaseBuild        *int32            `json:"base_build,omitempty"`
			Blob             []byte            `json:"blob"`
			ForceSVN         bool              `json:"force_svn,omitempty"`
			AuditReason      string            `json:"audit_reason,omitempty"`
			OperatorMetadata *OperatorMetadata `json:"operator_metadata,omitempty"`
		}

		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&jsonReq); err != nil {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
			return
		}

		req.Product = jsonReq.Product
		req.Channel = jsonReq.Channel
		req.Kind = jsonReq.Kind
		req.BaseBuild = jsonReq.BaseBuild
		req.Blob = jsonReq.Blob
		req.ForceSVN = jsonReq.ForceSVN
		req.AuditReason = jsonReq.AuditReason
		req.OperatorMetadata = jsonReq.OperatorMetadata
	}

	rec, err := h.svc.IngestArtifact(r.Context(), req)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrProductRequired) || errors.Is(err, ErrBlobRequired) ||
			errors.Is(err, ErrInvalidKind) || errors.Is(err, ErrDeltaRequiresBaseBuild) ||
			errors.Is(err, ErrFullForbiddenBaseBuild) {
			status = http.StatusBadRequest
		} else if errors.Is(err, ErrOperatorMetadataMismatch) {
			status = http.StatusBadRequest
		} else if errors.As(err, new(*svn.ErrSVNTooLow)) || errors.Is(err, svn.ErrForceRequiresAuditReason) {
			status = http.StatusConflict
		} else if errors.Is(err, store.ErrDigestMismatch) {
			status = http.StatusInternalServerError
		}

		writeJSONError(w, status, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, rec)
}

// HandleSetRelease handles POST /v1/internal/releases.
func (h *Handler) HandleSetRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed: POST required")
		return
	}

	var req ReleaseRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)) // 1 MiB limit
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
		return
	}

	rec, err := h.svc.SetRelease(r.Context(), req)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrArtifactNotFound) {
			status = http.StatusNotFound
		} else if errors.Is(err, ErrArtifactProductMismatch) {
			status = http.StatusUnprocessableEntity
		}
		writeJSONError(w, status, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, rec)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
