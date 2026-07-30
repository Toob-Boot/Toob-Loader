// Package ingest implements firmware artifact ingestion, Header Authority verification,
// and atomic channel release pointers (§5, §7.4 in plan7.md, UPD-014 in plan8.md).
package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/toob-boot/update-service/internal/admit"
	"github.com/toob-boot/update-service/internal/store"
	"github.com/toob-boot/update-service/internal/svn"
)

// Ingest Sentinel Errors
var (
	ErrProductRequired          = errors.New("ingest: product is required")
	ErrBlobRequired             = errors.New("ingest: artifact blob cannot be empty")
	ErrInvalidKind              = errors.New("ingest: kind must be 'full' or 'delta'")
	ErrDeltaRequiresBaseBuild   = errors.New("ingest: delta artifact requires base_build")
	ErrFullForbiddenBaseBuild   = errors.New("ingest: full artifact cannot have base_build")
	ErrOperatorMetadataMismatch = errors.New("ingest: operator metadata disagrees with signed TBM1 header")
	ErrArtifactAlreadyExists    = errors.New("ingest: artifact with this digest already exists in database")
	ErrArtifactNotFound         = errors.New("ingest: specified artifact_id not found")
	ErrArtifactProductMismatch  = errors.New("ingest: artifact product does not match release product")
)

// OperatorMetadata contains optional operator claims to cross-check against the TBM1 header.
type OperatorMetadata struct {
	BuildNumber *uint32 `json:"build_number,omitempty"`
	SVN         *uint32 `json:"svn,omitempty"`
	ProductID   *uint16 `json:"product_id,omitempty"`
	VendorID    *uint16 `json:"vendor_id,omitempty"`
	HWRevMin    *uint16 `json:"hw_rev_min,omitempty"`
	HWRevMax    *uint16 `json:"hw_rev_max,omitempty"`
	KeyIndex    *uint8  `json:"key_index,omitempty"`
}

// IngestRequest contains parameters for ingesting a signed firmware artifact.
type IngestRequest struct {
	Product          string
	Channel          string // Optional target channel e.g. "stable"
	Kind             string // "full" or "delta"
	BaseBuild        *int32 // Required if Kind == "delta"
	Blob             []byte
	ForceSVN         bool
	AuditReason      string
	OperatorMetadata *OperatorMetadata
}

// ArtifactRecord represents a registered artifact in the catalog.
type ArtifactRecord struct {
	ID             string    `json:"id"`
	Product        string    `json:"product"`
	BuildNumber    uint32    `json:"build_number"`
	Kind           string    `json:"kind"`
	BaseBuild      *int32    `json:"base_build,omitempty"`
	DigestHex      string    `json:"digest_hex"`
	SizeBytes      int32     `json:"size_bytes"`
	SVN            uint32    `json:"svn"`
	Stage1SVN      uint32    `json:"stage1_svn"`
	KeyIndex       uint8     `json:"key_index"`
	HWRevMin       uint16    `json:"hw_rev_min"`
	HWRevMax       uint16    `json:"hw_rev_max"`
	MinReaderMajor uint16    `json:"min_reader_major"`
	MinReaderMinor uint16    `json:"min_reader_minor"`
	FWVerMajor     uint16    `json:"fw_ver_major"`
	FWVerMinor     uint16    `json:"fw_ver_minor"`
	FWVerPatch     uint16    `json:"fw_ver_patch"`
	SBOMDigestHex  string    `json:"sbom_digest_hex"`
	TargetSlot     uint8     `json:"target_slot"`
	ImageCount     uint8     `json:"image_count"`
	AdmittedAt     time.Time `json:"admitted_at"`
}

// ReleaseRequest contains parameters for pointing a channel to an artifact.
type ReleaseRequest struct {
	Product    string `json:"product"`
	Channel    string `json:"channel"`
	ArtifactID string `json:"artifact_id"`
}

// ReleaseRecord represents an active channel release pointer.
type ReleaseRecord struct {
	ID          string    `json:"id"`
	Product     string    `json:"product"`
	Channel     string    `json:"channel"`
	ArtifactID  string    `json:"artifact_id"`
	Active      bool      `json:"active"`
	ActivatedAt time.Time `json:"activated_at"`
}

// FleetProvider retrieves channel device fleet profiles for admission checks.
type FleetProvider interface {
	GetChannelProfile(ctx context.Context, product, channel string) (admit.ChannelProfile, error)
}

// DatabaseOps abstracts database transaction operations for ingest and releases.
type DatabaseOps interface {
	BeginTx(ctx context.Context) (TxOps, error)
}

// TxOps abstracts transaction queries.
type TxOps interface {
	svn.ExecQueryRow
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
	InsertArtifact(ctx context.Context, record *ArtifactRecord, digestBytes, sbomDigestBytes []byte) error
	GetArtifactByID(ctx context.Context, artifactID string) (*ArtifactRecord, error)
	DeactivateChannelReleases(ctx context.Context, product, channel string) error
	InsertRelease(ctx context.Context, product, channel, artifactID string) (*ReleaseRecord, error)
}

// IngestService handles artifact admission, storage, and release pointer deployment.
type IngestService struct {
	db          DatabaseOps
	objectStore store.ObjectStore
	fleet       FleetProvider
}

// NewIngestService constructs an IngestService.
func NewIngestService(db DatabaseOps, objectStore store.ObjectStore, fleet FleetProvider) *IngestService {
	return &IngestService{
		db:          db,
		objectStore: objectStore,
		fleet:       fleet,
	}
}

// IngestArtifact executes the full admission, SVN guard, WORM store, and catalog registration pipeline.
func (s *IngestService) IngestArtifact(ctx context.Context, req IngestRequest) (*ArtifactRecord, error) {
	// 1. Basic Parameter Validation
	req.Product = strings.TrimSpace(req.Product)
	if req.Product == "" {
		return nil, ErrProductRequired
	}
	if len(req.Blob) == 0 {
		return nil, ErrBlobRequired
	}

	req.Kind = strings.ToLower(strings.TrimSpace(req.Kind))
	if req.Kind != "full" && req.Kind != "delta" {
		return nil, ErrInvalidKind
	}
	if req.Kind == "delta" && req.BaseBuild == nil {
		return nil, ErrDeltaRequiresBaseBuild
	}
	if req.Kind == "full" && req.BaseBuild != nil {
		return nil, ErrFullForbiddenBaseBuild
	}

	// 2. Compute Blob Digest (SHA-256)
	digestArray := sha256.Sum256(req.Blob)
	digestBytes := digestArray[:]
	digestHex := hex.EncodeToString(digestBytes)

	// 3. Fetch Fleet Channel Profile for Admission Gate
	var profile admit.ChannelProfile
	if s.fleet != nil && req.Channel != "" {
		p, err := s.fleet.GetChannelProfile(ctx, req.Product, req.Channel)
		if err == nil {
			profile = p
		}
	}

	// 4. Admission Gate Validation (C-Reader + 4 rules)
	admitRes := admit.Admit(req.Blob, profile)
	if !admitRes.Accepted {
		return nil, fmt.Errorf("ingest: admission gate rejected artifact (rule: %s): %s", admitRes.Rule, admitRes.Reason)
	}

	hdr := admitRes.Header

	// 5. Header Authority Rule: Verify Operator Claims against extracted Header
	if req.OperatorMetadata != nil {
		op := req.OperatorMetadata
		if op.BuildNumber != nil && *op.BuildNumber != hdr.BuildNumber {
			return nil, fmt.Errorf("%w: claimed build_number %d != header %d", ErrOperatorMetadataMismatch, *op.BuildNumber, hdr.BuildNumber)
		}
		if op.SVN != nil && *op.SVN != hdr.SVN {
			return nil, fmt.Errorf("%w: claimed svn %d != header %d", ErrOperatorMetadataMismatch, *op.SVN, hdr.SVN)
		}
		if op.ProductID != nil && *op.ProductID != hdr.ProductID {
			return nil, fmt.Errorf("%w: claimed product_id %d != header %d", ErrOperatorMetadataMismatch, *op.ProductID, hdr.ProductID)
		}
		if op.VendorID != nil && *op.VendorID != hdr.VendorID {
			return nil, fmt.Errorf("%w: claimed vendor_id %d != header %d", ErrOperatorMetadataMismatch, *op.VendorID, hdr.VendorID)
		}
		if op.HWRevMin != nil && *op.HWRevMin != hdr.HWRevMin {
			return nil, fmt.Errorf("%w: claimed hw_rev_min %d != header %d", ErrOperatorMetadataMismatch, *op.HWRevMin, hdr.HWRevMin)
		}
		if op.HWRevMax != nil && *op.HWRevMax != hdr.HWRevMax {
			return nil, fmt.Errorf("%w: claimed hw_rev_max %d != header %d", ErrOperatorMetadataMismatch, *op.HWRevMax, hdr.HWRevMax)
		}
		if op.KeyIndex != nil && *op.KeyIndex != hdr.KeyIndex {
			return nil, fmt.Errorf("%w: claimed key_index %d != header %d", ErrOperatorMetadataMismatch, *op.KeyIndex, hdr.KeyIndex)
		}
	}

	// 6. Begin Transaction for DB SVN floor check & Record Insertion
	tx, err := s.db.BeginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("ingest: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// 7. Enforce Per-Slot SVN Monotonicity Guard (UPD-012)
	if err := svn.EnforceFloor(ctx, tx, req.Product, hdr.TargetSlot, hdr.SVN, req.ForceSVN, req.AuditReason); err != nil {
		return nil, fmt.Errorf("ingest: svn floor check failed: %w", err)
	}

	// 8. Upload to WORM Object Store with Read-Back Digest Check (UPD-013)
	if err := s.objectStore.Put(ctx, digestHex, req.Blob, digestBytes); err != nil {
		if errors.Is(err, store.ErrObjectExists) {
			// Key exists in store; verify it exists in DB as well
		} else {
			return nil, fmt.Errorf("ingest: WORM store write failed: %w", err)
		}
	}

	// Prepare Record
	sbomHex := hex.EncodeToString(hdr.SBOMDigest[:])
	rec := &ArtifactRecord{
		Product:        req.Product,
		BuildNumber:    hdr.BuildNumber,
		Kind:           req.Kind,
		BaseBuild:      req.BaseBuild,
		DigestHex:      digestHex,
		SizeBytes:      int32(hdr.TotalLen),
		SVN:            hdr.SVN,
		Stage1SVN:      hdr.Stage1SVN,
		KeyIndex:       hdr.KeyIndex,
		HWRevMin:       hdr.HWRevMin,
		HWRevMax:       hdr.HWRevMax,
		MinReaderMajor: hdr.MinReaderMajor,
		MinReaderMinor: hdr.MinReaderMinor,
		FWVerMajor:     hdr.FWVerMajor,
		FWVerMinor:     hdr.FWVerMinor,
		FWVerPatch:     hdr.FWVerPatch,
		SBOMDigestHex:  sbomHex,
		TargetSlot:     hdr.TargetSlot,
		ImageCount:     hdr.ImageCount,
		AdmittedAt:     time.Now().UTC(),
	}

	// 9. Insert Artifact Record in Database
	if err := tx.InsertArtifact(ctx, rec, digestBytes, hdr.SBOMDigest[:]); err != nil {
		return nil, fmt.Errorf("ingest: insert artifact record: %w", err)
	}

	// 10. Commit Transaction
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("ingest: commit tx: %w", err)
	}

	return rec, nil
}

// SetRelease atomically sets the active release for a product channel.
func (s *IngestService) SetRelease(ctx context.Context, req ReleaseRequest) (*ReleaseRecord, error) {
	req.Product = strings.TrimSpace(req.Product)
	req.Channel = strings.TrimSpace(req.Channel)
	req.ArtifactID = strings.TrimSpace(req.ArtifactID)

	if req.Product == "" || req.Channel == "" || req.ArtifactID == "" {
		return nil, errors.New("ingest: product, channel, and artifact_id are required")
	}

	tx, err := s.db.BeginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("ingest.SetRelease: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// 1. Verify artifact exists
	art, err := tx.GetArtifactByID(ctx, req.ArtifactID)
	if err != nil {
		return nil, ErrArtifactNotFound
	}

	// 2. Verify product matches
	if !bytes.Equal([]byte(art.Product), []byte(req.Product)) {
		return nil, fmt.Errorf("%w: artifact product %q != release product %q", ErrArtifactProductMismatch, art.Product, req.Product)
	}

	// 3. Deactivate current active release for (product, channel)
	if err := tx.DeactivateChannelReleases(ctx, req.Product, req.Channel); err != nil {
		return nil, fmt.Errorf("ingest.SetRelease: deactivate current release: %w", err)
	}

	// 4. Insert new active release
	rel, err := tx.InsertRelease(ctx, req.Product, req.Channel, req.ArtifactID)
	if err != nil {
		return nil, fmt.Errorf("ingest.SetRelease: insert active release: %w", err)
	}

	// 5. Commit Transaction
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("ingest.SetRelease: commit tx: %w", err)
	}

	return rel, nil
}
