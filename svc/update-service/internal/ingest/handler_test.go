package ingest_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/toob-boot/update-service/internal/admit"
	"github.com/toob-boot/update-service/internal/ingest"
	"github.com/toob-boot/update-service/internal/store"
	"github.com/toob-boot/update-service/internal/svn"
	"github.com/toob-boot/update-service/pkg/tbm1"
)

// ---- Mocks for DB and Fleet ----

type mockTx struct {
	db              *mockDB
	floors          map[string]uint32
	artifacts       map[string]*ingest.ArtifactRecord
	releases        map[string]*ingest.ReleaseRecord // key: "product:channel"
	committed       bool
	forceAuditLogged bool
}

func (tx *mockTx) QueryRow(ctx context.Context, query string, args ...any) svn.RowScanner {
	product := args[0].(string)
	slot := args[1].(uint8)
	key := fmt.Sprintf("%s:%d", product, slot)

	val, exists := tx.floors[key]
	if !exists {
		return &mockRow{err: fmt.Errorf("no rows in result set")}
	}
	return &mockRow{val: val}
}

func (tx *mockTx) Exec(ctx context.Context, query string, args ...any) (any, error) {
	if len(args) >= 3 && query != "" {
		// Update floor
		product := args[0].(string)
		slot := args[1].(uint8)
		val := args[2].(uint32)
		key := fmt.Sprintf("%s:%d", product, slot)
		tx.floors[key] = val
	}
	if len(args) >= 2 && query != "" {
		tx.forceAuditLogged = true
	}
	return nil, nil
}

func (tx *mockTx) Commit(ctx context.Context) error {
	tx.committed = true
	return nil
}

func (tx *mockTx) Rollback(ctx context.Context) error {
	return nil
}

func (tx *mockTx) InsertArtifact(ctx context.Context, record *ingest.ArtifactRecord, digestBytes, sbomDigestBytes []byte) error {
	record.ID = fmt.Sprintf("art-%d", len(tx.artifacts)+1)
	tx.artifacts[record.ID] = record
	return nil
}

func (tx *mockTx) GetArtifactByID(ctx context.Context, artifactID string) (*ingest.ArtifactRecord, error) {
	rec, exists := tx.artifacts[artifactID]
	if !exists {
		return nil, ingest.ErrArtifactNotFound
	}
	return rec, nil
}

func (tx *mockTx) DeactivateChannelReleases(ctx context.Context, product, channel string) error {
	key := fmt.Sprintf("%s:%s", product, channel)
	if rel, exists := tx.releases[key]; exists {
		rel.Active = false
	}
	return nil
}

func (tx *mockTx) InsertRelease(ctx context.Context, product, channel, artifactID string) (*ingest.ReleaseRecord, error) {
	key := fmt.Sprintf("%s:%s", product, channel)
	rel := &ingest.ReleaseRecord{
		ID:          fmt.Sprintf("rel-%d", len(tx.releases)+1),
		Product:     product,
		Channel:     channel,
		ArtifactID:  artifactID,
		Active:      true,
		ActivatedAt: time.Now().UTC(),
	}
	tx.releases[key] = rel
	return rel, nil
}

type mockDB struct {
	activeTx *mockTx
}

func (m *mockDB) BeginTx(ctx context.Context) (ingest.TxOps, error) {
	return m.activeTx, nil
}

type mockRow struct {
	val uint32
	err error
}

func (m *mockRow) Scan(dest ...any) error {
	if m.err != nil {
		return m.err
	}
	if len(dest) > 0 {
		if ptr, ok := dest[0].(*uint32); ok {
			*ptr = m.val
		}
	}
	return nil
}

type mockFleet struct{}

func (f *mockFleet) GetChannelProfile(ctx context.Context, product, channel string) (admit.ChannelProfile, error) {
	return admit.ChannelProfile{
		HasDevices:         false,
		MinStagingCapacity: 1024 * 1024,
	}, nil
}

// Helper to create a valid signed TBM1 blob
func makeTestSignedBlob(t *testing.T, svnVal uint32, buildNum uint32) ([]byte, ed25519.PublicKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	signer, _ := tbm1.NewLocalSigner(priv)

	m := tbm1.Manifest{
		VendorID:    0x1234,
		ProductID:   0x0042,
		HWRevMin:    1,
		HWRevMax:    2,
		KeyIndex:    0,
		SVN:         svnVal,
		BuildNumber: buildNum,
		FwVerMajor:  1,
		FwVerMinor:  0,
		FwVerPatch:  0,
		AutoSBOM:    true,
		Images: []tbm1.Image{
			{
				Type:       1,
				TargetSlot: tbm1.SlotApp,
				Installed:  []byte("IMAGE_APP_BYTES_1234567890"),
			},
		},
	}

	pkg, err := tbm1.Build(m, signer)
	if err != nil {
		t.Fatalf("failed to build signed package: %v", err)
	}

	flat, err := pkg.AssembleFlat([][]byte{[]byte("IMAGE_APP_BYTES_1234567890")})
	if err != nil {
		t.Fatalf("failed to assemble flat image: %v", err)
	}

	return flat, pub
}

// ---- Integration Tests ----

func TestIngestHandler_ValidMultipartIngest(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "ingest_test_*")
	defer os.RemoveAll(tempDir)

	wStore, _ := store.NewLocalWORMStore(tempDir)
	tx := &mockTx{
		floors:    make(map[string]uint32),
		artifacts: make(map[string]*ingest.ArtifactRecord),
		releases:  make(map[string]*ingest.ReleaseRecord),
	}
	db := &mockDB{activeTx: tx}
	svc := ingest.NewIngestService(db, wStore, &mockFleet{})
	handler := ingest.NewHandler(svc)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	blob, _ := makeTestSignedBlob(t, 10, 100)

	// Create multipart request
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("product", "toob-lamp-01")
	_ = writer.WriteField("kind", "full")
	fileWriter, _ := writer.CreateFormFile("blob", "firmware.bin")
	_, _ = fileWriter.Write(blob)
	_ = writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/internal/artifacts", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected HTTP 201 Created, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var resp ingest.ArtifactRecord
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.Product != "toob-lamp-01" || resp.SVN != 10 || resp.BuildNumber != 100 {
		t.Errorf("unexpected record returned: %+v", resp)
	}

	// Verify WORM store contains the object
	exists, _ := wStore.Exists(context.Background(), resp.DigestHex)
	if !exists {
		t.Errorf("expected object %s to exist in WORM store", resp.DigestHex)
	}
}

func TestIngestHandler_OperatorMetadataMismatch(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "ingest_test_*")
	defer os.RemoveAll(tempDir)

	wStore, _ := store.NewLocalWORMStore(tempDir)
	tx := &mockTx{
		floors:    make(map[string]uint32),
		artifacts: make(map[string]*ingest.ArtifactRecord),
		releases:  make(map[string]*ingest.ReleaseRecord),
	}
	db := &mockDB{activeTx: tx}
	svc := ingest.NewIngestService(db, wStore, &mockFleet{})
	handler := ingest.NewHandler(svc)

	blob, _ := makeTestSignedBlob(t, 10, 100) // Header has SVN=10

	// Operator claims SVN=99 in JSON body
	claimedSVN := uint32(99)
	payload := map[string]any{
		"product": "toob-lamp-01",
		"kind":    "full",
		"blob":    blob,
		"operator_metadata": map[string]any{
			"svn": claimedSVN,
		},
	}
	bodyBytes, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/v1/internal/artifacts", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 Bad Request on operator mismatch, got %d. Body: %s", rec.Code, rec.Body.String())
	}
}

func TestIngestHandler_SVNFloorRejection(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "ingest_test_*")
	defer os.RemoveAll(tempDir)

	wStore, _ := store.NewLocalWORMStore(tempDir)
	tx := &mockTx{
		floors:    map[string]uint32{"toob-lamp-01:0": 20}, // Existing floor = 20
		artifacts: make(map[string]*ingest.ArtifactRecord),
		releases:  make(map[string]*ingest.ReleaseRecord),
	}
	db := &mockDB{activeTx: tx}
	svc := ingest.NewIngestService(db, wStore, &mockFleet{})
	handler := ingest.NewHandler(svc)

	blob, _ := makeTestSignedBlob(t, 10, 100) // Header has SVN=10 < floor 20

	payload := map[string]any{
		"product": "toob-lamp-01",
		"kind":    "full",
		"blob":    blob,
	}
	bodyBytes, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/v1/internal/artifacts", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected HTTP 409 Conflict on lower SVN, got %d. Body: %s", rec.Code, rec.Body.String())
	}
}

func TestSetReleaseHandler_AtomicSwitch(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "ingest_test_*")
	defer os.RemoveAll(tempDir)

	wStore, _ := store.NewLocalWORMStore(tempDir)
	tx := &mockTx{
		floors: make(map[string]uint32),
		artifacts: map[string]*ingest.ArtifactRecord{
			"art-1": {ID: "art-1", Product: "toob-lamp-01"},
			"art-2": {ID: "art-2", Product: "toob-lamp-01"},
		},
		releases: make(map[string]*ingest.ReleaseRecord),
	}
	db := &mockDB{activeTx: tx}
	svc := ingest.NewIngestService(db, wStore, &mockFleet{})
	handler := ingest.NewHandler(svc)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// 1. Set release to art-1
	body1, _ := json.Marshal(map[string]string{
		"product":     "toob-lamp-01",
		"channel":     "stable",
		"artifact_id": "art-1",
	})
	req1 := httptest.NewRequest(http.MethodPost, "/v1/internal/releases", bytes.NewReader(body1))
	rec1 := httptest.NewRecorder()
	mux.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("set release 1 failed: %d. Body: %s", rec1.Code, rec1.Body.String())
	}

	var rel1 ingest.ReleaseRecord
	_ = json.Unmarshal(rec1.Body.Bytes(), &rel1)
	if !rel1.Active || rel1.ArtifactID != "art-1" {
		t.Errorf("unexpected release 1: %+v", rel1)
	}

	// 2. Set release to art-2 (atomic switch)
	body2, _ := json.Marshal(map[string]string{
		"product":     "toob-lamp-01",
		"channel":     "stable",
		"artifact_id": "art-2",
	})
	req2 := httptest.NewRequest(http.MethodPost, "/v1/internal/releases", bytes.NewReader(body2))
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("set release 2 failed: %d. Body: %s", rec2.Code, rec2.Body.String())
	}

	var rel2 ingest.ReleaseRecord
	_ = json.Unmarshal(rec2.Body.Bytes(), &rel2)
	if !rel2.Active || rel2.ArtifactID != "art-2" {
		t.Errorf("unexpected release 2: %+v", rel2)
	}

	// Verify old release key "toob-lamp-01:stable" was switched to art-2
	if tx.releases["toob-lamp-01:stable"].ArtifactID != "art-2" {
		t.Errorf("expected active release to be art-2")
	}
}
