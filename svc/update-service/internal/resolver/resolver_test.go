package resolver_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/toob-boot/update-service/internal/resolver"
)

func makeTestDevice() resolver.Device {
	devID, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	return resolver.Device{
		ID:              devID,
		Product:         "toob-lamp-01",
		VendorID:        0x1234,
		ProductID:       0x0042,
		ProductHWRev:    2,
		StagingCapacity: 1024 * 1024, // 1 MiB
		ReaderMajor:     2,
		ReaderMinor:     0,
		Channel:         "stable",
		Health:          "ok",
	}
}

func makeTestObserved() resolver.ObservedState {
	return resolver.ObservedState{
		ReportedSVN:     10,
		ReportedBuild:   100,
		BootedPartition: 0, // SlotApp
	}
}

func makeCandidateArtifact(id string, buildNum uint32, svnVal uint32) resolver.Artifact {
	return resolver.Artifact{
		ID:             id,
		Product:        "toob-lamp-01",
		BuildNumber:    buildNum,
		Kind:           "full",
		SizeBytes:      512 * 1024, // 512 KiB
		SVN:            svnVal,
		Stage1SVN:      0,
		KeyIndex:       0,
		HWRevMin:       1,
		HWRevMax:       5,
		MinReaderMajor: 2,
		MinReaderMinor: 0,
		TargetSlot:     0, // SlotApp
	}
}

func TestResolve_DeterminismInvariant(t *testing.T) {
	dev := makeTestDevice()
	obs := makeTestObserved()
	candidates := []resolver.Artifact{
		makeCandidateArtifact("art-101", 101, 11),
	}
	opts := resolver.Options{RampBPS: 5000} // 50% ramp

	// Run 1000 times, assert 100% identical outputs
	firstArt, firstReason, firstErr := resolver.Resolve(dev, obs, candidates, opts)
	for i := 0; i < 1000; i++ {
		art, reason, err := resolver.Resolve(dev, obs, candidates, opts)
		if err != firstErr {
			t.Fatalf("iteration %d: expected err %v, got %v", i, firstErr, err)
		}
		if reason != firstReason {
			t.Fatalf("iteration %d: expected reason %s, got %s", i, firstReason, reason)
		}
		if (art == nil) != (firstArt == nil) {
			t.Fatalf("iteration %d: artifact nil mismatch", i)
		}
		if art != nil && art.ID != firstArt.ID {
			t.Fatalf("iteration %d: expected art ID %s, got %s", i, firstArt.ID, art.ID)
		}
	}
}

func TestResolve_QuarantinedHealthCheck(t *testing.T) {
	dev := makeTestDevice()
	dev.Health = "quarantined"
	obs := makeTestObserved()
	candidates := []resolver.Artifact{makeCandidateArtifact("art-101", 101, 11)}

	art, reason, err := resolver.Resolve(dev, obs, candidates, resolver.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if art != nil {
		t.Errorf("quarantined device should receive nil artifact, got: %+v", art)
	}
	if reason != resolver.ReasonDeviceQuarantined {
		t.Errorf("expected ReasonDeviceQuarantined, got %s", reason)
	}
}

func TestResolve_PinningVictory(t *testing.T) {
	dev := makeTestDevice()
	obs := makeTestObserved()
	candidates := []resolver.Artifact{
		makeCandidateArtifact("art-101", 101, 11),
		makeCandidateArtifact("art-pinned", 105, 12),
	}

	opts := resolver.Options{PinnedArtifactID: "art-pinned"}
	art, reason, err := resolver.Resolve(dev, obs, candidates, opts)
	if err != nil || art == nil {
		t.Fatalf("expected pinned resolution success, got art: %v, err: %v", art, err)
	}

	if art.ID != "art-pinned" {
		t.Errorf("expected pinned artifact art-pinned, got %s", art.ID)
	}
	if reason != resolver.ReasonResolved {
		t.Errorf("expected ReasonResolved, got %s", reason)
	}
}

func TestResolve_IncompatibleHWRevision(t *testing.T) {
	dev := makeTestDevice()
	dev.ProductHWRev = 10 // Device is rev 10
	obs := makeTestObserved()

	cand := makeCandidateArtifact("art-101", 101, 11)
	cand.HWRevMin = 1
	cand.HWRevMax = 5 // Artifact only supports revs 1..5

	art, reason, err := resolver.Resolve(dev, obs, []resolver.Artifact{cand}, resolver.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if art != nil {
		t.Errorf("expected nil artifact for incompatible HW rev, got %+v", art)
	}
	if reason != resolver.ReasonIncompatibleHW {
		t.Errorf("expected ReasonIncompatibleHW, got %s", reason)
	}
}

func TestResolve_IncompatibleStagingCapacity(t *testing.T) {
	dev := makeTestDevice()
	dev.StagingCapacity = 256 * 1024 // 256 KiB
	obs := makeTestObserved()

	cand := makeCandidateArtifact("art-101", 101, 11)
	cand.SizeBytes = 512 * 1024 // 512 KiB (exceeds staging capacity)

	art, reason, err := resolver.Resolve(dev, obs, []resolver.Artifact{cand}, resolver.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if art != nil {
		t.Errorf("expected nil artifact for oversized staging, got %+v", art)
	}
	if reason != resolver.ReasonIncompatibleStaging {
		t.Errorf("expected ReasonIncompatibleStaging, got %s", reason)
	}
}

func TestResolve_IncompatibleBootloaderReaderVersion(t *testing.T) {
	dev := makeTestDevice()
	dev.ReaderMajor = 1 // Device has reader 1.5
	dev.ReaderMinor = 5
	obs := makeTestObserved()

	cand := makeCandidateArtifact("art-101", 101, 11)
	cand.MinReaderMajor = 2 // Artifact requires min reader 2.0
	cand.MinReaderMinor = 0

	art, reason, err := resolver.Resolve(dev, obs, []resolver.Artifact{cand}, resolver.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if art != nil {
		t.Errorf("expected nil artifact for outdated reader, got %+v", art)
	}
	if reason != resolver.ReasonIncompatibleReader {
		t.Errorf("expected ReasonIncompatibleReader, got %s", reason)
	}
}

func TestResolve_RollbackProhibited(t *testing.T) {
	dev := makeTestDevice()
	obs := makeTestObserved()
	obs.ReportedSVN = 20 // Device has SVN 20 installed

	cand := makeCandidateArtifact("art-101", 101, 15) // Candidate has lower SVN 15

	art, reason, err := resolver.Resolve(dev, obs, []resolver.Artifact{cand}, resolver.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if art != nil {
		t.Errorf("expected rollback rejection for lower SVN, got %+v", art)
	}
	if reason != resolver.ReasonRollbackProhibited {
		t.Errorf("expected ReasonRollbackProhibited, got %s", reason)
	}
}

func TestResolve_AlreadyUpToDate(t *testing.T) {
	dev := makeTestDevice()
	obs := makeTestObserved()
	obs.ReportedBuild = 100
	obs.ReportedSVN = 10

	cand := makeCandidateArtifact("art-100", 100, 10) // Same build and SVN

	art, reason, err := resolver.Resolve(dev, obs, []resolver.Artifact{cand}, resolver.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if art != nil {
		t.Errorf("expected nil artifact for already up-to-date, got %+v", art)
	}
	if reason != resolver.ReasonAlreadyUpToDate {
		t.Errorf("expected ReasonAlreadyUpToDate, got %s", reason)
	}
}

func TestResolve_DeltaPreference(t *testing.T) {
	dev := makeTestDevice()
	obs := makeTestObserved()
	obs.ReportedBuild = 100

	baseBuild100 := int32(100)
	fullArt := makeCandidateArtifact("art-full", 101, 11)

	deltaArt := makeCandidateArtifact("art-delta", 101, 11)
	deltaArt.Kind = "delta"
	deltaArt.BaseBuild = &baseBuild100

	candidates := []resolver.Artifact{fullArt, deltaArt}

	art, reason, err := resolver.Resolve(dev, obs, candidates, resolver.Options{})
	if err != nil || art == nil {
		t.Fatalf("expected resolution success, got art: %v, err: %v", art, err)
	}

	if art.ID != "art-delta" {
		t.Errorf("expected Delta artifact art-delta to be preferred, got %s", art.ID)
	}
	if reason != resolver.ReasonResolved {
		t.Errorf("expected ReasonResolved, got %s", reason)
	}
}

func TestResolve_PropertyAdmissibilityInvariant(t *testing.T) {
	// Property test: Generate 100 random devices and candidates.
	// For every resolution that returns an artifact, verify that it passes all admissibility criteria.
	for i := 0; i < 100; i++ {
		devID := sha256.Sum256([]byte(fmt.Sprintf("device-%d", i)))
		dev := resolver.Device{
			ID:              devID[:],
			Product:         "toob-lamp-01",
			VendorID:        0x1234,
			ProductID:       0x0042,
			ProductHWRev:    uint16((i % 5) + 1),
			StagingCapacity: uint32((i%4 + 1) * 256 * 1024),
			ReaderMajor:     2,
			ReaderMinor:     uint16(i % 3),
			Channel:         "stable",
			Health:          "ok",
		}

		obs := resolver.ObservedState{
			ReportedSVN:     uint32(i % 10),
			ReportedBuild:   uint32(i * 10),
			BootedPartition: 0,
		}

		cand := makeCandidateArtifact(fmt.Sprintf("art-%d", i), uint32(i*10+5), uint32(i%10+1))

		art, reason, err := resolver.Resolve(dev, obs, []resolver.Artifact{cand}, resolver.Options{})
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}

		if art != nil {
			if reason != resolver.ReasonResolved {
				t.Errorf("iteration %d: resolved artifact must return ReasonResolved, got %s", i, reason)
			}
			if dev.ProductHWRev < art.HWRevMin || dev.ProductHWRev > art.HWRevMax {
				t.Errorf("iteration %d: resolved artifact violated HWRev bounds!", i)
			}
			if art.SizeBytes > dev.StagingCapacity {
				t.Errorf("iteration %d: resolved artifact violated staging capacity!", i)
			}
			if art.SVN < obs.ReportedSVN {
				t.Errorf("iteration %d: resolved artifact violated anti-rollback SVN!", i)
			}
		}
	}
}
