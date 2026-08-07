package tbm1

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestBuildIsDeterministic(t *testing.T) {
	a := mustBuild(t, &Encoder{}, sampleManifest())
	b := mustBuild(t, &Encoder{}, sampleManifest())
	if !bytes.Equal(a.Block, b.Block) {
		t.Fatal("two builds of the same manifest differ — golden vectors would drift")
	}
	if a.SignedLen != a.TotalLen-SigLen {
		t.Fatalf("signed_len %d != total_len %d - %d", a.SignedLen, a.TotalLen, SigLen)
	}
}

// TestParallelismDoesNotChangeOutput is the guard on the dynamic scheduler: the
// number of workers must never be observable in the output.
func TestParallelismDoesNotChangeOutput(t *testing.T) {
	ref := mustBuild(t, &Encoder{Parallelism: 1}, sampleManifest()).Block
	for _, p := range []int{2, 3, 8, 64} {
		got := mustBuild(t, &Encoder{Parallelism: p}, sampleManifest()).Block
		if !bytes.Equal(got, ref) {
			t.Fatalf("Parallelism=%d produced a different block", p)
		}
	}
}

// TestStreamedAndInMemoryAgree is the guard on the io.ReaderAt path.
func TestStreamedAndInMemoryAgree(t *testing.T) {
	ref := mustBuild(t, &Encoder{}, sampleManifest()).Block

	streamed := sampleManifest()
	for i := range streamed.Images {
		im := &streamed.Images[i]
		installed := im.Installed
		im.Installed = nil
		im.InstalledAt = bytes.NewReader(installed)
		im.InstalledSize = uint32(len(installed))
		// The staged payload never has to be in memory either.
		if im.Stored != nil {
			im.StoredSize = uint32(len(im.Stored))
			im.Stored = nil
		}
	}
	for _, p := range []int{1, 4} {
		got := mustBuild(t, &Encoder{Parallelism: p}, streamed).Block
		if !bytes.Equal(got, ref) {
			t.Fatalf("streamed build (Parallelism=%d) differs from the in-memory build", p)
		}
	}
}

// chunkHashRegion locates region 1 inside a block.
func chunkHashRegion(t *testing.T, b []byte) []byte {
	t.Helper()
	le := binary.LittleEndian
	for i := 0; i < MaxRegions; i++ {
		base := offRegions + i*regionStride
		if le.Uint16(b[base:]) == RegionChunkHashes {
			off, ln := le.Uint32(b[base+4:]), le.Uint32(b[base+8:])
			return b[off : off+ln]
		}
	}
	t.Fatal("block carries no chunk-hash region")
	return nil
}

func TestDigestsMatchIndependentComputation(t *testing.T) {
	m := sampleManifest()
	pkg := mustBuild(t, &Encoder{}, m)

	var want []byte
	for _, im := range m.Images {
		cs := int(im.ChunkSize)
		if cs == 0 {
			cs = DefaultChunkSize
		}
		for off := 0; off < len(im.Installed); off += cs {
			end := off + cs
			if end > len(im.Installed) {
				end = len(im.Installed)
			}
			d := sha256.Sum256(im.Installed[off:end])
			want = append(want, d[:]...)
		}
	}
	if got := chunkHashRegion(t, pkg.Block); !bytes.Equal(got, want) {
		t.Fatalf("chunk-hash region mismatch: %d bytes vs %d expected", len(got), len(want))
	}

	// AutoSBOM must be SHA-256 over the whole first installed image.
	h, err := ParseHeader(pkg.Block)
	if err != nil {
		t.Fatal(err)
	}
	if wantSBOM := sha256.Sum256(m.Images[0].Installed); h.SBOMDigest != wantSBOM {
		t.Fatal("AutoSBOM digest mismatch")
	}
}

func TestManifestRejections(t *testing.T) {
	cases := map[string]func(m *Manifest){
		"no images":       func(m *Manifest) { m.Images = nil },
		"duplicate slot":  func(m *Manifest) { m.Images[1].TargetSlot = m.Images[0].TargetSlot },
		"partial pqc":     func(m *Manifest) { m.PQCSig = []byte{1, 2, 3} },
		"empty hw range":  func(m *Manifest) { m.HWRevMin, m.HWRevMax = 9, 2 },
		"tiny chunk":      func(m *Manifest) { m.Images[0].ChunkSize = 16 },
		"odd sector":      func(m *Manifest) { m.SectorSize = 3000 },
		"future reader":   func(m *Manifest) { m.MinReaderMajor = VersionMajor + 1 },
		"short bind":      func(m *Manifest) { m.DeviceBind = []byte{1} },
		"empty image":     func(m *Manifest) { m.Images[0].Installed = []byte{} },
		"bad fingerprint": func(m *Manifest) { m.Images[0].BaseFingerprint = []byte{1, 2} },
		"no source":       func(m *Manifest) { m.Images[0].Installed = nil },
		"two sources": func(m *Manifest) {
			m.Images[0].InstalledAt = bytes.NewReader(appImage)
			m.Images[0].InstalledSize = uint32(len(appImage))
		},
		"size disagreement": func(m *Manifest) { m.Images[0].InstalledSize = 1 },
		"stored disagreement": func(m *Manifest) {
			m.Images[1].StoredSize = uint32(len(m.Images[1].Stored)) + 1
		},
	}
	for name, mutate := range cases {
		m := sampleManifest()
		mutate(&m)
		if _, err := BuildUnsigned(m); err == nil {
			t.Fatalf("%s: expected rejection", name)
		}
	}
}

func TestFlatLayout(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := NewLocalSigner(priv)
	m := sampleManifest()
	pkg, err := Build(m, signer)
	if err != nil {
		t.Fatal(err)
	}

	blobs := [][]byte{m.Images[0].Installed, m.Images[1].Stored}
	flat, err := pkg.AssembleFlat(blobs)
	if err != nil {
		t.Fatalf("AssembleFlat: %v", err)
	}
	for i, blob := range blobs {
		off := pkg.DataOff[i]
		if off%pkg.SectorSize != 0 {
			t.Fatalf("image %d data_off %d is not sector-aligned", i, off)
		}
		if !bytes.Equal(flat[off:off+uint32(len(blob))], blob) {
			t.Fatalf("image %d payload misplaced", i)
		}
	}

	// All three output paths must agree byte for byte.
	var buf bytes.Buffer
	if _, err := pkg.WriteFlat(&buf, blobs); err != nil {
		t.Fatalf("WriteFlat: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), flat) {
		t.Fatal("WriteFlat and AssembleFlat disagree")
	}

	buf.Reset()
	readers := []io.Reader{bytes.NewReader(blobs[0]), bytes.NewReader(blobs[1])}
	if _, err := pkg.StreamFlat(&buf, readers); err != nil {
		t.Fatalf("StreamFlat: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), flat) {
		t.Fatal("StreamFlat and AssembleFlat disagree")
	}

	// Payloads that contradict the signed header must be refused.
	if _, err := pkg.AssembleFlat([][]byte{blobs[0], append(blobs[1], 0)}); err == nil {
		t.Fatal("mismatched payload size accepted")
	}
	buf.Reset()
	short := []io.Reader{bytes.NewReader(blobs[0]), bytes.NewReader(blobs[1][:10])}
	if _, err := pkg.StreamFlat(&buf, short); err == nil {
		t.Fatal("short payload stream accepted")
	}
}

func TestUnsignedPackageCannotBeAssembled(t *testing.T) {
	pkg := mustBuild(t, &Encoder{}, sampleManifest())
	if _, err := pkg.AssembleFlat([][]byte{appImage, netStored}); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("expected ErrUnsigned, got %v", err)
	}
}

func TestStripeSizing(t *testing.T) {
	cases := []struct{ chunkSize, numChunks uint32 }{
		{MinChunkSize, 1 << 16}, {1024, 4096}, {4096, 8192}, {65536, 512}, {MaxChunkSize, 4},
	}
	for _, c := range cases {
		for _, workers := range []int{2, 8, 64} {
			p := &imagePlan{chunkSize: c.chunkSize, numChunks: c.numChunks}
			s := stripeChunks(p, workers)
			if s < 1 {
				t.Fatalf("chunk=%d n=%d w=%d: stripe %d", c.chunkSize, c.numChunks, workers, s)
			}
			if s >= digestsPerLine && s%digestsPerLine != 0 {
				t.Fatalf("chunk=%d n=%d w=%d: stripe %d straddles a cache line",
					c.chunkSize, c.numChunks, workers, s)
			}
			// Every worker must be able to claim at least one hand-out.
			if stripes := (uint64(c.numChunks) + s - 1) / s; stripes < uint64(workers) &&
				uint64(c.numChunks) >= uint64(workers) {
				t.Fatalf("chunk=%d n=%d w=%d: only %d stripes, workers would idle",
					c.chunkSize, c.numChunks, workers, stripes)
			}
		}
	}
}

func BenchmarkBuild(b *testing.B) {
	for _, p := range []int{1, 0} { // 0 = GOMAXPROCS
		name := "parallel"
		if p == 1 {
			name = "sequential"
		}
		b.Run(name, func(b *testing.B) {
			e := &Encoder{Parallelism: p}
			m := sampleManifest()
			b.SetBytes(int64(len(appImage) + len(netImage)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := e.BuildUnsigned(m); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
