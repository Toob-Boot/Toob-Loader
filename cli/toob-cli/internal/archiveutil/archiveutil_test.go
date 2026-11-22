package archiveutil_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/toob-boot/toob/internal/archiveutil"
)

func TestSafeJoin_RejectsEscapes(t *testing.T) {
	dest := filepath.Join(string(filepath.Separator), "tmp", "toolchain")

	escapes := []string{
		"../evil",
		"../../etc/passwd",
		"a/../../evil",
		"./../../evil",
		"",
		"   ",
		"/etc/passwd",
		"foo\x00bar",
		"sub/file.c:evil",
		"file.txt:$DATA",
		"C:relative",
	}
	if runtime.GOOS == "windows" {
		escapes = append(escapes, `C:\Windows\System32\evil.dll`, `\\server\share\evil`, `..\..\evil`)
	}

	for _, name := range escapes {
		t.Run(strings.ReplaceAll(name, string(filepath.Separator), "_"), func(t *testing.T) {
			if got, err := archiveutil.SafeJoin(dest, name); err == nil {
				t.Fatalf("entry %q was accepted and would be written to %q", name, got)
			}
		})
	}
}

func TestSafeJoin_AcceptsLegitimateNames(t *testing.T) {
	dest := filepath.Join(string(filepath.Separator), "tmp", "toolchain")

	for _, name := range []string{
		"bin/gcc",
		"..config",
		"..",
		"lib/../lib/libc.so",
		"a/b/c/d.txt",
	} {
		t.Run(name, func(t *testing.T) {
			target, err := archiveutil.SafeJoin(dest, name)
			if name == ".." {
				if err == nil {
					t.Fatalf("%q resolves to the parent and must be rejected", name)
				}
				return
			}
			if err != nil {
				t.Fatalf("legitimate entry %q was rejected: %v", name, err)
			}
			if !strings.HasPrefix(target, filepath.Clean(dest)) {
				t.Fatalf("%q resolved outside the destination: %q", name, target)
			}
		})
	}
}

func TestSafeLinkTarget_RejectsEscapingLinks(t *testing.T) {
	dest := filepath.Join(string(filepath.Separator), "tmp", "toolchain")
	linkPath := filepath.Join(dest, "bin", "evil")

	for _, linkname := range []string{
		"/etc",
		"/etc/passwd",
		"../../../../etc",
		"../../..",
		"",
		"sub/file:ads",
		"C:/Windows/System32",
	} {
		t.Run(linkname, func(t *testing.T) {
			if err := archiveutil.SafeLinkTarget(dest, linkPath, linkname); err == nil {
				t.Fatalf("a link pointing at %q was accepted", linkname)
			}
		})
	}
}

func TestSafeLinkTarget_RejectsMultiHopSymlinkChain(t *testing.T) {
	dest := t.TempDir()
	links := make(map[string]string)

	// Entry 1: d1/d2/d3/d4/d5/d6/up -> ../../../../../.. (points to dest itself)
	relUp := filepath.Join("d1", "d2", "d3", "d4", "d5", "d6", "up")
	if err := archiveutil.RecordAndValidateSymlink(dest, relUp, "../../../../../..", links); err != nil {
		t.Fatalf("valid intra-tree link rejected: %v", err)
	}

	// Entry 2: d1/escape -> d2/d3/d4/d5/d6/up/../../../../../../victim
	// Lexically collapses 6 segments against 6 '..', but through 'up' escapes 6 levels above dest.
	relEscape := filepath.Join("d1", "escape")
	err := archiveutil.RecordAndValidateSymlink(dest, relEscape, "d2/d3/d4/d5/d6/up/../../../../../../victim", links)
	if !errors.Is(err, archiveutil.ErrUnsafePath) {
		t.Fatalf("expected ErrUnsafePath on 2-hop symlink chain escape, got %v", err)
	}

	// Reversed order: forward-referenced 'd1/escape' recorded before 'd1..d6/up' is defined.
	revLinks := make(map[string]string)
	if recErr := archiveutil.RecordAndValidateSymlink(dest, relEscape, "d2/d3/d4/d5/d6/up/../../../../../../victim", revLinks); recErr != nil {
		t.Fatalf("forward symlink before 'up' exists failed unexpectedly: %v", recErr)
	}
	err = archiveutil.RecordAndValidateSymlink(dest, relUp, "../../../../../..", revLinks)
	if !errors.Is(err, archiveutil.ErrUnsafePath) {
		t.Fatalf("expected ErrUnsafePath when 'up' completes forward-referenced escape chain, got %v", err)
	}
}

func TestSafeLinkTarget_RejectsSymlinkCycle(t *testing.T) {
	dest := t.TempDir()
	links := make(map[string]string)
	if err := archiveutil.RecordAndValidateSymlink(dest, "a", "b", links); err != nil {
		t.Fatalf("first link rejected: %v", err)
	}
	if err := archiveutil.RecordAndValidateSymlink(dest, "b", "a", links); !errors.Is(err, archiveutil.ErrUnsafePath) {
		t.Fatalf("expected ErrUnsafePath on symlink cycle, got %v", err)
	}
}

func TestSafeLinkTarget_OnDiskSymlinkChain(t *testing.T) {
	dest := t.TempDir()
	upDir := filepath.Join(dest, "d1", "d2")
	if err := os.MkdirAll(upDir, 0o755); err != nil {
		t.Fatal(err)
	}
	upLink := filepath.Join(upDir, "up")
	if err := os.Symlink("../..", upLink); err != nil {
		t.Skipf("os.Symlink unavailable: %v", err)
	}
	escapeLink := filepath.Join(dest, "d1", "escape")
	err := archiveutil.SafeLinkTarget(dest, escapeLink, "d2/up/../../victim")
	if !errors.Is(err, archiveutil.ErrUnsafePath) {
		t.Fatalf("expected ErrUnsafePath against on-disk symlink chain, got %v", err)
	}
}

func TestSafeLinkTarget_AcceptsLinksInsideTheTree(t *testing.T) {
	dest := filepath.Join(string(filepath.Separator), "tmp", "toolchain")
	linkPath := filepath.Join(dest, "bin", "gcc")

	for _, linkname := range []string{"gcc-13", "../libexec/gcc/real-gcc", "./gcc-13"} {
		t.Run(linkname, func(t *testing.T) {
			if err := archiveutil.SafeLinkTarget(dest, linkPath, linkname); err != nil {
				t.Fatalf("a legitimate link to %q was rejected: %v", linkname, err)
			}
		})
	}
}

func TestBudget_StopsADecompressionBomb(t *testing.T) {
	budget := archiveutil.NewBudget(1024)

	if _, err := budget.Copy(io.Discard, bytes.NewReader(make([]byte, 512))); err != nil {
		t.Fatalf("a write within the budget failed: %v", err)
	}

	_, err := budget.Copy(io.Discard, bytes.NewReader(make([]byte, 1024)))
	if !errors.Is(err, archiveutil.ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge once the budget is exhausted, got %v", err)
	}
}

func TestBudget_CountsAcrossEntriesAndCapsEntryCount(t *testing.T) {
	budget := archiveutil.NewBudgetWithEntries(100, 10)

	for i := range 10 {
		if err := budget.TakeEntry(); err != nil {
			t.Fatalf("entry %d failed within maxEntries: %v", i, err)
		}
		if _, err := budget.Copy(io.Discard, bytes.NewReader(make([]byte, 10))); err != nil {
			t.Fatalf("entry %d failed within byte budget: %v", i, err)
		}
	}

	if err := budget.TakeEntry(); !errors.Is(err, archiveutil.ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge once maxEntries is exceeded, got %v", err)
	}
}

func TestEntryMode_DropsDangerousBits(t *testing.T) {
	got := archiveutil.EntryMode(0o4757)

	if got&0o4000 != 0 {
		t.Errorf("setuid survived: %04o", got)
	}
	if got&0o022 != 0 {
		t.Errorf("group or other write survived: %04o", got)
	}
	if got&0o100 == 0 {
		t.Errorf("the owner execute bit must survive so binaries stay runnable: %04o", got)
	}
}

func TestSafeJoin_RejectsWindowsReservedNamesAndTrailingDotsSpaces(t *testing.T) {
	dest := t.TempDir()
	bad := []string{
		"CON",
		"con.txt",
		"sub/PRN.c",
		"AUX",
		"nul.h",
		"COM0",
		"COM1.log",
		"lpt9.bin",
		"CONIN$",
		"CONOUT$",
		"dir./file.txt",
		"dir /file.txt",
		"trailing.",
		"trailing ",
	}
	for _, entry := range bad {
		if _, _, err := archiveutil.SafeRelPath(dest, entry); !errors.Is(err, archiveutil.ErrUnsafePath) {
			t.Errorf("SafeRelPath(%q) = %v; want ErrUnsafePath", entry, err)
		}
		if err := archiveutil.ValidateLinkSyntax(filepath.Join(dest, "link"), entry); !errors.Is(err, archiveutil.ErrUnsafePath) {
			t.Errorf("ValidateLinkSyntax(%q) = %v; want ErrUnsafePath", entry, err)
		}
	}
}

func TestPathTracker_RejectsCaseCollidingEntries(t *testing.T) {
	pt := archiveutil.NewPathTracker()
	if err := pt.Record("Include/driver.h"); err != nil {
		t.Fatalf("first Record failed: %v", err)
	}
	if err := pt.Record("Include/other.h"); err != nil {
		t.Fatalf("same-case directory Record failed: %v", err)
	}
	if err := pt.Record("include/evil.h"); !errors.Is(err, archiveutil.ErrUnsafePath) {
		t.Fatalf("expected ErrUnsafePath on directory case collision, got %v", err)
	}
	if err := pt.Record("Include/DRIVER.H"); !errors.Is(err, archiveutil.ErrUnsafePath) {
		t.Fatalf("expected ErrUnsafePath on file case collision, got %v", err)
	}
}

func TestValidateSymlinkGraph_CaseInsensitiveEscapeAndLinearScaling(t *testing.T) {
	dest := t.TempDir()

	// Mixed-case two-hop escape: "sym" -> "D1/A/.." where "d1/a" -> ".." escapes above dest on NTFS/APFS.
	escapeGraph := map[string]string{
		"d1/a": "../..",
		"sym":  "D1/A/..",
	}
	if err := archiveutil.ValidateSymlinkGraph(dest, escapeGraph); !errors.Is(err, archiveutil.ErrUnsafePath) {
		t.Fatalf("expected ErrUnsafePath on case-insensitive symlink escape, got %v", err)
	}

	// ResolveArchiveRelPath must also block writing a file through a parent symlink chain that escapes.
	if _, err := archiveutil.ResolveArchiveRelPath(dest, "sym/pwned.txt", escapeGraph); !errors.Is(err, archiveutil.ErrUnsafePath) {
		t.Fatalf("expected ResolveArchiveRelPath to reject escaping parent symlink, got %v", err)
	}

	// Linear O(S) memoized graph verification across 4,000 sysroot symlinks.
	largeGraph := make(map[string]string, 4000)
	largeGraph["lib/libc.so.6"] = "libc-2.39.so"
	for i := range 3999 {
		key := "usr/lib/alias_" + strings.Repeat("x", i%7) + "_" + string(rune('a'+(i%26))) + "_" + strconvItoa(i)
		largeGraph[key] = "../../lib/libc.so.6"
	}
	if err := archiveutil.ValidateSymlinkGraph(dest, largeGraph); err != nil {
		t.Fatalf("ValidateSymlinkGraph failed on 4,000 valid sysroot symlinks: %v", err)
	}
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [20]byte
	pos := len(digits)
	for n > 0 {
		pos--
		digits[pos] = byte('0' + (n % 10))
		n /= 10
	}
	return string(digits[pos:])
}

func TestDrainStreamTrailer(t *testing.T) {
	if err := archiveutil.DrainStreamTrailer(bytes.NewReader([]byte{0, 0, 0, 0}), 8); err != nil {
		t.Fatalf("expected trailing bytes within limit to succeed, got %v", err)
	}
	if err := archiveutil.DrainStreamTrailer(bytes.NewReader(make([]byte, 17)), 16); !errors.Is(err, archiveutil.ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge when trailer exceeds maxPad, got %v", err)
	}
}
