package archiveutil_test

import (
	"bytes"
	"errors"
	"io"
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

// TestSafeJoin_AcceptsLegitimateNames guards the other direction. The check this replaced rejected
// any relative path beginning with two dots, so a file called "..config" — which is inside the
// destination — could not be extracted.
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

// TestSafeLinkTarget_RejectsEscapingLinks is the check the extractor did not have. A lexical path
// test cannot see through a symlink: "evil -> /etc" followed by "evil/passwd" passes it twice and
// still writes outside the destination, because the operating system resolves the link.
func TestSafeLinkTarget_RejectsEscapingLinks(t *testing.T) {
	dest := filepath.Join(string(filepath.Separator), "tmp", "toolchain")
	linkPath := filepath.Join(dest, "bin", "evil")

	for _, linkname := range []string{
		"/etc",
		"/etc/passwd",
		"../../../../etc",
		"../../..",
		"",
	} {
		t.Run(linkname, func(t *testing.T) {
			if err := archiveutil.SafeLinkTarget(dest, linkPath, linkname); err == nil {
				t.Fatalf("a link pointing at %q was accepted", linkname)
			}
		})
	}
}

func TestSafeLinkTarget_AcceptsLinksInsideTheTree(t *testing.T) {
	dest := filepath.Join(string(filepath.Separator), "tmp", "toolchain")
	linkPath := filepath.Join(dest, "bin", "gcc")

	// The relative targets a real toolchain uses: a sibling and a path back up into the tree.
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

func TestBudget_CountsAcrossEntries(t *testing.T) {
	budget := archiveutil.NewBudget(100)

	for i := 0; i < 10; i++ {
		if _, err := budget.Copy(io.Discard, bytes.NewReader(make([]byte, 10))); err != nil {
			t.Fatalf("entry %d failed within the budget: %v", i, err)
		}
	}

	if _, err := budget.Copy(io.Discard, bytes.NewReader([]byte{0})); !errors.Is(err, archiveutil.ErrTooLarge) {
		t.Fatalf("the budget must span the whole extraction, got %v", err)
	}
}

func TestEntryMode_DropsDangerousBits(t *testing.T) {
	// 04755: setuid plus rwxr-xr-x. Only the permission bits survive, and group/other lose write.
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
