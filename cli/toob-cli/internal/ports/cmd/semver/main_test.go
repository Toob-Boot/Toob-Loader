package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempPorts(t *testing.T, dir, name, src string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestSemver_MissingOrEmptyFails(t *testing.T) {
	dir := t.TempDir()
	valid := writeTempPorts(t, dir, "valid.go", `package ports
const ProtocolVersion = 1
type Foo struct {
	ID string `+"`json:\"id\" port:\"required\"`"+`
}
`)
	empty := writeTempPorts(t, dir, "empty.go", "   \n")
	missing := filepath.Join(dir, "does_not_exist.go")

	tests := []struct {
		name string
		args []string
	}{
		{"missing new file", []string{valid, missing}},
		{"empty new file", []string{valid, empty}},
		{"missing old file without --initial", []string{missing, valid}},
		{"empty old file without --initial", []string{empty, valid}},
		{"missing new file even with --initial", []string{"--initial", missing, missing}},
		{"empty new file even with --initial", []string{"--initial", missing, empty}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var outBuf, errBuf bytes.Buffer
			code := run(tc.args, &outBuf, &errBuf)
			if code == 0 {
				t.Fatalf("expected non-zero exit code for %s, got 0 (stdout=%q stderr=%q)",
					tc.name, outBuf.String(), errBuf.String())
			}
		})
	}

	t.Run("--initial allows missing old file when new file is valid", func(t *testing.T) {
		var outBuf, errBuf bytes.Buffer
		code := run([]string{"--initial", missing, valid}, &outBuf, &errBuf)
		if code != 0 {
			t.Fatalf("expected 0 exit code, got %d: %s", code, errBuf.String())
		}
		if strings.TrimSpace(outBuf.String()) != "MINOR" {
			t.Fatalf("expected MINOR for initial contract, got %q", outBuf.String())
		}
	})
}

func TestSemver_BreakingClassifications(t *testing.T) {
	base := `package ports
const ProtocolVersion = 1
type Sample struct {
	A, B string ` + "`json:\"ab\" toml:\"ab\" port:\"required\"`" + `
	Opt  string ` + "`json:\"opt,omitempty\" port:\"optional\"`" + `
	Nested []struct {
		ID string ` + "`json:\"id\" port:\"required\"`" + `
	} ` + "`json:\"nested\" port:\"required\"`" + `
}
`

	tests := []struct {
		name       string
		newSrc     string
		wantBump   string
		wantExit   int
		wantErrSub string
	}{
		{
			name:     "no changes is PATCH",
			newSrc:   base,
			wantBump: "PATCH",
			wantExit: 0,
		},
		{
			name: "remove optional field is MAJOR",
			newSrc: `package ports
const ProtocolVersion = 2
type Sample struct {
	A, B string ` + "`json:\"ab\" toml:\"ab\" port:\"required\"`" + `
	Nested []struct {
		ID string ` + "`json:\"id\" port:\"required\"`" + `
	} ` + "`json:\"nested\" port:\"required\"`" + `
}
`,
			wantBump: "MAJOR",
			wantExit: 0,
		},
		{
			name: "required to optional relaxation is MAJOR",
			newSrc: `package ports
const ProtocolVersion = 2
type Sample struct {
	A, B string ` + "`json:\"ab\" toml:\"ab\" port:\"optional\"`" + `
	Opt  string ` + "`json:\"opt,omitempty\" port:\"optional\"`" + `
	Nested []struct {
		ID string ` + "`json:\"id\" port:\"required\"`" + `
	} ` + "`json:\"nested\" port:\"required\"`" + `
}
`,
			wantBump: "MAJOR",
			wantExit: 0,
		},
		{
			name: "multi-identifier second field removal is MAJOR",
			newSrc: `package ports
const ProtocolVersion = 2
type Sample struct {
	A   string ` + "`json:\"ab\" toml:\"ab\" port:\"required\"`" + `
	Opt string ` + "`json:\"opt,omitempty\" port:\"optional\"`" + `
	Nested []struct {
		ID string ` + "`json:\"id\" port:\"required\"`" + `
	} ` + "`json:\"nested\" port:\"required\"`" + `
}
`,
			wantBump: "MAJOR",
			wantExit: 0,
		},
		{
			name: "toml tag change is MAJOR",
			newSrc: `package ports
const ProtocolVersion = 2
type Sample struct {
	A, B string ` + "`json:\"ab\" toml:\"ab_renamed\" port:\"required\"`" + `
	Opt  string ` + "`json:\"opt,omitempty\" port:\"optional\"`" + `
	Nested []struct {
		ID string ` + "`json:\"id\" port:\"required\"`" + `
	} ` + "`json:\"nested\" port:\"required\"`" + `
}
`,
			wantBump: "MAJOR",
			wantExit: 0,
		},
		{
			name: "inline anonymous struct field type change is MAJOR",
			newSrc: `package ports
const ProtocolVersion = 2
type Sample struct {
	A, B string ` + "`json:\"ab\" toml:\"ab\" port:\"required\"`" + `
	Opt  string ` + "`json:\"opt,omitempty\" port:\"optional\"`" + `
	Nested []struct {
		ID int64 ` + "`json:\"id\" port:\"required\"`" + `
	} ` + "`json:\"nested\" port:\"required\"`" + `
}
`,
			wantBump: "MAJOR",
			wantExit: 0,
		},
		{
			name: "optional field added inside inline struct is MINOR",
			newSrc: `package ports
const ProtocolVersion = 1
type Sample struct {
	A, B string ` + "`json:\"ab\" toml:\"ab\" port:\"required\"`" + `
	Opt  string ` + "`json:\"opt,omitempty\" port:\"optional\"`" + `
	Nested []struct {
		ID   string ` + "`json:\"id\" port:\"required\"`" + `
		Role string ` + "`json:\"role,omitempty\" port:\"optional\"`" + `
	} ` + "`json:\"nested\" port:\"required\"`" + `
}
`,
			wantBump: "MINOR",
			wantExit: 0,
		},
		{
			name: "MAJOR without ProtocolVersion bump fails non-zero",
			newSrc: `package ports
const ProtocolVersion = 1
type Sample struct {
	A, B string ` + "`json:\"ab\" toml:\"ab\" port:\"optional\"`" + `
	Opt  string ` + "`json:\"opt,omitempty\" port:\"optional\"`" + `
	Nested []struct {
		ID string ` + "`json:\"id\" port:\"required\"`" + `
	} ` + "`json:\"nested\" port:\"required\"`" + `
}
`,
			wantExit:   1,
			wantErrSub: "ProtocolVersion",
		},
	}

	dir := t.TempDir()
	oldPath := writeTempPorts(t, dir, "old_ports.go", base)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			newPath := writeTempPorts(t, dir, "new_ports.go", tc.newSrc)
			var outBuf, errBuf bytes.Buffer
			code := run([]string{oldPath, newPath}, &outBuf, &errBuf)
			if code != tc.wantExit {
				t.Fatalf("exit=%d want %d (stdout=%q stderr=%q)",
					code, tc.wantExit, outBuf.String(), errBuf.String())
			}
			if tc.wantBump != "" && strings.TrimSpace(outBuf.String()) != tc.wantBump {
				t.Fatalf("bump=%q want %q (stderr=%q)", outBuf.String(), tc.wantBump, errBuf.String())
			}
			if tc.wantErrSub != "" && !strings.Contains(errBuf.String(), tc.wantErrSub) {
				t.Fatalf("expected stderr to contain %q, got %q", tc.wantErrSub, errBuf.String())
			}
		})
	}
}
