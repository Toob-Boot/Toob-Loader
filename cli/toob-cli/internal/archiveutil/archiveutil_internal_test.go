package archiveutil

import "testing"

func TestCleanWindowsReparsePrefix_PreservesUNCAndStripsDevicePrefix(t *testing.T) {
	cases := map[string]string{
		`\??\UNC\server\share\dir`:  `\\server\share\dir`,
		`\\?\unc\server\share\file`: `\\server\share\file`,
		`\??\C:\Users\victim`:       `C:\Users\victim`,
		`\\?\D:\ToobStorage\tc`:     `D:\ToobStorage\tc`,
		`../relative/link`:          `../relative/link`,
	}
	for in, want := range cases {
		got := cleanWindowsReparsePrefix(in)
		if got != want {
			t.Errorf("cleanWindowsReparsePrefix(%q) = %q, want %q", in, got, want)
		}
		if in == `\??\UNC\server\share\dir` && !isRooted(got) {
			t.Errorf("cleaned UNC target %q must be detected as rooted", got)
		}
	}
}
