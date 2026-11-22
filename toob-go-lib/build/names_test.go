package build

import "testing"

func TestValidateName(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"lowercase", "esp32c6", false},
		{"mixed case with dash", "TEST-CHIP", false},
		{"dots and underscores", "v1.2_rc-3", false},
		{"empty", "", true},
		{"path traversal", "../evil", true},
		{"dot dot", "..", true},
		{"leading dot", ".hidden", true},
		{"slash", "a/b", true},
		{"backslash", `a\b`, true},
		{"quote", `a"b`, true},
		{"space", "a b", true},
		{"newline", "a\nb", true},
		{"cmake variable", "${HOME}", true},
		{"non-ascii", "chip\u00e9", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateName("chip", c.input); (err != nil) != c.wantErr {
				t.Fatalf("ValidateName(%q) error = %v, wantErr %v", c.input, err, c.wantErr)
			}
		})
	}
}

func TestValidatePackageRef(t *testing.T) {
	validRefs := []string{"esp_efuse", "@partner/atecc608", "@espressif/esp_trng_v2", "@community-org/custom.drv"}
	for _, r := range validRefs {
		if err := ValidatePackageRef("driver", r); err != nil {
			t.Errorf("ValidatePackageRef(%q) unexpected error: %v", r, err)
		}
	}
	invalidRefs := []string{"", "@", "@/pkg", "@scope/", "@scope/a/b", "@../evil", "a/b", "@scope/../x"}
	for _, r := range invalidRefs {
		if err := ValidatePackageRef("driver", r); err == nil {
			t.Errorf("ValidatePackageRef(%q) must fail", r)
		}
	}
}

func TestValidateDisplayText(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"plain", "Boot ROM (read-only)", false},
		{"empty", "", false},
		{"comment open", "a /* b", true},
		{"comment close", "a */ b", true},
		{"newline", "a\nb", true},
		{"tab", "a\tb", true},
		{"non-ascii", "caf\u00e9", true},
		{"delete char", "a\x7fb", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := validateDisplayText("field", c.input); (err != nil) != c.wantErr {
				t.Fatalf("validateDisplayText(%q) error = %v, wantErr %v", c.input, err, c.wantErr)
			}
		})
	}
}
