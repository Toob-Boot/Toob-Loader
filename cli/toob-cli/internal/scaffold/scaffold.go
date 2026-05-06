package scaffold

import (
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/toob-boot/toob/internal/registry"
)

// Context contains all the necessary parameters for generating a project.
type Context struct {
	ProjectName string
	ProjectDir  string
	ChipName    string
	ChipInfo    *registry.ChipInfo
	RegistryDir     string
	NoVSCode        bool
	UseDevContainer bool
	SdkUrl          string
	SdkRevision     string
}

// Generator defines the interface for framework-specific scaffolders.
type Generator interface {
	Generate(ctx Context) error
}

func GenerateDeviceToml(ctx Context) error {
	tmplPath := filepath.Join(ctx.RegistryDir, "chips", ctx.ChipName, "template_device.toml")
	
	// Fallback Template (Minimal)
	fallbackTmpl := `name = "{{.ProjectName}}"
version = "0.1.0"

[device]
vendor = "{{.ChipInfo.Vendor}}"
chip = "{{.ChipName}}"
`

	var tmpl *template.Template
	var err error

	if _, err := os.Stat(tmplPath); err == nil {
		tmpl, err = template.ParseFiles(tmplPath)
		if err != nil {
			return fmt.Errorf("failed to parse registry template: %w", err)
		}
	} else {
		tmpl, err = template.New("device.toml").Parse(fallbackTmpl)
		if err != nil {
			return fmt.Errorf("failed to parse fallback template: %w", err)
		}
	}

	f, err := os.Create(filepath.Join(ctx.ProjectDir, "device.toml"))
	if err != nil {
		return err
	}
	defer f.Close()

	if err := tmpl.Execute(f, ctx); err != nil {
		return fmt.Errorf("failed to execute device.toml template: %w", err)
	}
	return nil
}
