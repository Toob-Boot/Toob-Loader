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
	ProjectName     string
	ProjectDir      string
	ChipName        string
	ChipInfo        *registry.ChipInfo
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

// RegistryGenerator copies template files dynamically from the registry.
type RegistryGenerator struct {
	Framework string
}

func (g *RegistryGenerator) Generate(ctx Context) error {
	if err := GenerateDeviceToml(ctx); err != nil {
		return err
	}

	tmplDir := filepath.Join(ctx.RegistryDir, "chips", ctx.ChipName, "templates", strings.ToLower(g.Framework))
	if _, err := os.Stat(tmplDir); os.IsNotExist(err) {
		return fmt.Errorf("framework '%s' not found for chip '%s' in registry (missing %s)", g.Framework, ctx.ChipName, tmplDir)
	}

	err := filepath.Walk(tmplDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		relPath, err := filepath.Rel(tmplDir, path)
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}

		destPath := filepath.Join(ctx.ProjectDir, relPath)
		if info.IsDir() {
			return os.MkdirAll(destPath, 0755)
		}

		// Read and execute template
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		tmpl, err := template.New(relPath).Parse(string(data))
		if err != nil {
			return fmt.Errorf("failed to parse template %s: %w", relPath, err)
		}

		f, err := os.Create(destPath)
		if err != nil {
			return err
		}
		defer f.Close()

		if err := tmpl.Execute(f, ctx); err != nil {
			return fmt.Errorf("failed to execute template %s: %w", relPath, err)
		}
		return nil
	})

	return err
}

func GenerateDeviceToml(ctx Context) error {
	tmplPath := filepath.Join(ctx.RegistryDir, "chips", ctx.ChipName, "template_device.toml")

	// Fallback Template (Minimal with instructions)
	fallbackTmpl := `name = "{{.ProjectName}}"
version = "0.1.0"

[device]
vendor = "{{.ChipInfo.Vendor}}"
chip = "{{.ChipName}}"

[partitions]
# FATAL: No template found in registry for this chip.
# You MUST configure these following partition sizes (in bytes) for your specific hardware flash size!
stage0_size = 0
stage1_size = 0
app_size = 0
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
