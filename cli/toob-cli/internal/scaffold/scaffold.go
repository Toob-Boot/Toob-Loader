package scaffold

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// IntegrationGenerator generates minimal libtoob bridging code instead of full scaffolding.
type IntegrationGenerator struct {
	Framework string
}

func (g *IntegrationGenerator) Generate(ctx Context) error {
	if err := GenerateDeviceToml(ctx); err != nil {
		return err
	}

	integrationDir := filepath.Join(ctx.ProjectDir, "toob_integration")
	if err := os.MkdirAll(integrationDir, 0o755); err != nil {
		return err
	}

	tmplDir := filepath.Join(ctx.RegistryDir, "integrations", strings.ToLower(g.Framework), "files")
	if _, err := os.Stat(tmplDir); os.IsNotExist(err) {
		return fmt.Errorf("FATAL: Integration files not found for framework '%s' in registry", g.Framework)
	}

	return filepath.Walk(tmplDir, func(path string, info os.FileInfo, err error) error {
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

		destPath := filepath.Join(integrationDir, relPath)
		if info.IsDir() {
			return os.MkdirAll(destPath, 0o755)
		}

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
}

func GenerateDeviceToml(ctx Context) error {
	tmplPath := filepath.Join(ctx.RegistryDir, "chips", ctx.ChipName, "template_device.toml")

	var tmpl *template.Template
	var err error

	if _, err := os.Stat(tmplPath); os.IsNotExist(err) {
		return fmt.Errorf("FATAL: No template_device.toml found in registry for chip '%s'", ctx.ChipName)
	}

	tmpl, err = template.ParseFiles(tmplPath)
	if err != nil {
		return fmt.Errorf("failed to parse registry template: %w", err)
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
