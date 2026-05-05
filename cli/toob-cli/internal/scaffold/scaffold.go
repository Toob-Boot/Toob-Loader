package scaffold

import "github.com/toob-boot/toob/internal/registry"

// Context contains all the necessary parameters for generating a project.
type Context struct {
	ProjectName string
	ProjectDir  string
	ChipName    string
	ChipInfo    *registry.ChipInfo
	RegistryDir string
	NoVSCode    bool
}

// Generator defines the interface for framework-specific scaffolders.
type Generator interface {
	Generate(ctx Context) error
}
