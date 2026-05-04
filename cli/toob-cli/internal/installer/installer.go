// Package installer handles chip add, spawn, and remove operations.
package installer

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
)



// Installer orchestrates chip installation, spawning, and removal.
type Installer struct {
	root     string
	hal      string
	lockPath string
	lock     *lockfile.Lockfile
	cache    *registry.Cache
}

// New creates an installer for the given project root.
func New(root string, cache *registry.Cache) *Installer {
	lockPath := paths.LockfilePath(root)
	lf, _ := lockfile.Load(lockPath)
	return &Installer{
		root:     root,
		hal:      paths.HALDir(root),
		lockPath: lockPath,
		lock:     lf,
		cache:    cache,
	}
}

func parseChipArg(arg string) (string, string) {
	parts := strings.SplitN(arg, "@", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return parts[0], ""
}

// Add installs a chip from the registry (not tracked by git).
func (inst *Installer) Add(arg string) error {
	name, version := parseChipArg(arg)
	if inst.lock.HasChip(name) {
		e := inst.lock.GetChip(name)
		if e != nil && e.Spawned {
			return fmt.Errorf("chip '%s' is already spawned. Use `toob chip remove` first", name)
		}
		return fmt.Errorf("chip '%s' is already installed", name)
	}
	
	if version != "" {
		if err := inst.cache.Checkout(version); err != nil {
			return fmt.Errorf("failed to checkout registry version '%s': %w", version, err)
		}
	}

	ci, err := inst.cache.GetChip(name)
	if err != nil {
		return err
	}
	idx, _ := inst.cache.LoadIndex()
	
	commit, _ := inst.cache.HeadCommit()
	inst.lock.Registry.Commit = commit
	if idx != nil {
		inst.lock.Registry.Version = idx.RegistryVersion
	}
	
	inst.lock.Chips[name] = lockfile.ChipEntry{
		Version: ci.Version, Arch: ci.Arch, Vendor: ci.Vendor, Spawned: false,
	}
	if err := inst.lock.Save(inst.lockPath); err != nil {
		return err
	}
	fmt.Printf("Added chip '%s' (v%s) to lockfile [arch=%s, vendor=%s].\n", name, ci.Version, ci.Arch, ci.Vendor)
	fmt.Println("No files copied (True IKEA Mode). Run `toob build` to compile directly from registry.")
	return nil
}

// Spawn installs a chip as locally editable (tracked by git).
func (inst *Installer) Spawn(arg string) error {
	name, version := parseChipArg(arg)
	if inst.lock.HasChip(name) {
		e := inst.lock.GetChip(name)
		if e != nil && !e.Spawned {
			return fmt.Errorf("chip '%s' is already added. Use `toob chip remove` first, then `toob chip spawn`", name)
		}
		return fmt.Errorf("chip '%s' is already spawned", name)
	}

	if version != "" {
		if err := inst.cache.Checkout(version); err != nil {
			return fmt.Errorf("failed to checkout registry version '%s': %w", version, err)
		}
	}

	ci, err := inst.cache.GetChip(name)
	if err != nil {
		return err
	}
	if err := inst.installChip(ci); err != nil {
		return err
	}
	if err := inst.installDeps(ci); err != nil {
		return err
	}

	idx, _ := inst.cache.LoadIndex()
	commit, _ := inst.cache.HeadCommit()
	inst.lock.Registry.Commit = commit
	if idx != nil {
		inst.lock.Registry.Version = idx.RegistryVersion
	}
	
	inst.lock.Chips[name] = lockfile.ChipEntry{
		Version: ci.Version, Arch: ci.Arch, Vendor: ci.Vendor, Spawned: true,
	}
	if err := inst.lock.Save(inst.lockPath); err != nil {
		return err
	}
	fmt.Printf("Spawned chip '%s' (v%s)  [locally editable — tracked by git]\n", name, ci.Version)
	return nil
}

// Remove uninstalls a chip and cleans up unshared dependencies.
func (inst *Installer) Remove(name string) error {
	entry := inst.lock.GetChip(name)
	if entry == nil {
		return fmt.Errorf("chip '%s' is not installed", name)
	}

	// Only remove physical files if the chip was spawned.
	if entry.Spawned {
		chipDir := filepath.Join(inst.hal, "chips", name)
		os.RemoveAll(chipDir)

		// Remove arch/vendor only if no other chip shares them
		if !inst.lock.IsArchShared(entry.Arch, name) {
			os.RemoveAll(filepath.Join(inst.hal, "arch", entry.Arch))
		}
		if !inst.lock.IsVendorShared(entry.Vendor, name) {
			os.RemoveAll(filepath.Join(inst.hal, "vendor", entry.Vendor))
		}
	}

	delete(inst.lock.Chips, name)
	if err := inst.lock.Save(inst.lockPath); err != nil {
		return err
	}
	fmt.Printf("Removed chip '%s'.\n", name)
	return nil
}

func (inst *Installer) installChip(ci *registry.ChipInfo) error {
	src, err := inst.cache.ChipSourcePath(ci.Name)
	if err != nil {
		return err
	}
	dst := filepath.Join(inst.hal, "chips", ci.Name)
	return copyTree(src, dst)
}

func (inst *Installer) installDeps(ci *registry.ChipInfo) error {
	// Architecture layer
	archDst := filepath.Join(inst.hal, "arch", ci.Arch)
	if _, err := os.Stat(archDst); os.IsNotExist(err) {
		archSrc := inst.cache.ArchSourcePath(ci.Arch)
		if err := copyTree(archSrc, archDst); err != nil {
			return err
		}
	}

	// Vendor layer
	vendorDst := filepath.Join(inst.hal, "vendor", ci.Vendor)
	if _, err := os.Stat(vendorDst); os.IsNotExist(err) {
		vendorSrc := inst.cache.VendorSourcePath(ci.Vendor)
		if err := copyTree(vendorSrc, vendorDst); err != nil {
			return err
		}
	}

	// Toolchain file
	tcDst := filepath.Join(inst.root, "cmake", ci.Toolchain)
	if _, err := os.Stat(tcDst); os.IsNotExist(err) {
		tcSrc := inst.cache.ToolchainSourcePath(ci.Toolchain)
		if _, err := os.Stat(tcSrc); err == nil {
			data, err := os.ReadFile(tcSrc)
			if err != nil {
				return err
			}
			os.MkdirAll(filepath.Dir(tcDst), 0o755)
			if err := os.WriteFile(tcDst, data, 0o644); err != nil {
				return err
			}
		}
	}

	return nil
}

// copyTree recursively copies src to dst.
func copyTree(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("registry source does not exist: %s (run `toob registry sync`)", src)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", src)
	}

	// Remove existing destination
	os.RemoveAll(dst)

	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)

		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}


