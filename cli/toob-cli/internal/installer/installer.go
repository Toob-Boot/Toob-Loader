// Package installer handles chip add, spawn, and remove operations.
package installer

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	
	vVer := ""
	aVer := ""
	tcVer := ""
	if idx != nil {
		inst.lock.Registry.Version = idx.RegistryVersion
		if vInfo, ok := idx.Vendors[ci.Vendor]; ok {
			vVer = vInfo.Version
		}
		if aInfo, ok := idx.Archs[ci.Arch]; ok {
			aVer = aInfo.Version
		}
		// toolchain version is stored globally in lockfile, but let's grab it for the chip entry
		tcName := strings.TrimSuffix(ci.CompilerPrefix, "-")
		if tcInfo, ok := idx.Toolchains[tcName]; ok {
			tcVer = tcInfo.Version
		}
	}
	
	entry := lockfile.ChipEntry{
		Name: name, Version: ci.Version, Arch: ci.Arch, ArchVersion: aVer, Vendor: ci.Vendor, VendorVersion: vVer, Toolchain: strings.TrimSuffix(ci.CompilerPrefix, "-"), ToolchainVersion: tcVer, Spawned: false,
	}
	
	// Replace or append
	found := false
	for i := range inst.lock.Chips {
		if inst.lock.Chips[i].Name == name {
			inst.lock.Chips[i] = entry
			found = true
			break
		}
	}
	if !found {
		inst.lock.Chips = append(inst.lock.Chips, entry)
	}
	if err := inst.lock.Save(inst.lockPath); err != nil {
		return err
	}
	fmt.Printf("Added chip '%s' (v%s) to lockfile [arch=%s, vendor=%s].\n", name, ci.Version, ci.Arch, ci.Vendor)
	
	if !ci.Verified {
		fmt.Println("\n\033[33mWarning: This hardware configuration is marked as UNVERIFIED by the CI Compatibility Matrix. Build stability is not guaranteed.\033[0m")
	}

	fmt.Println("Registry link established. Run `toob build` to compile.")
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
	} else if inst.lock.Registry.Version != "" {
		// Enforce current lockfile version to prevent shared dependency drift
		if err := inst.cache.Checkout(inst.lock.Registry.Version); err != nil {
			return fmt.Errorf("failed to checkout locked registry version '%s': %w", inst.lock.Registry.Version, err)
		}
	}

	ci, err := inst.cache.GetChip(name)
	if err != nil {
		return err
	}

	var rollback []string
	var spawnErr error
	defer func() {
		if spawnErr != nil {
			fmt.Println("[toob] Spawn failed. Rolling back created directories...")
			for _, dir := range rollback {
				os.RemoveAll(dir)
			}
		}
	}()

	created, err := inst.installChip(ci)
	if err != nil {
		spawnErr = err
		return err
	}
	rollback = append(rollback, created...)

	createdDeps, err := inst.installDeps(ci)
	if err != nil {
		spawnErr = err
		return err
	}
	rollback = append(rollback, createdDeps...)

	// Auto-Gitignore
	gitignorePath := filepath.Join(inst.root, ".gitignore")
	if data, err := os.ReadFile(gitignorePath); err == nil {
		if !strings.Contains(string(data), "toobloader/hal/") {
			f, err := os.OpenFile(gitignorePath, os.O_APPEND|os.O_WRONLY, 0o644)
			if err == nil {
				f.WriteString("\n# Toob-Loader Spawned HALs\ntoobloader/hal/\n")
				f.Close()
			}
		}
	}

	idx, _ := inst.cache.LoadIndex()
	commit, _ := inst.cache.HeadCommit()
	inst.lock.Registry.Commit = commit
	
	vVer := ""
	aVer := ""
	tcVer := ""
	if idx != nil {
		inst.lock.Registry.Version = idx.RegistryVersion
		if vInfo, ok := idx.Vendors[ci.Vendor]; ok {
			vVer = vInfo.Version
		}
		if aInfo, ok := idx.Archs[ci.Arch]; ok {
			aVer = aInfo.Version
		}
		tcName := strings.TrimSuffix(ci.CompilerPrefix, "-")
		if tcInfo, ok := idx.Toolchains[tcName]; ok {
			tcVer = tcInfo.Version
		}
	}
	
	entry := lockfile.ChipEntry{
		Name: name, Version: ci.Version, Arch: ci.Arch, ArchVersion: aVer, Vendor: ci.Vendor, VendorVersion: vVer, Toolchain: strings.TrimSuffix(ci.CompilerPrefix, "-"), ToolchainVersion: tcVer, Spawned: true,
	}
	
	found := false
	for i := range inst.lock.Chips {
		if inst.lock.Chips[i].Name == name {
			inst.lock.Chips[i] = entry
			found = true
			break
		}
	}
	if !found {
		inst.lock.Chips = append(inst.lock.Chips, entry)
	}
	if err := inst.lock.Save(inst.lockPath); err != nil {
		spawnErr = err
		return err
	}
	fmt.Printf("Spawned chip '%s' (v%s)  [locally editable]\n", name, ci.Version)
	
	if !ci.Verified {
		fmt.Println("\n\033[33mWarning: This hardware configuration is marked as UNVERIFIED by the CI Compatibility Matrix. Build stability is not guaranteed.\033[0m")
	}

	return nil
}

// moveToTrash renames a directory to a .trash folder instead of deleting it.
func moveToTrash(dir string) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return
	}
	trashDir := filepath.Join(filepath.Dir(filepath.Dir(dir)), ".trash", filepath.Base(filepath.Dir(dir)), filepath.Base(dir)+"-"+time.Now().Format("20060102150405"))
	os.MkdirAll(filepath.Dir(trashDir), 0o755)
	os.Rename(dir, trashDir)
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
		moveToTrash(chipDir)

		// Remove arch/vendor only if no other chip shares them
		if !inst.lock.IsArchShared(entry.Arch, name) {
			moveToTrash(filepath.Join(inst.hal, "arch", entry.Arch))
		}
		if !inst.lock.IsVendorShared(entry.Vendor, name) {
			moveToTrash(filepath.Join(inst.hal, "vendor", entry.Vendor))
		}
	}

	for i, c := range inst.lock.Chips {
		if c.Name == name {
			inst.lock.Chips = append(inst.lock.Chips[:i], inst.lock.Chips[i+1:]...)
			break
		}
	}
	if err := inst.lock.Save(inst.lockPath); err != nil {
		return err
	}
	fmt.Printf("Removed chip '%s'.\n", name)
	return nil
}

func (inst *Installer) installChip(ci *registry.ChipInfo) ([]string, error) {
	src, err := inst.cache.ChipSourcePath(ci.Name)
	if err != nil {
		return nil, err
	}
	dst := filepath.Join(inst.hal, "chips", ci.Name)
	return []string{dst}, copyTree(src, dst)
}

func (inst *Installer) installDeps(ci *registry.ChipInfo) ([]string, error) {
	var created []string

	// Architecture layer
	archDst := filepath.Join(inst.hal, "arch", ci.Arch)
	if _, err := os.Stat(archDst); os.IsNotExist(err) {
		archSrc := inst.cache.ArchSourcePath(ci.Arch)
		if err := copyTree(archSrc, archDst); err != nil {
			return created, err
		}
		created = append(created, archDst)
	} else if inst.lock.Registry.Version != "" {
		// If it exists, but the registry version in lockfile differs from what we are spawning...
		// Actually, we forced checkout to Lockfile version or specific version above.
		// If they forced a new version, the existing dependency might be outdated!
		// For now, we print a warning, as we are not overwriting it.
		fmt.Printf("[toob] Warning: shared dependency '%s' already exists. Not overwriting to preserve local edits.\n", archDst)
	}

	// Vendor layer
	vendorDst := filepath.Join(inst.hal, "vendor", ci.Vendor)
	if _, err := os.Stat(vendorDst); os.IsNotExist(err) {
		vendorSrc := inst.cache.VendorSourcePath(ci.Vendor)
		if err := copyTree(vendorSrc, vendorDst); err != nil {
			return created, err
		}
		created = append(created, vendorDst)
	} else if inst.lock.Registry.Version != "" {
		fmt.Printf("[toob] Warning: shared dependency '%s' already exists. Not overwriting to preserve local edits.\n", vendorDst)
	}

	// Toolchain file
	tcName := "toolchain.cmake"
	tcDst := filepath.Join(inst.root, "cmake", tcName)
	if _, err := os.Stat(tcDst); os.IsNotExist(err) {
		tcDirName := strings.TrimSuffix(ci.CompilerPrefix, "-")
		tcSrc := filepath.Join(inst.cache.Dir(), "toolchains", tcDirName, "toolchain.cmake")
		if _, err := os.Stat(tcSrc); err == nil {
			data, err := os.ReadFile(tcSrc)
			if err != nil {
				return created, err
			}
			os.MkdirAll(filepath.Dir(tcDst), 0o755)
			if err := os.WriteFile(tcDst, data, 0o644); err != nil {
				return created, err
			}
			created = append(created, tcDst)
		}
	}

	return created, nil
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

	// Overwrite Protection
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("directory %s already exists. Please remove it manually to respawn or update", dst)
	}

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


