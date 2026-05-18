// Package installer handles chip add, spawn, and remove operations.
package installer

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/ui"
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
	// Async Matrix Fetch (Gap 4.1)
	matrixChan := make(chan *registry.Matrix, 1)
	go func() {
		m, _ := inst.cache.FetchLiveMatrix()
		matrixChan <- m
	}()
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
	} else if inst.lock.Registry.Commit != "" {
		if err := inst.cache.Checkout(inst.lock.Registry.Commit); err != nil {
			return fmt.Errorf("failed to checkout locked registry commit '%s': %w", inst.lock.Registry.Commit, err)
		}
	}

	ci, err := inst.cache.GetChip(name)
	if err != nil {
		if liveVer, liveErr := inst.cache.ResolveChipLive(name); liveErr == nil {
			return fmt.Errorf("Chip '%s' is locally unknown.\n  › Good news: It exists in Toob-Registry Version %s!\n  › Run `toob registry sync` to download it.", name, liveVer)
		}
		return err
	}
	idx, _ := inst.cache.LoadIndex()
	
	commit, _ := inst.cache.HeadCommit()
	inst.lock.Registry.Commit = commit
	
	aVer := ""
	tcVer := ""
	if idx != nil {
		inst.lock.Registry.Version = idx.RegistryVersion
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
		Name: name, Version: ci.Version, Arch: ci.Arch, ArchVersion: aVer, Toolchain: strings.TrimSuffix(ci.CompilerPrefix, "-"), ToolchainVersion: tcVer, Spawned: false,
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
	ui.Success("Added chip '%s' (v%s) to lockfile [arch=%s].", name, ci.Version, ci.Arch)
	
	// Wait up to 1 second for the matrix to avoid blocking
	var matrix *registry.Matrix
	select {
	case matrix = <-matrixChan:
	case <-time.After(1 * time.Second):
	}
	printMatrixCompatibility(matrix, ci.Name, ci.Version, ci.Verified)

	ui.Tip("Registry link established. Run `toob build` to compile.")
	return nil
}

// Spawn installs a chip as locally editable (tracked by git).
func (inst *Installer) Spawn(arg string) error {
	// Async Matrix Fetch (Gap 4.1)
	matrixChan := make(chan *registry.Matrix, 1)
	go func() {
		m, _ := inst.cache.FetchLiveMatrix()
		matrixChan <- m
	}()
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
	} else if inst.lock.Registry.Commit != "" {
		// Enforce current lockfile commit to prevent shared dependency drift
		if err := inst.cache.Checkout(inst.lock.Registry.Commit); err != nil {
			return fmt.Errorf("failed to checkout locked registry commit '%s': %w", inst.lock.Registry.Commit, err)
		}
	}

	ci, err := inst.cache.GetChip(name)
	if err != nil {
		if liveVer, liveErr := inst.cache.ResolveChipLive(name); liveErr == nil {
			return fmt.Errorf("Chip '%s' is locally unknown.\n  › Good news: It exists in Toob-Registry Version %s!\n  › Run `toob registry sync` to download it.", name, liveVer)
		}
		return err
	}

	var rollback []string
	var spawnErr error
	defer func() {
		if spawnErr != nil {
			ui.Warn("Spawn failed. Rolling back created directories...")
			for _, dir := range rollback {
				// Gap 7.2: Use moveToTrash to prevent NTFS zombie folders on rollback failure
				moveToTrash(dir)
			}
		}
	}()

	created, err := inst.installChip(ci, false)
	if err != nil {
		spawnErr = err
		return err
	}
	rollback = append(rollback, created...)

	createdDeps, err := inst.installDeps(ci, false)
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
	
	aVer := ""
	tcVer := ""
	if idx != nil {
		inst.lock.Registry.Version = idx.RegistryVersion
		if aInfo, ok := idx.Archs[ci.Arch]; ok {
			aVer = aInfo.Version
		}
		tcName := strings.TrimSuffix(ci.CompilerPrefix, "-")
		if tcInfo, ok := idx.Toolchains[tcName]; ok {
			tcVer = tcInfo.Version
		}
	}
	
	entry := lockfile.ChipEntry{
		Name: name, Version: ci.Version, Arch: ci.Arch, ArchVersion: aVer, Toolchain: strings.TrimSuffix(ci.CompilerPrefix, "-"), ToolchainVersion: tcVer, Spawned: true,
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
	ui.Success("Spawned chip '%s' (v%s) [locally editable]", name, ci.Version)
	
	// Wait up to 1 second for the matrix to avoid blocking
	var matrix *registry.Matrix
	select {
	case matrix = <-matrixChan:
	case <-time.After(1 * time.Second):
	}
	printMatrixCompatibility(matrix, ci.Name, ci.Version, ci.Verified)

	return nil
}

// moveToTrash renames a directory to a .trash folder instead of deleting it.
func moveToTrash(dir string) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return
	}
	trashRoot := filepath.Join(filepath.Dir(filepath.Dir(dir)), ".trash")
	trashDir := filepath.Join(trashRoot, filepath.Base(filepath.Dir(dir)), filepath.Base(dir)+"-"+time.Now().Format("20060102150405"))
	os.MkdirAll(filepath.Dir(trashDir), 0o755)
	os.Rename(dir, trashDir)

	purgeOldTrash(trashRoot, 7*24*time.Hour)
}

// removeIfEmpty removes a directory only if it contains no entries.
func removeIfEmpty(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	if len(entries) == 0 {
		os.Remove(dir)
	}
}

// purgeOldTrash removes entries from .trash/ older than maxAge.
func purgeOldTrash(trashRoot string, maxAge time.Duration) {
	entries, err := os.ReadDir(trashRoot)
	if err != nil {
		return
	}
	for _, category := range entries {
		if !category.IsDir() {
			continue
		}
		catPath := filepath.Join(trashRoot, category.Name())
		subEntries, err := os.ReadDir(catPath)
		if err != nil {
			continue
		}
		for _, entry := range subEntries {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if time.Since(info.ModTime()) > maxAge {
				os.RemoveAll(filepath.Join(catPath, entry.Name()))
			}
		}
		removeIfEmpty(catPath)
	}
	removeIfEmpty(trashRoot)
}

func printMatrixCompatibility(matrix *registry.Matrix, chipName, chipVersion string, verified bool) {
	if !verified {
		ui.Warn("This hardware configuration is marked as UNVERIFIED by the CI Compatibility Matrix. Build stability is not guaranteed.")
		return
	}

	if matrix == nil {
		return
	}

	if chipEntry, has := (*matrix)[chipName]; has {
		// Normalize version string to handle mismatching prefixes (Gap 4.2)
		searchVer := strings.TrimPrefix(chipVersion, "v")
		for vKey, verEntry := range chipEntry.Versions {
			if strings.TrimPrefix(vKey, "v") == searchVer {
				var verifiedClis []string
				for cliVer, info := range verEntry.VerifiedCliVersions {
					if info.Status == "SUCCESS" {
						verifiedClis = append(verifiedClis, cliVer)
					}
				}
				if len(verifiedClis) > 0 {
					ui.Success("Chip %s v%s — Verified with CLI: %s", chipName, chipVersion, strings.Join(verifiedClis, ", "))
				}
				break
			}
		}
	}
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
		// Clean up empty parent directories left behind
		removeIfEmpty(filepath.Join(inst.hal, "chips"))
		removeIfEmpty(filepath.Join(inst.hal, "arch"))
		removeIfEmpty(filepath.Join(inst.hal, "drivers"))
		removeIfEmpty(filepath.Join(inst.hal, "include"))
		removeIfEmpty(inst.hal)
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
	ui.Success("Removed chip '%s'.", name)
	return nil
}

func (inst *Installer) installChip(ci *registry.ChipInfo, allowLinks bool) ([]string, error) {
	src, err := inst.cache.ChipSourcePath(ci.Name)
	if err != nil {
		return nil, err
	}
	dst := filepath.Join(inst.hal, "chips", ci.Name)
	return []string{dst}, copyTree(src, dst, allowLinks)
}

func (inst *Installer) installDeps(ci *registry.ChipInfo, allowLinks bool) ([]string, error) {
	var created []string

	// Architecture layer
	archDst := filepath.Join(inst.hal, "arch", ci.Arch)
	if _, err := os.Stat(archDst); os.IsNotExist(err) {
		archSrc, err := inst.cache.ArchSourcePath(ci.Arch)
		if err != nil {
			return created, err
		}
		if err := copyTree(archSrc, archDst, allowLinks); err != nil {
			return created, err
		}
		created = append(created, archDst)
	} else if inst.lock.Registry.Version != "" {
		// If it exists, but the registry version in lockfile differs from what we are spawning...
		// Actually, we forced checkout to Lockfile version or specific version above.
		// If they forced a new version, the existing dependency might be outdated!
		// For now, we print a warning, as we are not overwriting it.
		ui.Warn("Shared dependency '%s' already exists. Not overwriting to preserve local edits.", archDst)
	}

	// Drivers layer
	if ci.Sources != nil {
		for _, driverFile := range ci.Sources.Drivers {
			if strings.HasPrefix(driverFile, "drivers/") {
				driverDir := filepath.Dir(driverFile) // e.g., drivers/uart/esp_uart_v1
				driverDst := filepath.Join(inst.hal, filepath.FromSlash(driverDir))
				if _, err := os.Stat(driverDst); os.IsNotExist(err) {
					driverSrc := filepath.Join(inst.cache.Dir(), filepath.FromSlash(driverDir))
					if err := copyTree(driverSrc, driverDst, allowLinks); err != nil {
						return created, err
					}
					created = append(created, driverDst)
				} else if inst.lock.Registry.Version != "" {
					ui.Warn("Shared dependency '%s' already exists. Not overwriting to preserve local edits.", driverDst)
				}
			}
		}
	}
	for _, inc := range ci.Includes {
		if strings.HasPrefix(inc, "drivers/") || strings.HasPrefix(inc, "soc/") || strings.HasPrefix(inc, "shared/") {
			driverDst := filepath.Join(inst.hal, filepath.FromSlash(inc))
			if _, err := os.Stat(driverDst); os.IsNotExist(err) {
				driverSrc := filepath.Join(inst.cache.Dir(), filepath.FromSlash(inc))
				if err := copyTree(driverSrc, driverDst, allowLinks); err != nil {
					return created, err
				}
				created = append(created, driverDst)
			} else if inst.lock.Registry.Version != "" {
				ui.Warn("Shared dependency '%s' already exists. Not overwriting to preserve local edits.", driverDst)
			}
		}
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
// Uses hard-links where possible for instant, zero-disk-cost copies.
func copyTree(src, dst string, allowLinks bool) error {
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
		return linkOrCopy(path, target, allowLinks)
	})
}

// linkOrCopy attempts a hard-link first, falling back to a full byte-copy.
// Hard-links share the inode and are instant with zero additional disk cost.
// Fallback handles cross-device mounts, FAT32, and Windows restrictions.
func linkOrCopy(src, dst string, allowLinks bool) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if allowLinks {
		if err := os.Link(src, dst); err == nil {
			return nil
		}
	}
	
	stat, err := os.Stat(src)
	if err != nil {
		return err
	}
	origMode := stat.Mode()
	
	// Gap 7.2: Atomic copyTree Fallback with Windows NTFS Lock Retries
	var writeErr error
	delays := []time.Duration{10 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, 500 * time.Millisecond}
	for _, d := range delays {
		// Use O(1) memory streaming instead of os.ReadFile to prevent Out-Of-Memory (OOM) on large binaries
		srcFile, _ := os.Open(src)
		dstFile, _ := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, origMode)
		_, writeErr = io.Copy(dstFile, srcFile)
		srcFile.Close()
		dstFile.Close()
		
		if writeErr == nil {
			return nil
		}
		time.Sleep(d)
	}
	return writeErr
}


