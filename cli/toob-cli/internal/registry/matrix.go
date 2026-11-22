package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/toob-boot/toob/internal/apiclient"
)

// ResolveChipLive queries the registry API for a chip and returns its version.
func (c *Cache) ResolveChipLive(name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client := c.apiClient(2 * time.Second)
	resp, err := client.ResolveChip(ctx, name)
	if err != nil {
		return "", fmt.Errorf("failed to resolve chip via API: %w", err)
	}
	return resp.Version, nil
}

// FetchLiveIntegrations fetches available integrations from the API, falling back to local cache.
func (c *Cache) FetchLiveIntegrations() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client := c.apiClient(3 * time.Second)
	items, err := client.ListIntegrations(ctx)
	if err == nil {
		result := make([]string, 0, len(items))
		for _, i := range items {
			result = append(result, i.Name)
		}
		return result, nil
	}

	idx, idxErr := c.LoadIndex()
	if idxErr != nil {
		return nil, fmt.Errorf("api and local fallback both failed: %w", idxErr)
	}

	return slices.Sorted(maps.Keys(idx.Integrations)), nil
}

// FetchLiveMatrix downloads the compatibility matrix from the API, falling back to local cache.
func (c *Cache) FetchLiveMatrix() (*Matrix, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := c.apiClient(5 * time.Second)
	entries, err := client.GetMatrix(ctx, "")
	if err == nil {
		matrix := convertFlatMatrixToMap(entries)
		return &matrix, nil
	}

	localPath := filepath.Join(c.Dir(), "compatibility_matrix.json")
	localData, err := os.ReadFile(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch matrix (api and local both failed): %w", err)
	}

	matrix, err := parseMatrixData(localData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse matrix: %w", err)
	}

	return &matrix, nil
}

func convertFlatMatrixToMap(entries []apiclient.MatrixEntry) Matrix {
	matrix := make(Matrix)
	for i := range entries {
		entry := &entries[i]
		parts := strings.Split(entry.CombinationKey, "::")
		var cliVal string
		for _, p := range parts {
			if after, ok := strings.CutPrefix(p, "cli="); ok {
				cliVal = after
			}
		}
		if cliVal == "" {
			continue
		}

		chip := entry.Chip
		chipVer := entry.ChipVersion

		chipEntry, exists := matrix[chip]
		if !exists {
			chipEntry = MatrixChip{Versions: make(map[string]MatrixVersion)}
			matrix[chip] = chipEntry
		}

		verEntry, exists := chipEntry.Versions[chipVer]
		if !exists {
			var deps MatrixDependencies
			if len(entry.Dependencies) > 0 {
				_ = json.Unmarshal(entry.Dependencies, &deps)
			}
			verEntry = MatrixVersion{
				EnvironmentHash:     entry.EnvHash,
				Dependencies:        deps,
				VerifiedCliVersions: make(map[string]MatrixVerifiedCli),
			}
			chipEntry.Versions[chipVer] = verEntry
		}

		var lastTested string
		if entry.TestedAt != nil {
			lastTested = entry.TestedAt.Format(time.RFC3339)
		}

		verEntry.VerifiedCliVersions[cliVal] = MatrixVerifiedCli{
			Status:     entry.Status,
			LastTested: lastTested,
		}
	}
	return matrix
}

func parseMatrixData(data []byte) (Matrix, error) {
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("[")) {
		var entries []apiclient.MatrixEntry
		if err := json.Unmarshal(trimmed, &entries); err == nil {
			return convertFlatMatrixToMap(entries), nil
		}
	}

	var matrix Matrix
	if err := json.Unmarshal(trimmed, &matrix); err == nil {
		return matrix, nil
	}

	return nil, errors.New("unknown compatibility matrix format")
}
