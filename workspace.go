package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// WorkspaceInfo describes a persistent workspace on disk.
type WorkspaceInfo struct {
	Hash         string    `json:"hash"`
	SizeBytes    int64     `json:"size_bytes"`
	LastModified time.Time `json:"last_modified"`
}

// WorkspaceManager owns workspace operations.
type WorkspaceManager struct {
	baseDir string
}

// NewWorkspaceManager creates a manager rooted at baseDir.
func NewWorkspaceManager(baseDir string) *WorkspaceManager {
	return &WorkspaceManager{baseDir: baseDir}
}

func (wm *WorkspaceManager) workspacesDir() string {
	return filepath.Join(wm.baseDir, "workspaces")
}

func (wm *WorkspaceManager) artifactsDir() string {
	return filepath.Join(wm.baseDir, "artifacts")
}

// ---------------------------------------------------------------------------
// ListWorkspaces
// ---------------------------------------------------------------------------

func (wm *WorkspaceManager) ListWorkspaces() ([]WorkspaceInfo, error) {
	dir := wm.workspacesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var workspaces []WorkspaceInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if !isValidHash(name) {
			continue
		}
		wsPath := filepath.Join(dir, name)
		size := dirSize(wsPath)
		info, err := e.Info()
		if err != nil {
			continue
		}
		workspaces = append(workspaces, WorkspaceInfo{
			Hash:         name,
			SizeBytes:    size,
			LastModified: info.ModTime(),
		})
	}
	return workspaces, nil
}

// dirSize computes the total size of a directory tree.
func dirSize(path string) int64 {
	var total int64
	_ = filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// ---------------------------------------------------------------------------
// CleanWorkspace
// ---------------------------------------------------------------------------

func (wm *WorkspaceManager) CleanWorkspace(hash string) error {
	if !isValidHash(hash) {
		return fmt.Errorf("invalid workspace hash")
	}
	wsPath, err := safeSubpath(wm.workspacesDir(), hash)
	if err != nil {
		return err
	}
	return os.RemoveAll(wsPath)
}

// ---------------------------------------------------------------------------
// CleanStaleWorkspaces
// ---------------------------------------------------------------------------

// parseDuration parses strings like "7d", "24h", "30m".
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return 0, fmt.Errorf("empty duration")
	}

	suffix := s[len(s)-1]
	numStr := s[:len(s)-1]

	switch suffix {
	case 'd':
		n, err := strconv.Atoi(numStr)
		if err != nil {
			return 0, fmt.Errorf("invalid duration: %s", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	case 'h':
		n, err := strconv.Atoi(numStr)
		if err != nil {
			return 0, fmt.Errorf("invalid duration: %s", s)
		}
		return time.Duration(n) * time.Hour, nil
	case 'm':
		n, err := strconv.Atoi(numStr)
		if err != nil {
			return 0, fmt.Errorf("invalid duration: %s", s)
		}
		return time.Duration(n) * time.Minute, nil
	default:
		// Try standard Go duration parsing.
		return time.ParseDuration(s)
	}
}

func (wm *WorkspaceManager) CleanStaleWorkspaces(olderThan time.Duration) (int, error) {
	dir := wm.workspacesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	cutoff := time.Now().Add(-olderThan)
	removed := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			wsPath := filepath.Join(dir, e.Name())
			if err := os.RemoveAll(wsPath); err != nil {
				log.Printf("failed to remove stale workspace %s: %v", e.Name(), err)
				continue
			}
			removed++
		}
	}
	return removed, nil
}

// ---------------------------------------------------------------------------
// Cleanup goroutine
// ---------------------------------------------------------------------------

// StartCleanupLoop runs periodic cleanup in the background.
// It stops when the done channel is closed.
func (wm *WorkspaceManager) StartCleanupLoop(done <-chan struct{}) {
	go func() {
		// Run once on startup.
		wm.runCleanup()

		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				wm.runCleanup()
			}
		}
	}()
}

func (wm *WorkspaceManager) runCleanup() {
	log.Println("cleanup: starting periodic cleanup")

	// 1. Prune artifacts older than 1 hour.
	wm.pruneArtifacts(1 * time.Hour)

	// 2. Prune workspace build/ dirs older than 7 days.
	wm.pruneWorkspaceBuildDirs(7 * 24 * time.Hour)

	// 3. Prune entire workspaces older than 14 days.
	pruned, _ := wm.CleanStaleWorkspaces(14 * 24 * time.Hour)
	if pruned > 0 {
		log.Printf("cleanup: removed %d stale workspaces (>14 days)", pruned)
	}

	log.Println("cleanup: periodic cleanup complete")
}

func (wm *WorkspaceManager) pruneArtifacts(maxAge time.Duration) {
	dir := wm.artifactsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	cutoff := time.Now().Add(-maxAge)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			artPath := filepath.Join(dir, e.Name())
			if err := os.RemoveAll(artPath); err != nil {
				log.Printf("cleanup: failed to remove artifact dir %s: %v", e.Name(), err)
			} else {
				log.Printf("cleanup: removed stale artifact dir %s", e.Name())
			}
		}
	}
}

func (wm *WorkspaceManager) pruneWorkspaceBuildDirs(maxAge time.Duration) {
	dir := wm.workspacesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	cutoff := time.Now().Add(-maxAge)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		buildDir := filepath.Join(dir, e.Name(), "build")
		info, err := os.Stat(buildDir)
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.RemoveAll(buildDir); err != nil {
				log.Printf("cleanup: failed to remove build dir in %s: %v", e.Name(), err)
			} else {
				log.Printf("cleanup: removed stale build dir in workspace %s", e.Name())
			}
		}
	}
}

// ---------------------------------------------------------------------------
// HTTP Handlers
// ---------------------------------------------------------------------------

func (wm *WorkspaceManager) handleListWorkspaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	workspaces, err := wm.ListWorkspaces()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if workspaces == nil {
		workspaces = []WorkspaceInfo{}
	}
	writeJSON(w, http.StatusOK, workspaces)
}

func (wm *WorkspaceManager) handleDeleteWorkspace(w http.ResponseWriter, r *http.Request, hash string) {
	if !isValidHash(hash) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid workspace hash"})
		return
	}

	if err := wm.CleanWorkspace(hash); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "workspace": hash})
}

func (wm *WorkspaceManager) handleDeleteWorkspaces(w http.ResponseWriter, r *http.Request) {
	olderThan := r.URL.Query().Get("older_than")
	if olderThan == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "older_than query parameter required"})
		return
	}

	dur, err := parseDuration(olderThan)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid duration: " + err.Error()})
		return
	}

	removed, err := wm.CleanStaleWorkspaces(dur)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"removed": removed,
	})
}

func (wm *WorkspaceManager) handleWorkspaces(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		wm.handleListWorkspaces(w, r)
	case http.MethodDelete:
		wm.handleDeleteWorkspaces(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleWorkspaceByHash handles /workspaces/<hash> DELETE requests.
func (wm *WorkspaceManager) handleWorkspaceByHash(w http.ResponseWriter, r *http.Request, hash string) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	wm.handleDeleteWorkspace(w, r, hash)
}

