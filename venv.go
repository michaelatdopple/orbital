package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Safe dependency installation
// ---------------------------------------------------------------------------
//
// Container-rsynced requirements files are untrusted input. These functions
// ensure that dependency installation cannot execute arbitrary code:
//
//   pip install --only-binary :all:    → refuses to run setup.py
//   npm install --ignore-scripts       → blocks lifecycle scripts
//
// Without these flags, a malicious requirements.txt or package.json could
// execute arbitrary code on the host during installation.

// SafePipInstallCmd returns an exec.Cmd for pip install that refuses to
// build from source. --only-binary :all: ensures only pre-built wheels are
// accepted; if a package lacks a wheel for the platform, it fails loudly.
// --no-build-isolation prevents setuptools from running in isolation.
func SafePipInstallCmd(pipBin, requirementsPath string) *exec.Cmd {
	return exec.Command(pipBin, "install",
		"--only-binary", ":all:",
		"--no-build-isolation",
		"-r", requirementsPath,
	)
}

// SafeNpmInstallCmd returns an exec.Cmd for npm install that blocks all
// lifecycle scripts (preinstall, postinstall, etc.).
func SafeNpmInstallCmd(prefix string) *exec.Cmd {
	return exec.Command("npm", "install",
		"--ignore-scripts",
		"--prefix", prefix,
	)
}

// ---------------------------------------------------------------------------
// Venv path computation
// ---------------------------------------------------------------------------

// VenvPath computes the cache path for a Python venv based on the workspace
// hash and the content hash of the requirements file. This provides:
//   - Cache reuse: same requirements → same venv (fast path)
//   - Cache invalidation: changed requirements → new venv
//   - 48-bit collision resistance via SHA-256 truncation
func VenvPath(baseDir, workspaceHash, requirementsContent string) string {
	h := sha256.Sum256([]byte(requirementsContent))
	reqHash := hex.EncodeToString(h[:])[:12]
	return filepath.Join(baseDir, "venvs", workspaceHash+"-"+reqHash)
}

// NodeModulesPath computes the cache path for a Node.js node_modules based on
// the workspace hash and package.json content hash.
func NodeModulesPath(baseDir, workspaceHash, packageJsonContent string) string {
	h := sha256.Sum256([]byte(packageJsonContent))
	pkgHash := hex.EncodeToString(h[:])[:12]
	return filepath.Join(baseDir, "node_modules_cache", workspaceHash+"-"+pkgHash)
}

// VenvExists checks if a venv at the given path is ready to use.
func VenvExists(venvDir string) bool {
	activate := filepath.Join(venvDir, "bin", "activate")
	_, err := os.Stat(activate)
	return err == nil
}

// CreateVenv creates a new Python venv at the given path.
func CreateVenv(venvDir string) error {
	cmd := exec.Command("python3", "-m", "venv", venvDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("venv creation failed: %s: %w", string(out), err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// VenvManager
// ---------------------------------------------------------------------------

// VenvManager manages cached Python venvs and Node.js node_modules for
// compute jobs. Venvs are keyed by workspace hash + requirements content hash,
// providing cache reuse across identical requirement sets and automatic
// invalidation when requirements change.
type VenvManager struct {
	BaseDir string // root dir (e.g. ~/orbital-data)
}

// NewVenvManager creates a VenvManager.
func NewVenvManager(baseDir string) *VenvManager {
	return &VenvManager{BaseDir: baseDir}
}

func (vm *VenvManager) venvsDir() string {
	return filepath.Join(vm.BaseDir, "venvs")
}

func (vm *VenvManager) nodeModulesDir() string {
	return filepath.Join(vm.BaseDir, "node_modules_cache")
}

// EnsureVenv returns a ready-to-use venv path for the given workspace and
// requirements file. On cache hit, returns immediately. On cache miss,
// creates a new venv and installs dependencies with safe flags.
//
// The logFn callback receives progress messages for SSE streaming.
func (vm *VenvManager) EnsureVenv(workspaceHash, reqFilePath string, logFn func(string)) (string, error) {
	// Read and hash requirements content.
	content, err := os.ReadFile(reqFilePath)
	if err != nil {
		return "", fmt.Errorf("cannot read requirements file: %w", err)
	}

	venvDir := VenvPath(vm.BaseDir, workspaceHash, string(content))

	// Cache hit: venv exists and has bin/activate.
	if VenvExists(venvDir) {
		logFn(fmt.Sprintf("Venv cache hit: %s", filepath.Base(venvDir)))
		return venvDir, nil
	}

	logFn(fmt.Sprintf("Venv cache miss, creating: %s", filepath.Base(venvDir)))

	// Ensure parent directory exists.
	if err := os.MkdirAll(vm.venvsDir(), 0o775); err != nil {
		return "", fmt.Errorf("cannot create venvs dir: %w", err)
	}

	// Create the venv.
	if err := CreateVenv(venvDir); err != nil {
		// Clean up partial venv on failure.
		os.RemoveAll(venvDir)
		return "", err
	}

	// Install dependencies with safe flags.
	pipBin := filepath.Join(venvDir, "bin", "pip")
	installCmd := SafePipInstallCmd(pipBin, reqFilePath)
	installCmd.Dir = filepath.Dir(reqFilePath)

	logFn("Installing Python dependencies (--only-binary :all:)...")
	out, err := installCmd.CombinedOutput()
	if len(out) > 0 {
		for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
			logFn(line)
		}
	}
	if err != nil {
		// Clean up failed venv so it doesn't poison cache.
		os.RemoveAll(venvDir)
		return "", fmt.Errorf("pip install failed: %w", err)
	}

	logFn("Venv ready")
	return venvDir, nil
}

// EnsureNodeModules returns a ready-to-use node_modules path for the given
// workspace and package.json. Same cache semantics as EnsureVenv.
func (vm *VenvManager) EnsureNodeModules(workspaceHash, packageJsonPath string, logFn func(string)) (string, error) {
	content, err := os.ReadFile(packageJsonPath)
	if err != nil {
		return "", fmt.Errorf("cannot read package.json: %w", err)
	}

	nmDir := NodeModulesPath(vm.BaseDir, workspaceHash, string(content))

	// Cache hit: node_modules exists.
	nmPath := filepath.Join(nmDir, "node_modules")
	if info, err := os.Stat(nmPath); err == nil && info.IsDir() {
		logFn(fmt.Sprintf("node_modules cache hit: %s", filepath.Base(nmDir)))
		return nmDir, nil
	}

	logFn(fmt.Sprintf("node_modules cache miss, installing: %s", filepath.Base(nmDir)))

	if err := os.MkdirAll(nmDir, 0o775); err != nil {
		return "", fmt.Errorf("cannot create node_modules cache dir: %w", err)
	}

	// Copy package.json into the cache dir for npm install.
	dstPkg := filepath.Join(nmDir, "package.json")
	if err := copyFile(packageJsonPath, dstPkg); err != nil {
		return "", fmt.Errorf("cannot copy package.json: %w", err)
	}

	installCmd := SafeNpmInstallCmd(nmDir)
	logFn("Installing Node.js dependencies (--ignore-scripts)...")
	out, err := installCmd.CombinedOutput()
	if len(out) > 0 {
		for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
			logFn(line)
		}
	}
	if err != nil {
		os.RemoveAll(nmDir)
		return "", fmt.Errorf("npm install failed: %w", err)
	}

	logFn("node_modules ready")
	return nmDir, nil
}

// PruneStaleVenvs removes venvs that haven't been modified in 14 days.
// Called from the workspace cleanup loop.
func (vm *VenvManager) PruneStaleVenvs() {
	vm.pruneDir(vm.venvsDir(), "venv")
}

// PruneStaleNodeModules removes node_modules caches older than maxAge.
func (vm *VenvManager) PruneStaleNodeModules() {
	vm.pruneDir(vm.nodeModulesDir(), "node_modules")
}

func (vm *VenvManager) pruneDir(dir, label string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		// 14 days staleness threshold.
		if daysOld(info) > 14 {
			path := filepath.Join(dir, e.Name())
			if err := os.RemoveAll(path); err != nil {
				log.Printf("cleanup: failed to remove stale %s cache %s: %v", label, e.Name(), err)
			} else {
				log.Printf("cleanup: removed stale %s cache %s (>14 days)", label, e.Name())
			}
		}
	}
}

func daysOld(info os.FileInfo) int {
	age := time.Since(info.ModTime())
	return int(age.Hours() / 24)
}
