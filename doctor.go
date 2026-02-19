package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// CheckStatus represents the result status of a single doctor check.
type CheckStatus string

const (
	StatusOK   CheckStatus = "ok"
	StatusWarn CheckStatus = "warn"
	StatusFail CheckStatus = "fail"
)

// Check is a single doctor check result.
type Check struct {
	Name    string      `json:"name"`
	Status  CheckStatus `json:"status"`
	Message string      `json:"message"`
	Fixable bool        `json:"fixable"`
}

// DoctorResult is the response from GET /doctor.
type DoctorResult struct {
	Checks  []Check `json:"checks"`
	Summary string  `json:"summary"`
}

// FixResult is the response from POST /doctor/fix.
type FixResult struct {
	Fixes   []Check `json:"fixes"`
	Summary string  `json:"summary"`
}

// DoctorManager runs host-side health checks.
type DoctorManager struct {
	baseDir    string
	configPath string
}

// NewDoctorManager creates a new DoctorManager.
func NewDoctorManager(baseDir, configPath string) *DoctorManager {
	return &DoctorManager{baseDir: baseDir, configPath: configPath}
}

// RunChecks executes all host-side checks.
func (dm *DoctorManager) RunChecks() DoctorResult {
	var checks []Check

	checks = append(checks, dm.checkAndroidHome()...)
	checks = append(checks, dm.checkJava()...)
	checks = append(checks, dm.checkAndroidNDK()...)
	checks = append(checks, dm.checkGradle())
	checks = append(checks, dm.checkBaseDir()...)
	checks = append(checks, dm.checkOrbitalEnv())
	checks = append(checks, dm.checkSharedVolumeToken())

	// Summary.
	ok, warn, fail := 0, 0, 0
	for _, c := range checks {
		switch c.Status {
		case StatusOK:
			ok++
		case StatusWarn:
			warn++
		case StatusFail:
			fail++
		}
	}
	summary := fmt.Sprintf("%d passed, %d warnings, %d failed", ok, warn, fail)

	return DoctorResult{Checks: checks, Summary: summary}
}

// RunFixes attempts to auto-fix known issues.
func (dm *DoctorManager) RunFixes() FixResult {
	var fixes []Check

	// Fix: create missing directories.
	for _, sub := range []string{"workspaces", "artifacts"} {
		dir := filepath.Join(dm.baseDir, sub)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				fixes = append(fixes, Check{
					Name:    fmt.Sprintf("create %s/", sub),
					Status:  StatusFail,
					Message: fmt.Sprintf("failed to create %s: %v", dir, err),
				})
			} else {
				fixes = append(fixes, Check{
					Name:    fmt.Sprintf("create %s/", sub),
					Status:  StatusOK,
					Message: fmt.Sprintf("created %s", dir),
				})
			}
		}
	}

	// Fix: make gradlew executable in all workspaces.
	wsDir := filepath.Join(dm.baseDir, "workspaces")
	entries, err := os.ReadDir(wsDir)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			gw := filepath.Join(wsDir, e.Name(), "gradlew")
			info, err := os.Stat(gw)
			if err != nil {
				continue
			}
			if info.Mode()&0o111 == 0 {
				if err := os.Chmod(gw, info.Mode()|0o755); err == nil {
					fixes = append(fixes, Check{
						Name:    fmt.Sprintf("chmod gradlew in %s", e.Name()),
						Status:  StatusOK,
						Message: "made gradlew executable",
					})
				}
			}
		}
	}

	// Fix: suggest ANDROID_NDK_HOME if not set but NDK is installed.
	if os.Getenv("ANDROID_NDK_HOME") == "" && os.Getenv("ANDROID_NDK") == "" && os.Getenv("NDK_HOME") == "" {
		androidHome := os.Getenv("ANDROID_HOME")
		if androidHome == "" {
			androidHome = findAndroidSDK()
		}
		if androidHome != "" {
			ndkDir := filepath.Join(androidHome, "ndk")
			if entries, err := os.ReadDir(ndkDir); err == nil {
				// Find the latest installed NDK version.
				var latestNDK string
				for _, e := range entries {
					if e.IsDir() && e.Name() != "." {
						latestNDK = e.Name()
					}
				}
				if latestNDK != "" {
					ndkPath := filepath.Join(ndkDir, latestNDK)
					fixes = append(fixes, Check{
						Name:    "NDK discovery",
						Status:  StatusWarn,
						Message: fmt.Sprintf("found NDK at %s — add ANDROID_NDK_HOME=%s to orbital.env config", ndkPath, ndkPath),
					})
				}
			}
		}
	}

	if len(fixes) == 0 {
		fixes = append(fixes, Check{
			Name:    "nothing to fix",
			Status:  StatusOK,
			Message: "all auto-fixable issues already resolved",
		})
	}

	ok, fail2 := 0, 0
	for _, f := range fixes {
		if f.Status == StatusOK {
			ok++
		} else {
			fail2++
		}
	}
	summary := fmt.Sprintf("%d fixed, %d failed", ok, fail2)

	return FixResult{Fixes: fixes, Summary: summary}
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

func (dm *DoctorManager) checkAndroidHome() []Check {
	var checks []Check

	androidHome := os.Getenv("ANDROID_HOME")
	if androidHome == "" {
		checks = append(checks, Check{
			Name:    "ANDROID_HOME",
			Status:  StatusFail,
			Message: "ANDROID_HOME is not set (set it in orbital.env config)",
			Fixable: true,
		})
		return checks
	}

	info, err := os.Stat(androidHome)
	if err != nil || !info.IsDir() {
		checks = append(checks, Check{
			Name:    "ANDROID_HOME",
			Status:  StatusFail,
			Message: fmt.Sprintf("ANDROID_HOME=%s does not exist or is not a directory", androidHome),
		})
		return checks
	}

	checks = append(checks, Check{
		Name:    "ANDROID_HOME",
		Status:  StatusOK,
		Message: androidHome,
	})

	// Check for expected subdirectories.
	for _, sub := range []string{"platform-tools", "platforms", "build-tools"} {
		p := filepath.Join(androidHome, sub)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			checks = append(checks, Check{
				Name:    fmt.Sprintf("ANDROID_HOME/%s", sub),
				Status:  StatusWarn,
				Message: fmt.Sprintf("missing %s — some builds may fail", p),
			})
		} else {
			checks = append(checks, Check{
				Name:    fmt.Sprintf("ANDROID_HOME/%s", sub),
				Status:  StatusOK,
				Message: p,
			})
		}
	}

	return checks
}

func (dm *DoctorManager) checkJava() []Check {
	var checks []Check

	// Check JAVA_HOME.
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome != "" {
		javaBin := filepath.Join(javaHome, "bin", "java")
		if _, err := os.Stat(javaBin); err != nil {
			checks = append(checks, Check{
				Name:    "JAVA_HOME",
				Status:  StatusFail,
				Message: fmt.Sprintf("JAVA_HOME=%s but %s not found", javaHome, javaBin),
			})
			return checks
		}
		checks = append(checks, Check{
			Name:    "JAVA_HOME",
			Status:  StatusOK,
			Message: javaHome,
		})
	}

	// Find java binary.
	javaBin := "java"
	if javaHome != "" {
		javaBin = filepath.Join(javaHome, "bin", "java")
	}

	// Check java version.
	out, err := exec.Command(javaBin, "-version").CombinedOutput()
	if err != nil {
		checks = append(checks, Check{
			Name:    "java",
			Status:  StatusFail,
			Message: "java not found on PATH — install JDK 17+",
		})
		return checks
	}

	version := parseJavaVersion(string(out))
	if version > 0 && version < 17 {
		checks = append(checks, Check{
			Name:    "java version",
			Status:  StatusFail,
			Message: fmt.Sprintf("java %d detected — JDK 17+ required", version),
		})
	} else if version >= 17 {
		checks = append(checks, Check{
			Name:    "java version",
			Status:  StatusOK,
			Message: fmt.Sprintf("JDK %d", version),
		})
	} else {
		checks = append(checks, Check{
			Name:    "java version",
			Status:  StatusWarn,
			Message: fmt.Sprintf("could not parse java version from: %s", strings.TrimSpace(string(out))),
		})
	}

	return checks
}

func (dm *DoctorManager) checkAndroidNDK() []Check {
	var checks []Check

	// Check for NDK home via known env vars.
	ndkHome := os.Getenv("ANDROID_NDK_HOME")
	if ndkHome == "" {
		ndkHome = os.Getenv("ANDROID_NDK")
	}
	if ndkHome == "" {
		ndkHome = os.Getenv("NDK_HOME")
	}

	if ndkHome == "" {
		checks = append(checks, Check{
			Name:    "Android NDK",
			Status:  StatusWarn,
			Message: "ANDROID_NDK_HOME not set (only needed for NDK/cmake builds)",
			Fixable: true,
		})
		return checks
	}

	info, err := os.Stat(ndkHome)
	if err != nil || !info.IsDir() {
		checks = append(checks, Check{
			Name:    "Android NDK",
			Status:  StatusFail,
			Message: fmt.Sprintf("ANDROID_NDK_HOME=%s does not exist or is not a directory", ndkHome),
		})
		return checks
	}

	checks = append(checks, Check{
		Name:    "Android NDK",
		Status:  StatusOK,
		Message: ndkHome,
	})

	// Verify the toolchain cmake file exists.
	toolchain := filepath.Join(ndkHome, "build", "cmake", "android.toolchain.cmake")
	if _, err := os.Stat(toolchain); err != nil {
		checks = append(checks, Check{
			Name:    "NDK toolchain",
			Status:  StatusWarn,
			Message: fmt.Sprintf("android.toolchain.cmake not found at %s", toolchain),
		})
	} else {
		checks = append(checks, Check{
			Name:    "NDK toolchain",
			Status:  StatusOK,
			Message: toolchain,
		})
	}

	return checks
}

func (dm *DoctorManager) checkGradle() Check {
	// Check if gradle user home is writable.
	gradleHome := os.Getenv("GRADLE_USER_HOME")
	if gradleHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Check{Name: "gradle home", Status: StatusWarn, Message: "cannot determine home directory"}
		}
		gradleHome = filepath.Join(home, ".gradle")
	}

	if _, err := os.Stat(gradleHome); os.IsNotExist(err) {
		return Check{
			Name:    "gradle home",
			Status:  StatusWarn,
			Message: fmt.Sprintf("%s does not exist yet (will be created on first build)", gradleHome),
		}
	}

	// Test writability.
	testFile := filepath.Join(gradleHome, ".orbital-write-test")
	if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil {
		return Check{
			Name:    "gradle home",
			Status:  StatusFail,
			Message: fmt.Sprintf("%s is not writable: %v", gradleHome, err),
		}
	}
	os.Remove(testFile)

	return Check{
		Name:    "gradle home",
		Status:  StatusOK,
		Message: gradleHome,
	}
}

func (dm *DoctorManager) checkBaseDir() []Check {
	var checks []Check

	info, err := os.Stat(dm.baseDir)
	if err != nil {
		checks = append(checks, Check{
			Name:    "base directory",
			Status:  StatusFail,
			Message: fmt.Sprintf("%s does not exist", dm.baseDir),
			Fixable: true,
		})
		return checks
	}
	if !info.IsDir() {
		checks = append(checks, Check{
			Name:    "base directory",
			Status:  StatusFail,
			Message: fmt.Sprintf("%s is not a directory", dm.baseDir),
		})
		return checks
	}

	checks = append(checks, Check{
		Name:    "base directory",
		Status:  StatusOK,
		Message: dm.baseDir,
	})

	for _, sub := range []string{"workspaces", "artifacts"} {
		dir := filepath.Join(dm.baseDir, sub)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			checks = append(checks, Check{
				Name:    fmt.Sprintf("%s/", sub),
				Status:  StatusFail,
				Message: fmt.Sprintf("%s does not exist", dir),
				Fixable: true,
			})
		} else {
			// Test writability.
			testFile := filepath.Join(dir, ".orbital-write-test")
			if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil {
				checks = append(checks, Check{
					Name:    fmt.Sprintf("%s/", sub),
					Status:  StatusFail,
					Message: fmt.Sprintf("%s is not writable: %v", dir, err),
				})
			} else {
				os.Remove(testFile)
				checks = append(checks, Check{
					Name:    fmt.Sprintf("%s/", sub),
					Status:  StatusOK,
					Message: dir,
				})
			}
		}
	}

	return checks
}

func (dm *DoctorManager) checkOrbitalEnv() Check {
	if dm.configPath == "" {
		return Check{
			Name:    "config file",
			Status:  StatusWarn,
			Message: "no --config flag provided — using environment defaults",
		}
	}

	if _, err := os.Stat(dm.configPath); os.IsNotExist(err) {
		return Check{
			Name:    "config file",
			Status:  StatusFail,
			Message: fmt.Sprintf("%s not found", dm.configPath),
		}
	}

	return Check{
		Name:    "config file",
		Status:  StatusOK,
		Message: dm.configPath,
	}
}

func (dm *DoctorManager) checkSharedVolumeToken() Check {
	// Write a token file that the client can check to verify the shared volume works.
	tokenFile := filepath.Join(dm.baseDir, ".doctor-token")
	token := fmt.Sprintf("orbital-%d", os.Getpid())
	if err := os.WriteFile(tokenFile, []byte(token), 0o644); err != nil {
		return Check{
			Name:    "shared volume (host write)",
			Status:  StatusFail,
			Message: fmt.Sprintf("cannot write token to %s: %v", tokenFile, err),
		}
	}

	return Check{
		Name:    "shared volume (host write)",
		Status:  StatusOK,
		Message: fmt.Sprintf("wrote token to %s", tokenFile),
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parseJavaVersion extracts the major version number from `java -version` output.
func parseJavaVersion(output string) int {
	// Matches: "17.0.1", "1.8.0_292", "21", etc.
	re := regexp.MustCompile(`"(\d+)(?:\.(\d+))?`)
	matches := re.FindStringSubmatch(output)
	if len(matches) < 2 {
		return 0
	}

	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0
	}

	// Old-style versioning: "1.8" means Java 8.
	if major == 1 && len(matches) >= 3 {
		minor, err := strconv.Atoi(matches[2])
		if err == nil {
			return minor
		}
	}

	return major
}

// findAndroidSDK looks for the Android SDK in common locations.
func findAndroidSDK() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	candidates := []string{
		filepath.Join(home, "Library", "Android", "sdk"),
		filepath.Join(home, "Android", "Sdk"),
		"/opt/android-sdk",
		"/usr/local/share/android-sdk",
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			// Verify it looks like a real SDK.
			if _, err := os.Stat(filepath.Join(c, "platform-tools")); err == nil {
				return c
			}
		}
	}

	return ""
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

func (dm *DoctorManager) handleDoctor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	result := dm.RunChecks()
	writeJSON(w, http.StatusOK, result)
}

func (dm *DoctorManager) handleDoctorFix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	result := dm.RunFixes()
	writeJSON(w, http.StatusOK, result)
}

// handleDoctorToken returns the current token for shared volume verification.
func (dm *DoctorManager) handleDoctorToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenFile := filepath.Join(dm.baseDir, ".doctor-token")
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"token": ""})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"token": string(data)})
}

// handleDoctorVerify accepts a client-written token and verifies it's readable from the host.
func (dm *DoctorManager) handleDoctorVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	tokenFile := filepath.Join(dm.baseDir, ".doctor-client-token")
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"match":   false,
			"message": fmt.Sprintf("cannot read client token file: %v", err),
		})
		return
	}

	match := strings.TrimSpace(string(data)) == strings.TrimSpace(req.Token)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"match":   match,
		"message": map[bool]string{true: "shared volume verified", false: "token mismatch — volume not shared correctly"}[match],
	})
}
