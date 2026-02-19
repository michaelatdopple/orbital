package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// BuildStatus represents the current state of a build.
type BuildStatus string

const (
	StatusBuilding  BuildStatus = "building"
	StatusSuccess   BuildStatus = "success"
	StatusFailed    BuildStatus = "failed"
	StatusCancelled BuildStatus = "cancelled"
)

// LogLine is a single captured output line with a timestamp.
type LogLine struct {
	Line string    `json:"line"`
	Ts   time.Time `json:"ts"`
}

// DepSpec describes a git dependency to resolve before building.
type DepSpec struct {
	Git string `json:"git"`
	Ref string `json:"ref"`
}

// Build holds all state for a single build invocation.
type Build struct {
	ID           string              `json:"id"`
	Status       BuildStatus         `json:"status"`
	Workspace    string              `json:"workspace"`
	Tasks        []string            `json:"tasks"`
	Properties   []string            `json:"properties,omitempty"`
	Container    string              `json:"container,omitempty"`
	PreBuild     []string            `json:"pre_build,omitempty"`
	BuildType    string              `json:"build_type,omitempty"`
	BuildScript  string              `json:"build_script,omitempty"`
	Deps           map[string]DepSpec  `json:"deps,omitempty"`
	ArtifactDirs   []string            `json:"artifact_dirs,omitempty"`
	SigningProfile string              `json:"signing_profile,omitempty"`
	ExitCode       int                 `json:"exit_code"`
	StartedAt    time.Time           `json:"started_at"`
	FinishedAt   time.Time           `json:"finished_at,omitempty"`
	ArtifactDir  string              `json:"artifact_dir"`
	Artifacts    []string            `json:"artifacts,omitempty"`

	cmd         *exec.Cmd
	mu          sync.Mutex
	logs        []LogLine
	subscribers []chan LogLine
	done        chan struct{}
}

const maxLogLines = 10000

// addLogLine appends a line to the ring buffer and notifies SSE subscribers.
func (b *Build) addLogLine(line string) {
	b.mu.Lock()
	entry := LogLine{Line: line, Ts: time.Now()}
	if len(b.logs) >= maxLogLines {
		b.logs = b.logs[1:]
	}
	b.logs = append(b.logs, entry)
	// Copy subscriber slice so we can unlock before sending.
	subs := make([]chan LogLine, len(b.subscribers))
	copy(subs, b.subscribers)
	b.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- entry:
		default:
			// Slow subscriber — drop the line rather than blocking the build.
		}
	}
}

// subscribe returns a channel that receives new log lines and a snapshot of
// all lines captured so far.
func (b *Build) subscribe() (existing []LogLine, ch chan LogLine) {
	b.mu.Lock()
	defer b.mu.Unlock()
	existing = make([]LogLine, len(b.logs))
	copy(existing, b.logs)
	ch = make(chan LogLine, 256)
	b.subscribers = append(b.subscribers, ch)
	return existing, ch
}

// unsubscribe removes a subscriber channel.
func (b *Build) unsubscribe(ch chan LogLine) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, s := range b.subscribers {
		if s == ch {
			b.subscribers = append(b.subscribers[:i], b.subscribers[i+1:]...)
			break
		}
	}
}

// ---------------------------------------------------------------------------
// BuildManager
// ---------------------------------------------------------------------------

// BuildManager owns the in-memory map of all builds.
type BuildManager struct {
	mu      sync.RWMutex
	builds  map[string]*Build
	baseDir string
	policy  *SecurityPolicy
	limiter *BuildLimiter
	audit   *AuditLogger
}

// NewBuildManager creates a new manager rooted at baseDir with security policy.
func NewBuildManager(baseDir string, policy *SecurityPolicy, audit *AuditLogger) *BuildManager {
	return &BuildManager{
		builds:  make(map[string]*Build),
		baseDir: baseDir,
		policy:  policy,
		limiter: NewBuildLimiter(policy.MaxConcurrentBuilds),
		audit:   audit,
	}
}

// Get returns a build by ID.
func (bm *BuildManager) Get(id string) *Build {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.builds[id]
}

// List returns a snapshot of all builds.
func (bm *BuildManager) List() []*Build {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	out := make([]*Build, 0, len(bm.builds))
	for _, b := range bm.builds {
		out = append(out, b)
	}
	return out
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

var validHash = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
var validBuildID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func isValidHash(s string) bool {
	return len(s) > 0 && len(s) <= 128 && validHash.MatchString(s)
}

func isValidBuildID(s string) bool {
	return len(s) > 0 && len(s) <= 128 && validBuildID.MatchString(s)
}

// safeSubpath validates that joining baseDir + name stays under baseDir.
func safeSubpath(baseDir, name string) (string, error) {
	joined := filepath.Join(baseDir, name)
	abs, err := filepath.Abs(joined)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}
	base, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("invalid base: %w", err)
	}
	if !strings.HasPrefix(abs, base+string(filepath.Separator)) && abs != base {
		return "", fmt.Errorf("path traversal blocked")
	}
	return abs, nil
}

// ---------------------------------------------------------------------------
// Build request
// ---------------------------------------------------------------------------

// BuildRequest is the JSON body for POST /build.
type BuildRequest struct {
	Workspace    string             `json:"workspace"`
	Tasks        []string           `json:"tasks"`
	Properties   map[string]string  `json:"properties,omitempty"`
	Container    string             `json:"container,omitempty"`
	PreBuild     []string           `json:"pre_build,omitempty"`
	BuildType    string             `json:"build_type,omitempty"`
	BuildScript  string             `json:"build_script,omitempty"`
	Deps           map[string]DepSpec `json:"deps,omitempty"`
	ArtifactDirs   []string           `json:"artifact_dirs,omitempty"`
	SigningProfile string             `json:"signing_profile,omitempty"`
}

// ---------------------------------------------------------------------------
// StartBuild
// ---------------------------------------------------------------------------

func (bm *BuildManager) StartBuild(req BuildRequest) (*Build, error) {
	// Validate workspace hash.
	if !isValidHash(req.Workspace) {
		return nil, fmt.Errorf("invalid workspace hash: must be alphanumeric/dash/underscore")
	}

	// Default build type to "gradle".
	buildType := req.BuildType
	if buildType == "" {
		buildType = "gradle"
	}
	if buildType != "gradle" && buildType != "script" {
		return nil, fmt.Errorf("invalid build_type %q: must be \"gradle\" or \"script\"", buildType)
	}

	// Type-specific validation.
	switch buildType {
	case "gradle":
		if len(req.Tasks) == 0 {
			return nil, fmt.Errorf("at least one task is required")
		}

		// --- Security: validate tasks ---
		if err := bm.policy.ValidateTasks(req.Tasks); err != nil {
			bm.audit.Log("build_rejected", map[string]string{
				"reason":    "invalid_task",
				"workspace": req.Workspace,
				"error":     err.Error(),
			})
			return nil, err
		}

		// --- Security: validate properties ---
		if err := bm.policy.ValidateProperties(req.Properties); err != nil {
			bm.audit.Log("build_rejected", map[string]string{
				"reason":    "blocked_property",
				"workspace": req.Workspace,
				"error":     err.Error(),
			})
			return nil, err
		}

	case "script":
		if req.BuildScript == "" {
			return nil, fmt.Errorf("build_script is required for script builds")
		}
		// Block path traversal in script path.
		if strings.Contains(req.BuildScript, "..") {
			return nil, fmt.Errorf("build_script must not contain '..'")
		}
	}

	// --- Security: validate deps ---
	if len(req.Deps) > 0 {
		if err := bm.policy.ValidateDeps(req.Deps); err != nil {
			bm.audit.Log("build_rejected", map[string]string{
				"reason":    "invalid_dep",
				"workspace": req.Workspace,
				"error":     err.Error(),
			})
			return nil, err
		}
	}

	// --- Security: validate artifact dirs ---
	if len(req.ArtifactDirs) > 0 {
		if err := bm.policy.ValidateArtifactDirs(req.ArtifactDirs); err != nil {
			bm.audit.Log("build_rejected", map[string]string{
				"reason":    "invalid_artifact_dir",
				"workspace": req.Workspace,
				"error":     err.Error(),
			})
			return nil, err
		}
	}

	// --- Security: validate signing profile ---
	if req.SigningProfile != "" {
		if _, err := bm.policy.ResolveSigningProfile(req.SigningProfile); err != nil {
			bm.audit.Log("build_rejected", map[string]string{
				"reason":    "invalid_signing_profile",
				"workspace": req.Workspace,
				"error":     err.Error(),
			})
			return nil, err
		}
	}

	// --- Security: validate pre-build commands ---
	if err := bm.policy.ValidatePreBuild(req.PreBuild); err != nil {
		bm.audit.Log("build_rejected", map[string]string{
			"reason":    "blocked_prebuild",
			"workspace": req.Workspace,
			"error":     err.Error(),
		})
		return nil, err
	}

	// --- Security: concurrency limit ---
	if err := bm.limiter.Acquire(); err != nil {
		return nil, err
	}

	// Convert properties map to CLI args (e.g. {"-Pkey": "value"} -> ["-Pkey=value"]).
	var propArgs []string
	for k, v := range req.Properties {
		if !strings.HasPrefix(k, "-") {
			bm.limiter.Release()
			return nil, fmt.Errorf("invalid property key %q: must start with -", k)
		}
		if v != "" {
			propArgs = append(propArgs, k+"="+v)
		} else {
			propArgs = append(propArgs, k)
		}
	}

	// Resolve workspace path with traversal protection.
	wsDir, err := safeSubpath(filepath.Join(bm.baseDir, "workspaces"), req.Workspace)
	if err != nil {
		bm.limiter.Release()
		return nil, fmt.Errorf("workspace path error: %w", err)
	}

	// --- Security: check for symlink escapes ---
	if err := bm.policy.CheckSymlinks(wsDir); err != nil {
		bm.limiter.Release()
		bm.audit.Log("build_rejected", map[string]string{
			"reason":    "symlink_escape",
			"workspace": req.Workspace,
			"error":     err.Error(),
		})
		return nil, err
	}

	// Type-specific executable validation.
	switch buildType {
	case "gradle":
		// Verify gradlew exists.
		gradlew := filepath.Join(wsDir, "gradlew")
		if _, err := os.Stat(gradlew); err != nil {
			bm.limiter.Release()
			return nil, fmt.Errorf("gradlew not found in workspace %s: %w", req.Workspace, err)
		}

		// --- Security: verify Gradle wrapper checksum ---
		if err := bm.policy.VerifyGradleWrapper(wsDir); err != nil {
			bm.limiter.Release()
			bm.audit.Log("build_rejected", map[string]string{
				"reason":    "wrapper_checksum",
				"workspace": req.Workspace,
				"error":     err.Error(),
			})
			return nil, err
		}

	case "script":
		// Verify the build script exists and is executable.
		scriptPath, err := safeSubpath(wsDir, req.BuildScript)
		if err != nil {
			bm.limiter.Release()
			return nil, fmt.Errorf("build script path error: %w", err)
		}
		info, err := os.Stat(scriptPath)
		if err != nil {
			bm.limiter.Release()
			return nil, fmt.Errorf("build script not found: %s", req.BuildScript)
		}
		if info.Mode()&0o111 == 0 {
			bm.limiter.Release()
			return nil, fmt.Errorf("build script is not executable: %s", req.BuildScript)
		}
	}

	// Generate build ID.
	id := fmt.Sprintf("%d", time.Now().UnixNano())

	// Audit log the build start.
	bm.audit.Log("build_started", map[string]string{
		"id":         id,
		"workspace":  req.Workspace,
		"build_type": buildType,
		"tasks":      strings.Join(req.Tasks, ","),
		"container":  req.Container,
	})

	// Create artifact directory.
	artifactDir := filepath.Join(bm.baseDir, "artifacts", id, "out")
	if err := os.MkdirAll(artifactDir, 0o775); err != nil {
		return nil, fmt.Errorf("failed to create artifact dir: %w", err)
	}

	build := &Build{
		ID:           id,
		Status:       StatusBuilding,
		Workspace:    req.Workspace,
		Tasks:        req.Tasks,
		Properties:   propArgs,
		Container:    req.Container,
		PreBuild:     req.PreBuild,
		BuildType:    buildType,
		BuildScript:  req.BuildScript,
		Deps:           req.Deps,
		ArtifactDirs:   req.ArtifactDirs,
		SigningProfile: req.SigningProfile,
		StartedAt:      time.Now(),
		ArtifactDir:  filepath.Join("orbital", "artifacts", id, "out"),
		done:         make(chan struct{}),
	}

	bm.mu.Lock()
	bm.builds[id] = build
	bm.mu.Unlock()

	// Spawn the build in the background.
	go bm.runBuild(build, wsDir, artifactDir)

	return build, nil
}

// resolveDeps clones or fetches git dependencies into a shared cache and returns
// environment variable assignments (KEY=/path/to/dep) for injection into the build.
func (bm *BuildManager) resolveDeps(b *Build) ([]string, error) {
	if len(b.Deps) == 0 {
		return nil, nil
	}

	depsDir := filepath.Join(bm.baseDir, "deps")
	if err := os.MkdirAll(depsDir, 0o775); err != nil {
		return nil, fmt.Errorf("failed to create deps dir: %w", err)
	}

	var envVars []string
	for name, dep := range b.Deps {
		h := sha256.Sum256([]byte(dep.Git))
		hash := hex.EncodeToString(h[:])[:16]
		depDir := filepath.Join(depsDir, hash)
		lockPath := filepath.Join(depsDir, hash+".lock")

		b.addLogLine(fmt.Sprintf("Resolving dep %s: %s#%s → %s", name, dep.Git, dep.Ref, depDir))

		if err := resolveOneDep(dep, depDir, lockPath, b); err != nil {
			return nil, fmt.Errorf("dep %s: %w", name, err)
		}

		envVars = append(envVars, name+"="+depDir)
	}
	return envVars, nil
}

// resolveOneDep clones or fetches a single git dependency under flock.
func resolveOneDep(dep DepSpec, depDir, lockPath string, b *Build) error {
	// Acquire file lock.
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o664)
	if err != nil {
		return fmt.Errorf("cannot create lock file: %w", err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("cannot acquire lock: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	needsClone := false
	if _, err := os.Stat(filepath.Join(depDir, ".git")); os.IsNotExist(err) {
		needsClone = true
	}

	if needsClone {
		b.addLogLine(fmt.Sprintf("  Cloning %s ...", dep.Git))
		out, err := exec.Command("git", "clone", "--no-checkout", dep.Git, depDir).CombinedOutput()
		if err != nil {
			return fmt.Errorf("git clone failed: %s: %w", strings.TrimSpace(string(out)), err)
		}
	}

	// Fetch the requested ref.
	b.addLogLine(fmt.Sprintf("  Fetching ref %s ...", dep.Ref))
	fetchCmd := exec.Command("git", "-C", depDir, "fetch", "origin", dep.Ref)
	fetchOut, fetchErr := fetchCmd.CombinedOutput()
	if fetchErr != nil {
		if !needsClone {
			// Cached repo might be corrupt — delete and retry clone once.
			b.addLogLine("  Fetch failed on cached repo, re-cloning...")
			_ = os.RemoveAll(depDir)
			cloneOut, cloneErr := exec.Command("git", "clone", "--no-checkout", dep.Git, depDir).CombinedOutput()
			if cloneErr != nil {
				return fmt.Errorf("git clone (retry) failed: %s: %w", strings.TrimSpace(string(cloneOut)), cloneErr)
			}
			fetchCmd2 := exec.Command("git", "-C", depDir, "fetch", "origin", dep.Ref)
			fetchOut2, fetchErr2 := fetchCmd2.CombinedOutput()
			if fetchErr2 != nil {
				return fmt.Errorf("git fetch (retry) failed: %s: %w", strings.TrimSpace(string(fetchOut2)), fetchErr2)
			}
		} else {
			return fmt.Errorf("git fetch failed: %s: %w", strings.TrimSpace(string(fetchOut)), fetchErr)
		}
	}

	// Checkout FETCH_HEAD.
	checkoutCmd := exec.Command("git", "-C", depDir, "checkout", "FETCH_HEAD")
	checkoutOut, checkoutErr := checkoutCmd.CombinedOutput()
	if checkoutErr != nil {
		return fmt.Errorf("git checkout failed: %s: %w", strings.TrimSpace(string(checkoutOut)), checkoutErr)
	}

	b.addLogLine(fmt.Sprintf("  Dep %s ready", dep.Git))
	return nil
}

// runBuild executes pre-build commands then gradlew and captures output.
func (bm *BuildManager) runBuild(b *Build, wsDir, artifactDir string) {
	defer close(b.done)
	defer bm.limiter.Release()

	// Run pre-build commands (e.g. npm install, yarn install).
	for i, cmdStr := range b.PreBuild {
		b.addLogLine(fmt.Sprintf("Pre-build [%d/%d]: %s", i+1, len(b.PreBuild), cmdStr))

		preCmd := exec.Command("sh", "-c", cmdStr)
		preCmd.Dir = wsDir
		preCmd.Env = os.Environ()

		preOut, err := preCmd.CombinedOutput()
		if len(preOut) > 0 {
			for _, line := range strings.Split(strings.TrimRight(string(preOut), "\n"), "\n") {
				b.addLogLine(line)
			}
		}
		if err != nil {
			b.addLogLine(fmt.Sprintf("Pre-build failed: %v", err))
			b.mu.Lock()
			b.Status = StatusFailed
			b.ExitCode = 1
			b.FinishedAt = time.Now()
			b.mu.Unlock()
			return
		}
	}

	// Resolve git dependencies (script builds only).
	var depEnv []string
	if len(b.Deps) > 0 {
		var depErr error
		depEnv, depErr = bm.resolveDeps(b)
		if depErr != nil {
			b.addLogLine(fmt.Sprintf("ERROR: dependency resolution failed: %v", depErr))
			b.mu.Lock()
			b.Status = StatusFailed
			b.ExitCode = 1
			b.FinishedAt = time.Now()
			b.mu.Unlock()
			return
		}
	}

	var cmd *exec.Cmd
	switch b.BuildType {
	case "script":
		cmd = exec.Command(filepath.Join(wsDir, b.BuildScript))
		cmd.Dir = wsDir
	default: // "gradle"
		args := make([]string, 0, len(b.Tasks)+len(b.Properties))
		args = append(args, b.Tasks...)
		args = append(args, b.Properties...)
		cmd = exec.Command(filepath.Join(wsDir, "gradlew"), args...)
		cmd.Dir = wsDir
	}

	// Resolve signing profile env vars.
	var signingEnv []string
	if b.SigningProfile != "" {
		var sigErr error
		signingEnv, sigErr = bm.policy.ResolveSigningProfile(b.SigningProfile)
		if sigErr != nil {
			b.addLogLine(fmt.Sprintf("ERROR: signing profile resolution failed: %v", sigErr))
			b.mu.Lock()
			b.Status = StatusFailed
			b.ExitCode = 1
			b.FinishedAt = time.Now()
			b.mu.Unlock()
			return
		}
		b.addLogLine(fmt.Sprintf("Signing profile %q: keystore loaded", b.SigningProfile))
	}

	// Propagate environment, including resolved dep paths and signing config.
	cmd.Env = append(os.Environ(), depEnv...)
	cmd.Env = append(cmd.Env, signingEnv...)

	// Use a process group so we can kill the whole tree.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Combine stdout and stderr.
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		b.mu.Lock()
		b.Status = StatusFailed
		b.ExitCode = -1
		b.FinishedAt = time.Now()
		b.mu.Unlock()
		b.addLogLine(fmt.Sprintf("ERROR: failed to create stdout pipe: %v", err))
		return
	}
	cmd.Stderr = cmd.Stdout // merge stderr into stdout pipe

	b.mu.Lock()
	b.cmd = cmd
	b.mu.Unlock()

	if err := cmd.Start(); err != nil {
		b.mu.Lock()
		b.Status = StatusFailed
		b.ExitCode = -1
		b.FinishedAt = time.Now()
		b.mu.Unlock()
		b.addLogLine(fmt.Sprintf("ERROR: failed to start gradlew: %v", err))
		return
	}

	switch b.BuildType {
	case "script":
		b.addLogLine(fmt.Sprintf("Started build %s: script %s", b.ID, b.BuildScript))
	default:
		b.addLogLine(fmt.Sprintf("Started build %s: gradlew %s", b.ID, strings.Join(cmd.Args[1:], " ")))
	}

	// --- Security: enforce build timeout ---
	timeout := bm.policy.MaxBuildDuration
	if timeout > 0 {
		timer := time.AfterFunc(timeout, func() {
			b.addLogLine(fmt.Sprintf("BUILD TIMEOUT: exceeded %s — killing process", timeout))
			bm.audit.Log("build_timeout", map[string]string{
				"id":        b.ID,
				"workspace": b.Workspace,
				"timeout":   timeout.String(),
			})
			pgid, err := syscall.Getpgid(cmd.Process.Pid)
			if err == nil {
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			} else {
				_ = cmd.Process.Kill()
			}
		})
		defer timer.Stop()
	}

	// Read output line by line.
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	for {
		n, readErr := pipe.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			// Flush complete lines.
			for {
				idx := -1
				for i, c := range buf {
					if c == '\n' {
						idx = i
						break
					}
				}
				if idx < 0 {
					break
				}
				line := string(buf[:idx])
				buf = buf[idx+1:]
				b.addLogLine(line)
			}
		}
		if readErr != nil {
			break
		}
	}
	// Flush any remaining partial line.
	if len(buf) > 0 {
		b.addLogLine(string(buf))
	}

	err = cmd.Wait()

	b.mu.Lock()
	b.FinishedAt = time.Now()
	if err != nil {
		if b.Status == StatusCancelled {
			// Already set by CancelBuild.
			b.mu.Unlock()
		} else {
			b.Status = StatusFailed
			if exitErr, ok := err.(*exec.ExitError); ok {
				b.ExitCode = exitErr.ExitCode()
			} else {
				b.ExitCode = -1
			}
			b.mu.Unlock()
		}
	} else {
		b.Status = StatusSuccess
		b.ExitCode = 0
		b.mu.Unlock()
	}

	// Audit log the build completion.
	bm.audit.Log("build_finished", map[string]string{
		"id":        b.ID,
		"workspace": b.Workspace,
		"status":    string(b.Status),
		"exit_code": fmt.Sprintf("%d", b.ExitCode),
		"duration":  b.FinishedAt.Sub(b.StartedAt).String(),
	})

	// Collect artifacts (APKs and other outputs).
	bm.collectArtifacts(b, wsDir, artifactDir)

	// Close subscriber channels.
	b.mu.Lock()
	for _, ch := range b.subscribers {
		close(ch)
	}
	b.subscribers = nil
	b.mu.Unlock()
}

// collectArtifacts copies build outputs from the workspace to the artifact dir.
// If b.ArtifactDirs is set, those dirs are scanned instead of the default
// Gradle build/outputs paths.
func (bm *BuildManager) collectArtifacts(b *Build, wsDir, artifactDir string) {
	var outputDirs []string

	if len(b.ArtifactDirs) > 0 {
		// Use explicitly specified artifact directories.
		for _, relDir := range b.ArtifactDirs {
			absDir, err := safeSubpath(wsDir, relDir)
			if err != nil {
				continue
			}
			if dirExists(absDir) {
				outputDirs = append(outputDirs, absDir)
			}
		}
	} else {
		// Default Gradle behavior: scan build/outputs.
		if dir := filepath.Join(wsDir, "build", "outputs"); dirExists(dir) {
			outputDirs = append(outputDirs, dir)
		}
		// Submodule build/outputs: scan top-level subdirectories only.
		entries, err := os.ReadDir(wsDir)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
					continue
				}
				if dir := filepath.Join(wsDir, e.Name(), "build", "outputs"); dirExists(dir) {
					outputDirs = append(outputDirs, dir)
				}
			}
		}
	}

	if len(outputDirs) == 0 {
		return
	}

	// When using explicit artifact dirs, preserve the full path relative to
	// the workspace root so that directory structure (e.g. dist/android/jniLibs/arm64-v8a/)
	// is maintained in the artifact output.
	relBase := ""
	if len(b.ArtifactDirs) > 0 {
		relBase = wsDir
	}

	var artifacts []string
	for _, outputsDir := range outputDirs {
		base := outputsDir
		if relBase != "" {
			base = relBase
		}
		_ = filepath.Walk(outputsDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(info.Name()))
			if ext == ".apk" || ext == ".aab" || ext == ".aar" || ext == ".so" {
				relPath, err := filepath.Rel(base, path)
				if err != nil {
					return nil
				}
				dst := filepath.Join(artifactDir, relPath)
				if err := os.MkdirAll(filepath.Dir(dst), 0o775); err != nil {
					return nil
				}
				if copyFile(path, dst) == nil {
					artifacts = append(artifacts, relPath)
				}
			}
			return nil
		})
	}

	b.mu.Lock()
	b.Artifacts = artifacts
	b.mu.Unlock()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

// ---------------------------------------------------------------------------
// CancelBuild
// ---------------------------------------------------------------------------

func (bm *BuildManager) CancelBuild(id string) error {
	b := bm.Get(id)
	if b == nil {
		return fmt.Errorf("build not found")
	}

	b.mu.Lock()
	if b.Status != StatusBuilding {
		b.mu.Unlock()
		return fmt.Errorf("build is not running (status: %s)", b.Status)
	}
	b.Status = StatusCancelled
	cmd := b.cmd
	b.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}

	// Send SIGTERM to process group.
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
	} else {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}

	// Wait up to 10 seconds, then SIGKILL.
	select {
	case <-b.done:
		return nil
	case <-time.After(10 * time.Second):
		if pgid != 0 {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		} else {
			_ = cmd.Process.Kill()
		}
		<-b.done
		return nil
	}
}

// ---------------------------------------------------------------------------
// HTTP Handlers
// ---------------------------------------------------------------------------

func (bm *BuildManager) handleStartBuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	build, err := bm.StartBuild(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"id":           build.ID,
		"status":       build.Status,
		"workspace":    build.Workspace,
		"logs_url":     fmt.Sprintf("/build/%s/logs", build.ID),
		"artifact_dir": build.ArtifactDir,
	})
}

func (bm *BuildManager) handleGetBuild(w http.ResponseWriter, _ *http.Request, id string) {
	if !isValidBuildID(id) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid build ID"})
		return
	}

	b := bm.Get(id)
	if b == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "build not found"})
		return
	}

	b.mu.Lock()
	resp := map[string]interface{}{
		"id":           b.ID,
		"status":       b.Status,
		"workspace":    b.Workspace,
		"exit_code":    b.ExitCode,
		"started_at":   b.StartedAt.Format(time.RFC3339),
		"artifact_dir": b.ArtifactDir,
		"artifacts":    b.Artifacts,
	}
	if !b.FinishedAt.IsZero() {
		resp["finished_at"] = b.FinishedAt.Format(time.RFC3339)
	}
	b.mu.Unlock()

	writeJSON(w, http.StatusOK, resp)
}

func (bm *BuildManager) handleGetBuildLogs(w http.ResponseWriter, r *http.Request, id string) {
	if !isValidBuildID(id) {
		http.Error(w, "invalid build ID", http.StatusBadRequest)
		return
	}

	b := bm.Get(id)
	if b == nil {
		http.Error(w, "build not found", http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	existing, ch := b.subscribe()
	defer b.unsubscribe(ch)

	// Send buffered lines.
	for _, entry := range existing {
		data, _ := json.Marshal(map[string]string{
			"line": entry.Line,
			"ts":   entry.Ts.Format(time.RFC3339Nano),
		})
		fmt.Fprintf(w, "data: %s\n\n", data)
	}
	flusher.Flush()

	// Check if already done before entering the loop.
	b.mu.Lock()
	isDone := b.Status != StatusBuilding
	status := b.Status
	artifacts := b.Artifacts
	b.mu.Unlock()

	if isDone {
		sendCompleteEvent(w, status, artifacts)
		flusher.Flush()
		return
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-ch:
			if !ok {
				// Channel closed — build finished.
				b.mu.Lock()
				status = b.Status
				artifacts = b.Artifacts
				b.mu.Unlock()
				sendCompleteEvent(w, status, artifacts)
				flusher.Flush()
				return
			}
			data, _ := json.Marshal(map[string]string{
				"line": entry.Line,
				"ts":   entry.Ts.Format(time.RFC3339Nano),
			})
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func sendCompleteEvent(w http.ResponseWriter, status BuildStatus, artifacts []string) {
	data, _ := json.Marshal(map[string]interface{}{
		"event":     "complete",
		"status":    status,
		"artifacts": artifacts,
	})
	fmt.Fprintf(w, "data: %s\n\n", data)
}

func (bm *BuildManager) handleCancelBuild(w http.ResponseWriter, _ *http.Request, id string) {
	if !isValidBuildID(id) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid build ID"})
		return
	}

	if err := bm.CancelBuild(id); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

func (bm *BuildManager) handleListBuilds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	builds := bm.List()
	result := make([]map[string]interface{}, 0, len(builds))
	for _, b := range builds {
		b.mu.Lock()
		entry := map[string]interface{}{
			"id":         b.ID,
			"status":     b.Status,
			"workspace":  b.Workspace,
			"started_at": b.StartedAt.Format(time.RFC3339),
		}
		if !b.FinishedAt.IsZero() {
			entry["finished_at"] = b.FinishedAt.Format(time.RFC3339)
		}
		b.mu.Unlock()
		result = append(result, entry)
	}

	writeJSON(w, http.StatusOK, result)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
