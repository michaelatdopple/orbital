package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Security policy — configurable guards for untrusted code
// ---------------------------------------------------------------------------

// SecurityPolicy defines the constraints for builds.
type SecurityPolicy struct {
	// Pre-build command allowlist. Only exact-prefix matches are permitted.
	// e.g. "npm install", "yarn install --frozen-lockfile"
	AllowedPreBuild []string

	// Maximum concurrent builds.
	MaxConcurrentBuilds int

	// Maximum build duration before forced kill.
	MaxBuildDuration time.Duration

	// Known Gradle wrapper SHA-256 checksums.
	// If non-empty, gradlew's wrapper jar must match one.
	KnownGradleWrapperSHAs []string

	// Blocked Gradle property patterns (case-insensitive regex).
	BlockedPropertyPatterns []*regexp.Regexp

	// Block symlinks in workspaces.
	BlockSymlinks bool

	// Allowed git host domains for dependency resolution.
	AllowedGitDomains []string

	// Audit log file path (append-only).
	AuditLogPath string

	// --- Compute delegation security ---

	// Allowed interpreter commands for compute jobs (first token of command).
	AllowedComputeCommands []string

	// Blocked interpreter flags that enable inline code execution.
	BlockedComputeFlags []string

	// Allowed file extensions for compute artifacts (separate from build artifacts).
	AllowedComputeArtifactExts []string

	// Resource limits for compute processes.
	ComputeMemoryLimitBytes int64 // RLIMIT_AS
	ComputeFileSizeLimitBytes int64 // RLIMIT_FSIZE
	ComputeMaxProcesses       int64 // RLIMIT_NPROC
}

// DefaultPolicy returns a security policy suitable for untrusted code.
func DefaultPolicy() *SecurityPolicy {
	return &SecurityPolicy{
		AllowedPreBuild: []string{
			"npm install",
			"npm ci",
			"yarn install",
			"yarn install --frozen-lockfile",
		},
		MaxConcurrentBuilds: 4,
		MaxBuildDuration:    30 * time.Minute,
		KnownGradleWrapperSHAs: []string{
			// These are populated from https://gradle.org/release-checksums/
			// Users should add their project's wrapper SHA here.
			// Empty list = skip wrapper verification (warn only).
		},
		BlockedPropertyPatterns: compileBlockedPatterns([]string{
			`(?i)-javaagent`,
			`(?i)-agentlib`,
			`(?i)-agentpath`,
			`(?i)-Xrunjdwp`,
			`(?i)-Xdebug`,
			`(?i)org\.gradle\.jvmargs.*-javaagent`,
			`(?i)org\.gradle\.jvmargs.*-agentlib`,
			`(?i)org\.gradle\.jvmargs.*-agentpath`,
			`(?i)init\.script`,
			`(?i)--init-script`,
			`(?i)-I\b`,
		}),
		BlockSymlinks:     true,
		AllowedGitDomains: []string{"github.com", "gitlab.com"},
		AuditLogPath:      "", // Set via config; empty = log to stdout only

		// Compute delegation defaults.
		AllowedComputeCommands: []string{"python3", "python", "node", "bash"},
		BlockedComputeFlags: []string{
			"-c",        // python -c, bash -c (inline code execution)
			"-e",        // node -e (eval)
			"-m",        // python -m (run modules as scripts)
			"--eval",    // node --eval
			"--require", // node --require (load arbitrary modules)
			"--import",  // node --import
			"-i",        // interactive mode
			"-W",        // python warnings (can be abused for code paths)
		},
		AllowedComputeArtifactExts: []string{
			".usearch", ".json", ".csv", ".bin",
			".onnx", ".npy", ".npz", ".safetensors",
			".txt", ".log",
		},
		ComputeMemoryLimitBytes:   8 * 1024 * 1024 * 1024, // 8 GB
		ComputeFileSizeLimitBytes: 2 * 1024 * 1024 * 1024, // 2 GB
		ComputeMaxProcesses:       64,
	}
}

func compileBlockedPatterns(patterns []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		r, err := regexp.Compile(p)
		if err != nil {
			log.Printf("security: invalid blocked pattern %q: %v", p, err)
			continue
		}
		compiled = append(compiled, r)
	}
	return compiled
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

// ValidatePreBuild checks that all pre-build commands are in the allowlist.
// Supports bare commands ("npm install") and subdirectory-scoped commands
// ("cd gallery && npm install") where the subdir is a safe relative path.
func (sp *SecurityPolicy) ValidatePreBuild(commands []string) error {
	// Pattern: cd <relative-path-no-dots> && <command>
	cdPattern := regexp.MustCompile(`^cd\s+([a-zA-Z0-9_./-]+)\s+&&\s+(.+)$`)

	for _, cmd := range commands {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}

		// Check if it's a cd <subdir> && <command> form.
		cmdToCheck := cmd
		if m := cdPattern.FindStringSubmatch(cmd); m != nil {
			subdir := m[1]
			// Block path traversal.
			if strings.Contains(subdir, "..") {
				return fmt.Errorf("pre_build command not allowed: %q (path traversal blocked)", cmd)
			}
			cmdToCheck = strings.TrimSpace(m[2])
		}

		allowed := false
		for _, prefix := range sp.AllowedPreBuild {
			if cmdToCheck == prefix || strings.HasPrefix(cmdToCheck, prefix+" ") {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("pre_build command not allowed: %q (allowed: %v)", cmd, sp.AllowedPreBuild)
		}
	}
	return nil
}

// ValidateProperties checks that no Gradle properties match blocked patterns.
func (sp *SecurityPolicy) ValidateProperties(properties map[string]string) error {
	for k, v := range properties {
		combined := k + "=" + v
		for _, pattern := range sp.BlockedPropertyPatterns {
			if pattern.MatchString(k) || pattern.MatchString(v) || pattern.MatchString(combined) {
				return fmt.Errorf("blocked property: %q matches security pattern %q", combined, pattern.String())
			}
		}
	}
	return nil
}

// ValidateTasks checks that task names don't contain injection attempts.
func (sp *SecurityPolicy) ValidateTasks(tasks []string) error {
	// Tasks must be simple Gradle task names: alphanumeric, colons, dashes.
	taskPattern := regexp.MustCompile(`^[a-zA-Z0-9:_-]+$`)
	for _, t := range tasks {
		if !taskPattern.MatchString(t) {
			return fmt.Errorf("invalid task name %q: must be alphanumeric with colons/dashes only", t)
		}
	}
	return nil
}

// ValidateDeps checks that dependency specs are safe.
// Env var names must be uppercase with underscores, git URLs must be HTTPS on
// an allowed domain, and refs must be simple branch/tag names.
func (sp *SecurityPolicy) ValidateDeps(deps map[string]DepSpec) error {
	envVarPat := regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	refPat := regexp.MustCompile(`^[a-zA-Z0-9._/-]+$`)

	for name, dep := range deps {
		// Validate env var name.
		if !envVarPat.MatchString(name) {
			return fmt.Errorf("invalid dep env var name %q: must match [A-Z_][A-Z0-9_]*", name)
		}

		// Validate git URL: must be https:// on allowed domain.
		if !strings.HasPrefix(dep.Git, "https://") {
			return fmt.Errorf("dep %q: git URL must use https:// (got %q)", name, dep.Git)
		}
		parsed, err := url.Parse(dep.Git)
		if err != nil {
			return fmt.Errorf("dep %q: invalid git URL %q: %w", name, dep.Git, err)
		}
		host := strings.ToLower(parsed.Hostname())
		allowed := false
		for _, d := range sp.AllowedGitDomains {
			if host == d {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("dep %q: git host %q not in allowed domains %v", name, host, sp.AllowedGitDomains)
		}

		// Validate ref.
		if dep.Ref == "" {
			return fmt.Errorf("dep %q: ref is required", name)
		}
		if !refPat.MatchString(dep.Ref) {
			return fmt.Errorf("dep %q: invalid ref %q: must match [a-zA-Z0-9._/-]+", name, dep.Ref)
		}
	}
	return nil
}

// ValidateArtifactDirs checks that artifact directory paths are safe relative paths.
func (sp *SecurityPolicy) ValidateArtifactDirs(dirs []string) error {
	for _, dir := range dirs {
		if strings.Contains(dir, "..") {
			return fmt.Errorf("artifact_dir must not contain '..': %q", dir)
		}
		if filepath.IsAbs(dir) {
			return fmt.Errorf("artifact_dir must be a relative path: %q", dir)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Compute security guards
// ---------------------------------------------------------------------------

// shellMetacharacters are characters that indicate shell injection attempts.
var shellMetacharacters = []string{"|", ";", "&&", "||", "`", "$(", ">", "<", "&", "\n", "\r"}

// ValidateComputeCommand validates a compute command string.
// Checks: first token in allowlist, no shell metacharacters, no blocked flags,
// file arguments are relative within workspace, bash requires .sh script file.
func (sp *SecurityPolicy) ValidateComputeCommand(command string, wsDir string) error {
	if command == "" {
		return fmt.Errorf("compute command is required")
	}

	// Check for shell metacharacters.
	for _, meta := range shellMetacharacters {
		if strings.Contains(command, meta) {
			return fmt.Errorf("compute command contains blocked shell metacharacter %q", meta)
		}
	}

	// Split into tokens.
	args := strings.Fields(command)
	if len(args) == 0 {
		return fmt.Errorf("compute command is empty after parsing")
	}

	// Validate first token is an allowed interpreter.
	interpreter := args[0]
	allowed := false
	for _, cmd := range sp.AllowedComputeCommands {
		if interpreter == cmd {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("compute command %q not in allowlist %v", interpreter, sp.AllowedComputeCommands)
	}

	// Validate no blocked interpreter flags.
	for _, arg := range args[1:] {
		for _, blocked := range sp.BlockedComputeFlags {
			if arg == blocked {
				return fmt.Errorf("compute command contains blocked flag %q (prevents inline code execution)", blocked)
			}
		}
	}

	// Validate file-like arguments: must be relative, no traversal, no absolute paths.
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") {
			continue // skip flags
		}
		if filepath.IsAbs(arg) {
			return fmt.Errorf("compute command argument must be relative path: %q", arg)
		}
		if strings.Contains(arg, "..") {
			return fmt.Errorf("compute command argument must not contain '..': %q", arg)
		}
	}

	// Bash-specific: second token must be a .sh file that exists in the workspace.
	if interpreter == "bash" {
		if len(args) < 2 {
			return fmt.Errorf("bash compute command requires a script file argument")
		}
		scriptArg := args[1]
		if !strings.HasSuffix(scriptArg, ".sh") {
			return fmt.Errorf("bash compute command requires a .sh script file, got %q", scriptArg)
		}
		if wsDir != "" {
			scriptPath := filepath.Join(wsDir, scriptArg)
			if _, err := os.Stat(scriptPath); err != nil {
				return fmt.Errorf("bash script not found in workspace: %s", scriptArg)
			}
		}
	}

	return nil
}

// IsAllowedComputeArtifact checks if a filename has an allowed extension for
// compute artifacts. Returns false for extensions that could contain executable
// code or be used for data exfiltration (.py, .sh, .so, .dylib).
func (sp *SecurityPolicy) IsAllowedComputeArtifact(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	for _, allowed := range sp.AllowedComputeArtifactExts {
		if ext == allowed {
			return true
		}
	}
	return false
}

// ValidateRequirementsPath checks that a requirements file path is safe.
func (sp *SecurityPolicy) ValidateRequirementsPath(reqPath string) error {
	if reqPath == "" {
		return nil
	}
	if filepath.IsAbs(reqPath) {
		return fmt.Errorf("requirements path must be relative: %q", reqPath)
	}
	if strings.Contains(reqPath, "..") {
		return fmt.Errorf("requirements path must not contain '..': %q", reqPath)
	}
	return nil
}

// ComputeEnvironment builds a minimal environment for compute processes.
// This MUST be used instead of os.Environ() to prevent secret leakage.
// No SIGNING_* secrets, no API keys, no real HOME directory.
func ComputeEnvironment(wsDir, tmpDir, venvDir string) []string {
	env := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin",
		"HOME=" + wsDir,
		"TMPDIR=" + tmpDir,
		"PYTHONPATH=",
		"LANG=en_US.UTF-8",
	}
	if venvDir != "" {
		env = append(env, "VIRTUAL_ENV="+venvDir)
		// Prepend venv bin to PATH.
		env[0] = "PATH=" + filepath.Join(venvDir, "bin") + ":/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin"
	}
	return env
}

// GenerateSandboxProfile creates a macOS sandbox-exec profile that restricts
// compute processes to their workspace, venv, and system libraries only.
// This is the primary defense: even if all other checks fail, the sandbox
// confines the process.
func GenerateSandboxProfile(wsDir, venvDir, tmpDir string) string {
	profile := `(version 1)
(deny default)

;; Read access: workspace, system libs, interpreters
(allow file-read* (subpath "` + wsDir + `"))
(allow file-read* (subpath "/bin"))
(allow file-read* (subpath "/usr/bin"))
(allow file-read* (subpath "/usr/lib"))
(allow file-read* (subpath "/usr/local/bin"))
(allow file-read* (subpath "/usr/local/lib"))
(allow file-read* (subpath "/opt/homebrew"))
(allow file-read* (subpath "/System/Library"))
(allow file-read* (subpath "/Library"))
(allow file-read* (subpath "/private/etc"))
(allow file-read* (subpath "/private/var/db"))
(allow file-read* (literal "/dev/urandom"))
(allow file-read* (literal "/dev/null"))
(allow file-read* (literal "/dev/random"))

;; Write access: workspace and temp only
(allow file-write* (subpath "` + wsDir + `"))
(allow file-write* (subpath "` + tmpDir + `"))
(allow file-write* (literal "/dev/null"))

;; Temp dir read access
(allow file-read* (subpath "` + tmpDir + `"))

;; Process execution (for python3, node, etc.)
(allow process-exec)
(allow process-fork)

;; Allow sysctl reads (required by Python, Node)
(allow sysctl-read)

;; Allow mach lookups (required for CoreML, Metal)
(allow mach-lookup)

;; Block network access (no exfiltration, no reverse shells)
(deny network*)
`
	// Note: no explicit home directory deny needed — (deny default) already
	// blocks all paths not explicitly allowed above.
	// Add venv read access if specified.
	if venvDir != "" {
		profile += `
;; Venv read/exec access
(allow file-read* (subpath "` + venvDir + `"))
`
	}

	return profile
}

// ComputeResourceLimitArgs returns ulimit shell arguments for resource-limiting
// compute processes. These are applied via a wrapper since macOS Go doesn't
// support SysProcAttr.Rlimits.
func (sp *SecurityPolicy) ComputeResourceLimitArgs() string {
	memKB := sp.ComputeMemoryLimitBytes / 1024
	fileKB := sp.ComputeFileSizeLimitBytes / 1024
	nproc := sp.ComputeMaxProcesses
	return fmt.Sprintf("ulimit -v %d && ulimit -f %d && ulimit -u %d", memKB, fileKB, nproc)
}

// ResolveSigningProfile looks up a signing profile from environment variables
// and returns the env vars to inject into the build process. Profile names are
// validated as ^[a-zA-Z0-9_-]+$ and mapped to SIGNING_<UPPER>_KEYSTORE etc.
func (sp *SecurityPolicy) ResolveSigningProfile(profile string) ([]string, error) {
	profilePat := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !profilePat.MatchString(profile) {
		return nil, fmt.Errorf("invalid signing profile name %q", profile)
	}

	prefix := "SIGNING_" + strings.ToUpper(profile) + "_"
	keystore := os.Getenv(prefix + "KEYSTORE")
	if keystore == "" {
		return nil, fmt.Errorf("signing profile %q not configured (missing %sKEYSTORE)", profile, prefix)
	}
	if _, err := os.Stat(keystore); err != nil {
		return nil, fmt.Errorf("signing profile %q: keystore not found at %s", profile, keystore)
	}

	storePass := os.Getenv(prefix + "KEYSTORE_PASSWORD")
	keyAlias := os.Getenv(prefix + "KEY_ALIAS")
	keyPass := os.Getenv(prefix + "KEY_PASSWORD")

	return []string{
		"SIGNING_KEYSTORE_PATH=" + keystore,
		"SIGNING_KEYSTORE_PASSWORD=" + storePass,
		"SIGNING_KEY_ALIAS=" + keyAlias,
		"SIGNING_KEY_PASSWORD=" + keyPass,
	}, nil
}

// VerifyGradleWrapper checks the Gradle wrapper jar's SHA-256.
func (sp *SecurityPolicy) VerifyGradleWrapper(wsDir string) error {
	wrapperJar := filepath.Join(wsDir, "gradle", "wrapper", "gradle-wrapper.jar")
	if _, err := os.Stat(wrapperJar); err != nil {
		return fmt.Errorf("gradle-wrapper.jar not found at %s", wrapperJar)
	}

	sha, err := fileSHA256(wrapperJar)
	if err != nil {
		return fmt.Errorf("failed to checksum gradle-wrapper.jar: %w", err)
	}

	if len(sp.KnownGradleWrapperSHAs) == 0 {
		log.Printf("security: WARNING: no known Gradle wrapper checksums configured — skipping verification (sha=%s)", sha)
		return nil
	}

	for _, known := range sp.KnownGradleWrapperSHAs {
		if strings.EqualFold(sha, known) {
			return nil
		}
	}

	return fmt.Errorf("gradle-wrapper.jar checksum mismatch: got %s, not in known list", sha)
}

// CheckSymlinks scans the workspace for symlinks that point outside it.
func (sp *SecurityPolicy) CheckSymlinks(wsDir string) error {
	if !sp.BlockSymlinks {
		return nil
	}

	absWs, err := filepath.Abs(wsDir)
	if err != nil {
		return fmt.Errorf("cannot resolve workspace path: %w", err)
	}

	return filepath.Walk(wsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("cannot read symlink %s: %w", path, err)
			}
			// Resolve relative symlinks.
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(path), target)
			}
			absTarget, err := filepath.Abs(target)
			if err != nil {
				return fmt.Errorf("cannot resolve symlink target %s: %w", target, err)
			}
			if !strings.HasPrefix(absTarget, absWs+string(filepath.Separator)) && absTarget != absWs {
				return fmt.Errorf("symlink escape blocked: %s -> %s (outside workspace)", path, absTarget)
			}
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Concurrency limiter
// ---------------------------------------------------------------------------

// BuildLimiter tracks concurrent builds.
type BuildLimiter struct {
	mu      sync.Mutex
	active  int
	maxConn int
}

// NewBuildLimiter creates a limiter with the given max.
func NewBuildLimiter(max int) *BuildLimiter {
	return &BuildLimiter{maxConn: max}
}

// Acquire attempts to start a build. Returns an error if at capacity.
func (bl *BuildLimiter) Acquire() error {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	if bl.active >= bl.maxConn {
		return fmt.Errorf("too many concurrent builds (%d/%d) — try again later", bl.active, bl.maxConn)
	}
	bl.active++
	return nil
}

// Release signals that a build has finished.
func (bl *BuildLimiter) Release() {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	if bl.active > 0 {
		bl.active--
	}
}

// ---------------------------------------------------------------------------
// Audit logging
// ---------------------------------------------------------------------------

// AuditLogger writes append-only security audit events.
type AuditLogger struct {
	mu   sync.Mutex
	file *os.File
}

// NewAuditLogger opens or creates the audit log file.
func NewAuditLogger(path string) *AuditLogger {
	if path == "" {
		return &AuditLogger{}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("security: WARNING: cannot open audit log %s: %v", path, err)
		return &AuditLogger{}
	}
	return &AuditLogger{file: f}
}

// Log writes an audit event.
func (al *AuditLogger) Log(event string, fields map[string]string) {
	ts := time.Now().UTC().Format(time.RFC3339)
	parts := []string{fmt.Sprintf("time=%s event=%s", ts, event)}
	for k, v := range fields {
		parts = append(parts, fmt.Sprintf("%s=%q", k, v))
	}
	line := strings.Join(parts, " ")
	log.Printf("audit: %s", line)

	al.mu.Lock()
	defer al.mu.Unlock()
	if al.file != nil {
		fmt.Fprintln(al.file, line)
	}
}

// Close closes the audit log file.
func (al *AuditLogger) Close() {
	al.mu.Lock()
	defer al.mu.Unlock()
	if al.file != nil {
		al.file.Close()
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
