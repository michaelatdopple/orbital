package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
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

	// Audit log file path (append-only).
	AuditLogPath string
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
		BlockSymlinks: true,
		AuditLogPath:  "", // Set via config; empty = log to stdout only
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
func (sp *SecurityPolicy) ValidatePreBuild(commands []string) error {
	for _, cmd := range commands {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}
		allowed := false
		for _, prefix := range sp.AllowedPreBuild {
			if cmd == prefix || strings.HasPrefix(cmd, prefix+" ") {
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
