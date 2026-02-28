package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testPolicy() *SecurityPolicy {
	return DefaultPolicy()
}

// ---------------------------------------------------------------------------
// ValidateComputeCommand tests (ob-g16 + ob-0m7)
// ---------------------------------------------------------------------------

func TestValidateComputeCommand_AllowedInterpreters(t *testing.T) {
	sp := testPolicy()
	tests := []struct {
		cmd     string
		wantErr bool
	}{
		{"python3 script.py", false},
		{"python script.py", false},
		{"node process.js", false},
		{"bash run.sh", false}, // needs file to exist for full validation
		{"ruby script.rb", true},
		{"perl script.pl", true},
		{"sh script.sh", true},
		{"curl http://evil.example.com", true},
		{"", true},
	}

	for _, tt := range tests {
		err := sp.ValidateComputeCommand(tt.cmd, "")
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateComputeCommand(%q): got err=%v, wantErr=%v", tt.cmd, err, tt.wantErr)
		}
	}
}

func TestValidateComputeCommand_ShellMetacharacters(t *testing.T) {
	sp := testPolicy()
	tests := []string{
		"python3 script.py | cat /etc/passwd",
		"python3 script.py; rm -rf /",
		"python3 script.py && curl evil.example.com",
		"python3 script.py || true",
		"python3 `whoami`.py",
		"python3 $(whoami).py",
		"python3 script.py > /tmp/out",
		"python3 script.py < /dev/null",
		"python3 script.py &",
	}

	for _, cmd := range tests {
		if err := sp.ValidateComputeCommand(cmd, ""); err == nil {
			t.Errorf("ValidateComputeCommand(%q): expected error for shell metacharacter", cmd)
		}
	}
}

func TestValidateComputeCommand_BlockedFlags(t *testing.T) {
	sp := testPolicy()
	tests := []struct {
		cmd     string
		wantErr bool
	}{
		{"python3 -m http.server", true},
		{"python3 -i", true},
		{"python3 -W all", true},
		{"node -e console.log", true},
		{"node --eval console.log", true},
		{"node --require ./evil.js script.js", true},
		{"node --import ./evil.mjs script.js", true},
		// These should be allowed:
		{"python3 script.py --verbose", false},
		{"python3 script.py --variant s2", false},
		{"node process.js --output dir", false},
	}

	for _, tt := range tests {
		err := sp.ValidateComputeCommand(tt.cmd, "")
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateComputeCommand(%q): got err=%v, wantErr=%v", tt.cmd, err, tt.wantErr)
		}
	}
}

func TestValidateComputeCommand_PathTraversal(t *testing.T) {
	sp := testPolicy()
	tests := []struct {
		cmd     string
		wantErr bool
	}{
		{"python3 ../../../etc/passwd", true},
		{"python3 /etc/passwd", true},
		{"node ../../sensitive.js", true},
		{"python3 subdir/script.py", false},
		{"python3 script.py", false},
	}

	for _, tt := range tests {
		err := sp.ValidateComputeCommand(tt.cmd, "")
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateComputeCommand(%q): got err=%v, wantErr=%v", tt.cmd, err, tt.wantErr)
		}
	}
}

func TestValidateComputeCommand_BashRequiresShFile(t *testing.T) {
	sp := testPolicy()

	// bash without a script file argument.
	if err := sp.ValidateComputeCommand("bash", ""); err == nil {
		t.Error("expected error for bare 'bash' command")
	}

	// bash with non-.sh file.
	if err := sp.ValidateComputeCommand("bash script.py", ""); err == nil {
		t.Error("expected error for bash with .py file")
	}

	// bash with .sh file (no workspace check).
	if err := sp.ValidateComputeCommand("bash run.sh", ""); err != nil {
		t.Errorf("unexpected error for bash run.sh: %v", err)
	}

	// bash with .sh file that exists in workspace.
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "build.sh")
	os.WriteFile(scriptPath, []byte("#!/bin/bash\necho hello"), 0o755)

	if err := sp.ValidateComputeCommand("bash build.sh", tmpDir); err != nil {
		t.Errorf("unexpected error for bash build.sh with existing file: %v", err)
	}

	// bash with .sh file that doesn't exist in workspace.
	if err := sp.ValidateComputeCommand("bash missing.sh", tmpDir); err == nil {
		t.Error("expected error for bash with missing .sh file")
	}
}

// ---------------------------------------------------------------------------
// IsAllowedComputeArtifact tests (ob-86c)
// ---------------------------------------------------------------------------

func TestIsAllowedComputeArtifact(t *testing.T) {
	sp := testPolicy()
	tests := []struct {
		filename string
		allowed  bool
	}{
		// Allowed types.
		{"index.usearch", true},
		{"results.json", true},
		{"data.csv", true},
		{"model.bin", true},
		{"model.onnx", true},
		{"embeddings.npy", true},
		{"weights.npz", true},
		{"model.safetensors", true},
		{"output.txt", true},
		{"build.log", true},
		// Case insensitive.
		{"DATA.JSON", true},
		{"MODEL.ONNX", true},
		// Blocked types (executable/exfiltration risk).
		{"script.py", false},
		{"build.sh", false},
		{"library.so", false},
		{"library.dylib", false},
		{"binary.exe", false},
		{"archive.tar.gz", false},
		{"config.yaml", false},
		{"noext", false},
	}

	for _, tt := range tests {
		got := sp.IsAllowedComputeArtifact(tt.filename)
		if got != tt.allowed {
			t.Errorf("IsAllowedComputeArtifact(%q) = %v, want %v", tt.filename, got, tt.allowed)
		}
	}
}

// ---------------------------------------------------------------------------
// ComputeEnvironment tests (ob-ij2)
// ---------------------------------------------------------------------------

func TestComputeEnvironment_NoVenv(t *testing.T) {
	env := ComputeEnvironment("/ws/abc", "/tmp/compute-123", "")

	envMap := envToMap(env)

	// Must have restricted PATH.
	if !strings.Contains(envMap["PATH"], "/usr/bin") {
		t.Error("PATH should contain /usr/bin")
	}
	if strings.Contains(envMap["PATH"], "/Users") {
		t.Error("PATH should not contain user directories")
	}

	// HOME must be workspace, not real home.
	if envMap["HOME"] != "/ws/abc" {
		t.Errorf("HOME = %q, want /ws/abc", envMap["HOME"])
	}

	// TMPDIR must be scoped.
	if envMap["TMPDIR"] != "/tmp/compute-123" {
		t.Errorf("TMPDIR = %q, want /tmp/compute-123", envMap["TMPDIR"])
	}

	// PYTHONPATH must be empty (no injection).
	if envMap["PYTHONPATH"] != "" {
		t.Errorf("PYTHONPATH = %q, want empty", envMap["PYTHONPATH"])
	}

	// Must NOT contain signing secrets.
	for k := range envMap {
		if strings.HasPrefix(k, "SIGNING_") {
			t.Errorf("env should not contain signing key: %s", k)
		}
	}

	// VIRTUAL_ENV should not be set.
	if _, ok := envMap["VIRTUAL_ENV"]; ok {
		t.Error("VIRTUAL_ENV should not be set without venv")
	}
}

func TestComputeEnvironment_WithVenv(t *testing.T) {
	env := ComputeEnvironment("/ws/abc", "/tmp/compute-123", "/data/venvs/abc-def123")

	envMap := envToMap(env)

	// PATH should have venv bin first.
	if !strings.HasPrefix(envMap["PATH"], "/data/venvs/abc-def123/bin:") {
		t.Errorf("PATH should start with venv bin, got %q", envMap["PATH"])
	}

	// VIRTUAL_ENV should be set.
	if envMap["VIRTUAL_ENV"] != "/data/venvs/abc-def123" {
		t.Errorf("VIRTUAL_ENV = %q, want /data/venvs/abc-def123", envMap["VIRTUAL_ENV"])
	}
}

func TestComputeEnvironment_NoHostLeakage(t *testing.T) {
	// Verify compute env doesn't leak real HOME.
	origHome := os.Getenv("HOME")

	env := ComputeEnvironment("/ws/test", "/tmp/t", "")
	envMap := envToMap(env)

	// HOME must be workspace, not real home.
	if envMap["HOME"] == origHome && origHome != "/ws/test" {
		t.Error("compute env leaked real HOME directory")
	}

	// Must have very few keys (minimal env).
	if len(env) > 10 {
		t.Errorf("compute env has %d entries, expected minimal (<10)", len(env))
	}
}

// ---------------------------------------------------------------------------
// GenerateSandboxProfile tests (ob-p5q)
// ---------------------------------------------------------------------------

func TestGenerateSandboxProfile_Structure(t *testing.T) {
	profile := GenerateSandboxProfile("/ws/abc123", "", "/tmp/compute-abc")

	// Must start with version and deny default.
	if !strings.Contains(profile, "(version 1)") {
		t.Error("sandbox profile missing version")
	}
	if !strings.Contains(profile, "(deny default)") {
		t.Error("sandbox profile missing deny default")
	}

	// Must allow workspace read/write.
	if !strings.Contains(profile, `(allow file-read* (subpath "/ws/abc123"))`) {
		t.Error("sandbox profile missing workspace read access")
	}
	if !strings.Contains(profile, `(allow file-write* (subpath "/ws/abc123"))`) {
		t.Error("sandbox profile missing workspace write access")
	}

	// Must allow temp dir access.
	if !strings.Contains(profile, `(subpath "/tmp/compute-abc")`) {
		t.Error("sandbox profile missing temp dir access")
	}

	// Must deny network.
	if !strings.Contains(profile, "(deny network*)") {
		t.Error("sandbox profile missing network deny")
	}

	// Home directory access is blocked by (deny default) — no explicit deny needed.
	// Verify no explicit home deny exists (it would conflict with workspace allow).
	if strings.Contains(profile, "deny file-read* (subpath \"/Users") {
		t.Error("sandbox profile should not have explicit home dir deny (deny default covers it)")
	}

	// Must allow /bin for sh/bash.
	if !strings.Contains(profile, `(allow file-read* (subpath "/bin"))`) {
		t.Error("sandbox profile missing /bin access (needed for sh)")
	}

	// Must allow system libs (for CoreML, Python).
	if !strings.Contains(profile, `(allow file-read* (subpath "/System/Library"))`) {
		t.Error("sandbox profile missing System/Library access")
	}
	if !strings.Contains(profile, `(allow file-read* (subpath "/Library/Frameworks"))`) {
		t.Error("sandbox profile missing Library/Frameworks access (CoreML)")
	}

	// Must allow /private/etc for system config (DNS, hostname, etc.).
	if !strings.Contains(profile, `(allow file-read* (subpath "/private/etc"))`) {
		t.Error("sandbox profile missing /private/etc access")
	}

	// Must allow process execution.
	if !strings.Contains(profile, "(allow process-exec)") {
		t.Error("sandbox profile missing process-exec")
	}
}

func TestGenerateSandboxProfile_WithVenv(t *testing.T) {
	profile := GenerateSandboxProfile("/ws/abc123", "/data/venvs/abc-def", "/tmp/compute-abc")

	// Must include venv read access.
	if !strings.Contains(profile, `(allow file-read* (subpath "/data/venvs/abc-def"))`) {
		t.Error("sandbox profile missing venv read access")
	}
}

func TestGenerateSandboxProfile_WithoutVenv(t *testing.T) {
	profile := GenerateSandboxProfile("/ws/abc123", "", "/tmp/compute-abc")

	// Should NOT contain venv section.
	if strings.Contains(profile, "Venv read/exec access") {
		t.Error("sandbox profile should not have venv section when venv is empty")
	}
}

// ---------------------------------------------------------------------------
// ComputeResourceLimitArgs tests (ob-81j)
// ---------------------------------------------------------------------------

func TestComputeResourceLimitArgs(t *testing.T) {
	sp := testPolicy()
	args := sp.ComputeResourceLimitArgs()

	// Should contain ulimit commands.
	if !strings.Contains(args, "ulimit -v") {
		t.Error("resource limits missing memory limit")
	}
	if !strings.Contains(args, "ulimit -f") {
		t.Error("resource limits missing file size limit")
	}
	if !strings.Contains(args, "ulimit -u") {
		t.Error("resource limits missing process limit")
	}

	// Verify correct values.
	// 8GB / 1024 = 8388608 KB
	if !strings.Contains(args, "8388608") {
		t.Errorf("resource limits memory should be 8388608 KB, got: %s", args)
	}
	// 2GB / 1024 = 2097152 KB
	if !strings.Contains(args, "2097152") {
		t.Errorf("resource limits file size should be 2097152 KB, got: %s", args)
	}
	// 64 processes
	if !strings.Contains(args, "64") {
		t.Errorf("resource limits should contain 64 processes, got: %s", args)
	}
}

// ---------------------------------------------------------------------------
// ValidateRequirementsPath tests (ob-w0x)
// ---------------------------------------------------------------------------

func TestValidateRequirementsPath(t *testing.T) {
	sp := testPolicy()
	tests := []struct {
		path    string
		wantErr bool
	}{
		{"", false},
		{"requirements.txt", false},
		{"deps/requirements.txt", false},
		{"../requirements.txt", true},
		{"/etc/requirements.txt", true},
		{"deps/../../../etc/passwd", true},
	}

	for _, tt := range tests {
		err := sp.ValidateRequirementsPath(tt.path)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateRequirementsPath(%q): got err=%v, wantErr=%v", tt.path, err, tt.wantErr)
		}
	}
}

// ---------------------------------------------------------------------------
// VenvPath tests (ob-w0x)
// ---------------------------------------------------------------------------

func TestVenvPath_Deterministic(t *testing.T) {
	path1 := VenvPath("/base", "ws123", "onnxruntime==1.16.0\nnumpy==1.24.0")
	path2 := VenvPath("/base", "ws123", "onnxruntime==1.16.0\nnumpy==1.24.0")
	if path1 != path2 {
		t.Errorf("VenvPath should be deterministic: %q != %q", path1, path2)
	}
}

func TestVenvPath_DifferentRequirements(t *testing.T) {
	path1 := VenvPath("/base", "ws123", "onnxruntime==1.16.0")
	path2 := VenvPath("/base", "ws123", "onnxruntime==1.17.0")
	if path1 == path2 {
		t.Errorf("VenvPath should differ for different requirements")
	}
}

func TestVenvPath_Format(t *testing.T) {
	path := VenvPath("/base", "ws123", "numpy==1.24.0")
	if !strings.HasPrefix(path, "/base/venvs/ws123-") {
		t.Errorf("VenvPath format wrong: %q", path)
	}
	// Hash part should be 12 hex chars.
	parts := strings.Split(filepath.Base(path), "-")
	if len(parts) < 2 {
		t.Fatalf("VenvPath should have hash suffix: %q", path)
	}
	hash := parts[len(parts)-1]
	if len(hash) != 12 {
		t.Errorf("VenvPath hash should be 12 chars, got %d: %q", len(hash), hash)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func envToMap(env []string) map[string]string {
	m := make(map[string]string)
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if ok {
			m[k] = v
		}
	}
	return m
}
