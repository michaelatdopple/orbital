# Orbital Compute Delegation Design

**Issue:** ob-2f5
**Date:** 2026-02-27
**Status:** Approved

## Problem

Container agents running ONNX inference (and other compute-intensive tasks) on virtualized Docker CPU see 60+ minute runtimes for work that would take 4-9 minutes on the host with Apple Silicon hardware acceleration (CoreML/ANE). Containers have zero GPU/ANE access.

**Concrete case:** `item_index_builder.py` embeds 31,564 captions through a 243MB MobileCLIP S2 text encoder using `CPUExecutionProvider`. On the host with `CoreMLExecutionProvider`, inference drops from ~110ms to ~5-15ms per caption.

## Threat Model

Containers run autonomous LLM agents. Code rsynced from the container is **unreviewed by humans ~99% of the time**. Agents may be prompt-injected, hallucinating, or subtly compromised. Everything rsynced from the container -- scripts, requirements files, model files -- must be treated as adversarial input.

This is fundamentally different from Gradle builds where the executable (`gradlew`) is a known tool. Compute runs attacker-controlled scripts directly on the host.

## Approach

Extend the existing `build_type` field to support `"compute"` alongside `"gradle"` and `"script"`. Reuses workspace rsync, SSE log streaming, artifact collection, and concurrency limiting. Adds auto-venv management for Python dependencies. All compute processes run inside a macOS sandbox profile that restricts filesystem, network, and process access.

## Client Interface

```bash
orbital compute <project-dir> <command...> [options]

# Index builder example:
orbital compute /home/claude/gt/packs/crew/rat \
  "python3 item_index_builder.py --variant s2 --no-connections --no-acn" \
  --requirements requirements.txt \
  --artifact-dir models/

# Node.js example:
orbital compute /home/claude/gt/analysis \
  "node process-embeddings.js" \
  --requirements package.json \
  --artifact-dir output/
```

**Options:**
- `--requirements <file>` -- triggers venv/npm setup before running
- `--artifact-dir <dir>` -- which dirs to copy back
- `--publish <name>` -- publish results to shared volume
- `--timeout <duration>` -- override default timeout

## Server Changes

### BuildRequest Extension

```go
// Existing fields reused: Workspace, Container, ArtifactDirs
// New/repurposed for compute:
BuildType        string   // "gradle" | "script" | "compute"
ComputeCommand   string   // "python3 item_index_builder.py --variant s2"
Requirements     string   // "requirements.txt" (relative to workspace)
```

### Execution Flow (runBuild, compute branch)

1. Validate command against allowlist (first token: `python3`, `node`, `bash`)
2. Validate no shell metacharacters (`|`, `;`, `&&`, `` ` ``, `$()`, etc.)
3. Validate no interpreter eval flags (`-c`, `-e`, `-m`, `--eval`, `--require`, etc.)
4. If `Requirements` specified:
   - Hash requirements file content
   - Check for cached venv at `~/orbital-data/venvs/{workspace_hash}-{req_hash[:12]}/`
   - Cache miss: create venv, pip install with `--only-binary :all:`, cache it
   - Cache hit: reuse (fast path)
5. Construct command: activate venv + run command
6. Build minimal environment (NO host env propagation)
7. Execute inside `sandbox-exec` with restrictive profile
8. Stream stdout/stderr via existing SSE
9. Collect artifacts from specified dirs (type-filtered)

## Security Architecture

### S1: Process Sandboxing (sandbox-exec)

All compute processes run inside a macOS sandbox profile. This is the primary defense -- even if every other check fails, the sandbox confines the process.

```scheme
(version 1)
(deny default)

;; Read access: workspace, venv, system libs, interpreters
(allow file-read* (subpath "{workspace_dir}"))
(allow file-read* (subpath "{venv_dir}"))
(allow file-read* (subpath "/usr/lib"))
(allow file-read* (subpath "/usr/bin"))
(allow file-read* (subpath "/usr/local/lib"))
(allow file-read* (subpath "/opt/homebrew"))
(allow file-read* (subpath "/System/Library"))
(allow file-read* (subpath "/Library/Frameworks"))  ; CoreML, Metal

;; Write access: workspace output dir and temp only
(allow file-write* (subpath "{workspace_dir}"))
(allow file-write* (subpath "{tmp_dir}"))

;; Process execution (for python3, node, etc.)
(allow process-exec)
(allow process-fork)

;; Block everything else
(deny network*)                        ; no network access
(deny file-read* (subpath (home-dir))) ; no home directory
(deny file-write* (subpath (home-dir)))
```

The sandbox prevents:
- Reading `~/.ssh/`, `~/.aws/`, signing keystores
- Writing outside the workspace
- Network access (no exfiltration, no reverse shells)
- Accessing other workspaces or the Orbital binary

### S2: Minimal Environment

Compute processes get a stripped environment, NOT `os.Environ()`:

```go
computeEnv := []string{
    "PATH=/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin",
    "HOME=" + wsDir,             // fake home = workspace
    "TMPDIR=" + computeTmpDir,   // scoped temp dir
    "PYTHONPATH=",               // empty, no injection
    "LANG=en_US.UTF-8",
    "VIRTUAL_ENV=" + venvDir,    // if venv active
}
// NO SIGNING_* secrets, NO API keys, NO real HOME
```

### S3: Safe Dependency Installation

**Python (`requirements.txt`):**
```bash
pip install --no-build-isolation --only-binary :all: -r requirements.txt
```

`--only-binary :all:` refuses to run `setup.py` -- only pre-built wheels are accepted. If a package doesn't have a wheel for the platform, it fails loudly rather than running arbitrary Python during install.

**Node.js (`package.json`):**
```bash
npm install --ignore-scripts
```

`--ignore-scripts` blocks `preinstall`, `postinstall`, and other lifecycle scripts.

### S4: Command Validation

#### Allowlisted Commands
```go
AllowedComputeCommands: []string{"python3", "python", "node", "bash"}
```

#### Blocked Interpreter Flags
```go
BlockedComputeFlags: []string{
    "-c",        // python -c, bash -c (inline code execution)
    "-e",        // node -e (eval)
    "-m",        // python -m (run modules as scripts)
    "--eval",    // node --eval
    "--require", // node --require (load arbitrary modules)
    "--import",  // node --import
    "-i",        // interactive mode
    "-W",        // python warnings (can be abused for code paths)
}
```

#### Validation Rules
1. First token of `ComputeCommand` must be in allowlist
2. No shell metacharacters: `|`, `;`, `&&`, `||`, `` ` ``, `$(`, `>`, `<`, `&`
3. No argument matches any blocked interpreter flag
4. File-like arguments must be relative, within workspace (no `..`, no absolute paths)
5. For `bash`: second token must be a `.sh` file that exists in the workspace
6. `Requirements` path must be relative, no traversal
7. Symlink rejection (existing check, reused)

#### Not Allowed
- Inline code execution (`python3 -c "..."`, `node -e "..."`, `bash -c "..."`)
- Module execution (`python3 -m http.server`)
- Piped commands
- Environment variable injection from container
- Shell expansion or globbing

### S5: Artifact Type Filtering

Compute artifacts use a separate allowlist from build artifacts:

```go
AllowedComputeArtifactExts: []string{
    ".usearch", ".json", ".csv", ".bin",
    ".onnx", ".npy", ".npz", ".safetensors",
    ".txt", ".log",
}
// NOT: .py, .sh, .so, .dylib (could contain exfiltrated data)
```

### S6: Resource Limits

```go
// Set via setrlimit before exec:
RLIMIT_AS     = 8 * 1024 * 1024 * 1024  // 8GB memory
RLIMIT_FSIZE  = 2 * 1024 * 1024 * 1024  // 2GB max file size
RLIMIT_NPROC  = 64                       // no fork bombs
// Build timeout (existing) applies: default 30 min
```

## Security Review Summary

| Threat | Severity | Mitigation |
|--------|----------|------------|
| Scripts = arbitrary code on host | CRITICAL | S1: sandbox-exec confinement |
| requirements.txt supply chain | CRITICAL | S3: --only-binary :all: |
| Host env leaked to scripts | CRITICAL | S2: minimal env allowlist |
| Interpreter -c/-e/-m flags | HIGH | S4: flag blocklist |
| ONNX model deserialization | HIGH | S1: sandbox-exec confinement |
| No filesystem isolation | HIGH | S1: sandbox-exec confinement |
| Artifact data exfiltration | MEDIUM | S5: type-filtered allowlist |
| No resource limits | MEDIUM | S6: ulimit constraints |
| Venv cache poisoning | LOW | SHA-256 keying (48-bit) |

## Venv Manager (new: venv.go)

```go
type VenvManager struct {
    BaseDir string  // ~/orbital-data/venvs/
}

func (vm *VenvManager) EnsureVenv(workspaceHash, reqFilePath string) (string, error)
```

**EnsureVenv logic:**
1. Read requirements file, SHA-256 content
2. Path: `{BaseDir}/{workspaceHash}-{sha256[:12]}/`
3. If exists with `bin/activate` -> return (cache hit)
4. Create: `python3 -m venv {path}`
5. Install: `{path}/bin/pip install --only-binary :all: -r {reqFile}`
6. Return path

**Cleanup:** Prune venvs unused for 14 days (added to existing hourly loop).

**Node.js:** Same pattern with `node_modules` cache via `npm install --ignore-scripts --prefix`.

## Client Changes (orbital-client)

New `cmd_compute()` function (~60 lines), following `cmd_build()` pattern:

1. `check_host()` -- existing
2. `compute_hash()` -- existing
3. `rsync_workspace()` -- existing
4. Build JSON with `build_type: "compute"`, `compute_command`, `requirements`
5. `POST /build` -- existing endpoint
6. `stream_logs()` -- existing
7. `copy_artifacts()` -- existing

## Estimated Scope

| File | Changes | Lines |
|------|---------|-------|
| build.go | compute dispatch + sandbox exec | ~150 |
| venv.go | new file, venv lifecycle | ~120 |
| security.go | compute validation + sandbox profile | ~120 |
| orbital-client | new command | ~60 |
| workspace.go | venv cleanup in prune loop | ~10 |

## Performance Projection

| Metric | Container (current) | Host compute (projected) |
|--------|--------------------|-----------------------|
| ONNX provider | CPUExecutionProvider | CoreMLExecutionProvider |
| Per-caption inference | ~110ms | ~5-15ms |
| 31,564 captions | ~58 min | ~3-8 min |
| Venv setup (first) | N/A | ~30s |
| Venv setup (cached) | N/A | 0s |
| Rsync workspace | N/A | ~5s |
| Artifact copy back | N/A | ~1s |
| **Total** | **~58 min** | **~4-9 min** |
