#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

REBUILD_CONTAINERS=false
for arg in "$@"; do
    case "$arg" in
        --rebuild-containers) REBUILD_CONTAINERS=true ;;
        -h|--help)
            echo "Usage: setup.sh [--rebuild-containers]"
            echo "  --rebuild-containers  Rebuild and restart Docker containers"
            exit 0
            ;;
    esac
done

DATA_DIR="$HOME/orbital-data"

echo "=== Orbital Guard Setup ==="
echo ""

# 1. Build
echo "--- Building ---"
make build
echo ""

# 2. Sign (interactive — requires human)
echo "--- Signing ---"
make sign
echo ""

# 3. Setup guard user/group/dirs
echo "--- Setting up orbital-guard ---"
make setup-guard
echo ""

# 4. Android SDK ACL for orbital-guard
echo "--- Setting Android SDK ACL ---"
SDK="${ANDROID_HOME:-/Users/michaelfinkler/Library/Android/sdk}"
if [ -d "$SDK" ]; then
    # Grant traversal on parent dirs so orbital-guard can reach the SDK.
    sudo chmod +a "orbital-guard allow list,search,execute" "$HOME/Library"
    sudo chmod +a "orbital-guard allow list,search,execute" "$HOME/Library/Android"
    sudo chmod -R +a "orbital-guard allow read,execute,list,search" "$SDK"
    echo "✓ ACL set on $SDK (+ parent traversal)"
else
    echo "⚠️  Android SDK not found at $SDK — set ACL manually"
fi
echo ""

# 5. Data directory (under ~/ for Docker VirtioFS compatibility)
echo "--- Setting up data directory ---"
sudo mkdir -p "$DATA_DIR/workspaces" "$DATA_DIR/artifacts" "$DATA_DIR/certs"
sudo chown -R orbital-guard:orbital "$DATA_DIR"
sudo chmod 2775 "$DATA_DIR" "$DATA_DIR/workspaces" "$DATA_DIR/artifacts" "$DATA_DIR/certs"
# Docker Desktop VirtioFS uses the host user's identity for all container file
# access, so the host user must be in the orbital group for group-write to work.
sudo dseditgroup -o edit -a "$(whoami)" -t user orbital
echo "✓ $DATA_DIR ready (orbital-guard:orbital, SGID)"
echo "✓ $(whoami) added to orbital group (required for Docker VirtioFS)"
echo ""

# 6. Copy TLS certs
echo "--- Copying TLS certs ---"
sudo cp ~/.orbital/certs/* /opt/orbital/etc/certs/
sudo cp ~/.orbital/certs/orbital-ca.crt "$DATA_DIR/certs/"
sudo chown -R orbital-guard:orbital /opt/orbital/etc/certs
sudo chown orbital-guard:orbital "$DATA_DIR/certs/orbital-ca.crt"
echo "✓ Certs installed"
echo ""

# 7. Write config
echo "--- Writing config ---"
sudo tee /opt/orbital/etc/orbital.env > /dev/null << EOF
ANDROID_HOME=/Users/michaelfinkler/Library/Android/sdk
JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
GRADLE_USER_HOME=/opt/orbital/cache/gradle
ORBITAL_TLS_CERT=/opt/orbital/etc/certs/orbital-server.crt
ORBITAL_TLS_KEY=/opt/orbital/etc/certs/orbital-server.key
ORBITAL_AUDIT_LOG=/opt/orbital/log/audit.log
EOF
sudo chown orbital-guard:orbital /opt/orbital/etc/orbital.env
echo "✓ Config written"
echo ""

# 8. Install signed binary + LaunchDaemon
echo "--- Installing ---"
make install
echo ""

# 9. Remove legacy installation if present
if [ -f "$HOME/Library/LaunchAgents/com.claude.orbital.plist" ]; then
    echo "--- Removing legacy LaunchAgent ---"
    make uninstall-legacy
    echo ""
fi

# 10. Start service
echo "--- Starting service ---"
make start
echo ""

# 11. Verify service
echo "--- Verifying ---"
sleep 2
curl -sk https://127.0.0.1:9090/health && echo ""
make status
echo ""

# 12. Rebuild and restart containers (only with --rebuild-containers)
if $REBUILD_CONTAINERS; then
    echo "--- Rebuilding containers ---"
    COMPOSE="$HOME/Dev/containers/claude-dev/docker-compose.yml"
    if [ -f "$COMPOSE" ]; then
        docker compose -f "$COMPOSE" --profile arm64 --profile amd64 up -d --build 2>&1 | tail -10
        echo ""
        echo "--- Container doctor checks ---"
        sleep 3
        for c in claude-dev claude-ndk; do
            if docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
                echo "  $c:"
                docker exec "$c" orbital doctor 2>&1 | grep "Summary:"
            fi
        done
    fi
else
    echo "--- Skipping container rebuild (use --rebuild-containers to include) ---"
    echo "  To hot-patch running containers:"
    echo "    docker cp ~/Dev/containers/claude-dev/orbital-client claude-dev:/usr/local/bin/orbital"
    echo "    docker cp ~/Dev/containers/claude-dev/orbital-client claude-ndk:/usr/local/bin/orbital"
fi

echo ""
echo "=== Done ==="
