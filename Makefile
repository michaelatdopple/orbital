# ===========================================================================
# Orbital — host-side Makefile for macOS
#
# Runs the build service as the orbital-guard user for security isolation.
# Binary is code-signed to prevent unauthorized modification.
#
# Quick start (one-time):
#   make create-signing-cert    # create code signing identity (HUMAN)
#   make setup-guard            # create user, group, directories (sudo)
#
# Build & deploy:
#   make build                  # compile (LLM can do this)
#   make sign                   # sign binary (HUMAN ONLY)
#   make install                # install to /opt/orbital (sudo)
#   make start                  # start the service
#
# Docker compose addition needed:
#   - /opt/orbital/data:/home/claude/orbital:rw
# ===========================================================================

BINARY         := orbital
SIGN_IDENTITY  := Orbital Code Signing
SIGN_CERT_DIR  := $(HOME)/.orbital/codesign

# Paths (orbital-guard's domain)
OPT_DIR        := /opt/orbital
BIN_DIR        := $(OPT_DIR)/bin
ETC_DIR        := $(OPT_DIR)/etc
CERT_DIR       := $(ETC_DIR)/certs
DATA_DIR       := $(OPT_DIR)/data
CACHE_DIR      := $(OPT_DIR)/cache
LOG_DIR        := $(OPT_DIR)/log

# Guard user/group
GUARD_USER     := orbital-guard
GUARD_GROUP    := orbital
GUARD_GID      := 1500

# LaunchDaemon
PLIST_NAME     := com.claude.orbital.plist
PLIST_SRC      := $(CURDIR)/$(PLIST_NAME)
PLIST_DST      := /Library/LaunchDaemons/$(PLIST_NAME)

.PHONY: build sign verify create-signing-cert \
        setup-guard teardown-guard \
        install uninstall start stop restart status logs \
        clean help uninstall-legacy

# ---------------------------------------------------------------------------
# build — compile the Go binary (LLM-safe, no signing)
# ---------------------------------------------------------------------------
VERSION        := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT         := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS        := -X main.version=$(VERSION) -X main.commit=$(COMMIT)

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .
	@echo "✓ Built ./$(BINARY) $(VERSION) ($(COMMIT), unsigned)"

# ---------------------------------------------------------------------------
# sign — code-sign the binary (HUMAN ONLY — interactive prompt)
# ---------------------------------------------------------------------------
sign: build
	@echo ""
	@echo "============================================================"
	@echo "  ⚠️  CODE SIGNING — HUMAN INTERVENTION REQUIRED"
	@echo "============================================================"
	@echo ""
	@echo "  Identity: $(SIGN_IDENTITY)"
	@echo "  Binary:   ./$(BINARY)"
	@echo ""
	@echo "  You may be prompted for your Keychain password."
	@echo ""
	@bash -c 'read -p "  Type SIGN to proceed: " confirm && [ "$$confirm" = "SIGN" ]' \
		|| (echo "Aborted."; exit 1)
	codesign --sign "$(SIGN_IDENTITY)" --force --timestamp=none ./$(BINARY)
	@echo ""
	@echo "✓ Binary signed with '$(SIGN_IDENTITY)'"

# ---------------------------------------------------------------------------
# verify — check that the binary has a valid signature
# ---------------------------------------------------------------------------
verify:
	@codesign --verify --verbose ./$(BINARY) 2>&1 || \
		(echo "✗ Binary is NOT signed. Run: make sign"; exit 1)
	@echo "✓ Signature valid"

# ---------------------------------------------------------------------------
# create-signing-cert — one-time setup of code signing identity (HUMAN)
# ---------------------------------------------------------------------------
create-signing-cert:
	@echo ""
	@echo "============================================================"
	@echo "  Creating code signing certificate"
	@echo "============================================================"
	@echo ""
	@mkdir -p $(SIGN_CERT_DIR)
	@echo "  Generating RSA key and self-signed certificate..."
	openssl req -x509 -newkey rsa:4096 \
		-keyout $(SIGN_CERT_DIR)/codesign.key \
		-out $(SIGN_CERT_DIR)/codesign.crt \
		-days 3650 -nodes \
		-subj "/CN=$(SIGN_IDENTITY)" \
		-addext "keyUsage=digitalSignature" \
		-addext "extendedKeyUsage=codeSigning"
	@echo "  Importing key and certificate into login keychain..."
	security import $(SIGN_CERT_DIR)/codesign.key \
		-k ~/Library/Keychains/login.keychain-db \
		-T /usr/bin/codesign
	security import $(SIGN_CERT_DIR)/codesign.crt \
		-k ~/Library/Keychains/login.keychain-db \
		-T /usr/bin/codesign
	@echo ""
	@echo "============================================================"
	@echo "  MANUAL STEP REQUIRED:"
	@echo ""
	@echo "  1. Open Keychain Access"
	@echo "  2. Find '$(SIGN_IDENTITY)' in login keychain"
	@echo "  3. Double-click → Trust → Code Signing → Always Trust"
	@echo "  4. Close and enter your password to confirm"
	@echo ""
	@echo "  Then run: make build && make sign"
	@echo "============================================================"

# ---------------------------------------------------------------------------
# setup-guard — create orbital-guard user, group, and directories (sudo)
# ---------------------------------------------------------------------------
setup-guard:
	@echo "==> Creating group '$(GUARD_GROUP)' (GID $(GUARD_GID))"
	sudo dscl . -create /Groups/$(GUARD_GROUP)
	sudo dscl . -create /Groups/$(GUARD_GROUP) PrimaryGroupID $(GUARD_GID)
	sudo dscl . -create /Groups/$(GUARD_GROUP) RealName "Orbital Build Service"
	@echo "==> Creating user '$(GUARD_USER)'"
	sudo dscl . -create /Users/$(GUARD_USER)
	sudo dscl . -create /Users/$(GUARD_USER) UniqueID 401
	sudo dscl . -create /Users/$(GUARD_USER) PrimaryGroupID $(GUARD_GID)
	sudo dscl . -create /Users/$(GUARD_USER) UserShell /usr/bin/false
	sudo dscl . -create /Users/$(GUARD_USER) NFSHomeDirectory $(OPT_DIR)
	sudo dscl . -create /Users/$(GUARD_USER) RealName "Orbital Guard"
	sudo dscl . -create /Users/$(GUARD_USER) IsHidden 1
	sudo dseditgroup -o edit -a $(GUARD_USER) -t user $(GUARD_GROUP)
	@echo "==> Creating directory structure at $(OPT_DIR)"
	sudo mkdir -p $(BIN_DIR) $(ETC_DIR) $(CERT_DIR) \
		$(HOME)/orbital-data/workspaces $(HOME)/orbital-data/artifacts $(HOME)/orbital-data/certs \
		$(CACHE_DIR)/gradle $(LOG_DIR)
	@echo "==> Setting ownership and permissions"
	@# Private dirs: only orbital-guard
	sudo chown -R $(GUARD_USER):$(GUARD_GROUP) $(OPT_DIR)
	sudo chmod 750 $(OPT_DIR)
	sudo chmod 750 $(BIN_DIR)
	sudo chmod 700 $(ETC_DIR)
	sudo chmod 700 $(CACHE_DIR)
	sudo chmod 750 $(LOG_DIR)
	@# Shared data dir: orbital-guard:orbital with SGID (under ~/orbital-data for Docker VirtioFS)
	sudo chown -R $(GUARD_USER):$(GUARD_GROUP) $(HOME)/orbital-data
	sudo chmod 2775 $(HOME)/orbital-data
	sudo chmod 2775 $(HOME)/orbital-data/workspaces
	sudo chmod 2775 $(HOME)/orbital-data/artifacts
	sudo chmod 2775 $(HOME)/orbital-data/certs
	@echo "==> Setting ACL on Android SDK for read access"
	@if [ -n "$$ANDROID_HOME" ] && [ -d "$$ANDROID_HOME" ]; then \
		sudo chmod -R +a "$(GUARD_USER) allow read,execute,list,search" "$$ANDROID_HOME"; \
		echo "    ACL set on $$ANDROID_HOME"; \
	else \
		echo "    ⚠️  ANDROID_HOME not set — set ACL manually later:"; \
		echo "    sudo chmod -R +a '$(GUARD_USER) allow read,execute,list,search' /path/to/sdk"; \
	fi
	@echo ""
	@echo "✓ Guard setup complete"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Copy TLS certs:  sudo cp ~/.orbital/certs/* $(CERT_DIR)/"
	@echo "                      sudo cp ~/.orbital/certs/orbital-ca.crt $(DATA_DIR)/certs/"
	@echo "                      sudo chown -R $(GUARD_USER):$(GUARD_GROUP) $(CERT_DIR)"
	@echo "                      sudo chown $(GUARD_USER):$(GUARD_GROUP) $(DATA_DIR)/certs/orbital-ca.crt"
	@echo "  2. Create config:   sudo cp orbital.env.example $(ETC_DIR)/orbital.env"
	@echo "                      sudo chown $(GUARD_USER):$(GUARD_GROUP) $(ETC_DIR)/orbital.env"
	@echo "                      Edit $(ETC_DIR)/orbital.env with correct paths"
	@echo "  3. Add docker mount: /opt/orbital/data:/home/claude/orbital:rw"
	@echo "  4. Run:             make build && make sign && make install"

# ---------------------------------------------------------------------------
# install — install signed binary and LaunchDaemon (requires sudo)
# ---------------------------------------------------------------------------
install: verify
	@echo "==> Installing signed binary to $(BIN_DIR)/$(BINARY)"
	sudo mkdir -p $(BIN_DIR)
	sudo cp ./$(BINARY) $(BIN_DIR)/$(BINARY)
	sudo chown $(GUARD_USER):$(GUARD_GROUP) $(BIN_DIR)/$(BINARY)
	sudo chmod 755 $(BIN_DIR)/$(BINARY)
	@echo "==> Installing LaunchDaemon to $(PLIST_DST)"
	sudo cp $(PLIST_SRC) $(PLIST_DST)
	sudo chown root:wheel $(PLIST_DST)
	sudo chmod 644 $(PLIST_DST)
	@echo ""
	@echo "✓ Installed. Run: make start"

# ---------------------------------------------------------------------------
# uninstall — stop service, remove binary and plist
# ---------------------------------------------------------------------------
uninstall: stop
	@echo "==> Removing LaunchDaemon"
	-sudo rm -f $(PLIST_DST)
	@echo "==> Removing binary"
	-sudo rm -f $(BIN_DIR)/$(BINARY)
	@echo "✓ Uninstalled (directories and config preserved)"

# ---------------------------------------------------------------------------
# start / stop / restart — manage the LaunchDaemon
# ---------------------------------------------------------------------------
start:
	@if sudo launchctl list 2>/dev/null | grep -q com.claude.orbital; then \
		echo "==> Service already loaded — restarting"; \
		sudo launchctl bootout system/com.claude.orbital 2>/dev/null || true; \
		sleep 1; \
	fi
	sudo launchctl bootstrap system $(PLIST_DST)
	@echo "✓ Service started"

stop:
	-sudo launchctl bootout system/com.claude.orbital 2>/dev/null
	@echo "✓ Service stopped"

restart: stop
	@sleep 1
	@$(MAKE) start

# ---------------------------------------------------------------------------
# status — check if service is running
# ---------------------------------------------------------------------------
status:
	@if sudo launchctl list 2>/dev/null | grep -q com.claude.orbital; then \
		echo "orbital-server is RUNNING (as $(GUARD_USER))"; \
		sudo launchctl list com.claude.orbital 2>/dev/null; \
	else \
		echo "orbital-server is NOT running"; \
	fi

# ---------------------------------------------------------------------------
# logs — tail the service log
# ---------------------------------------------------------------------------
logs:
	@if [ -f "$(LOG_DIR)/orbital.log" ]; then \
		tail -f $(LOG_DIR)/orbital.log; \
	else \
		echo "No log file at $(LOG_DIR)/orbital.log"; \
	fi

# ---------------------------------------------------------------------------
# teardown-guard — remove user, group, and all directories (DESTRUCTIVE)
# ---------------------------------------------------------------------------
teardown-guard: uninstall
	@echo ""
	@echo "⚠️  This will delete the $(GUARD_USER) user and ALL data under $(OPT_DIR)"
	@bash -c 'read -p "Type TEARDOWN to proceed: " confirm && [ "$$confirm" = "TEARDOWN" ]' \
		|| (echo "Aborted."; exit 1)
	@echo "==> Removing user $(GUARD_USER)"
	-sudo dscl . -delete /Users/$(GUARD_USER)
	@echo "==> Removing group $(GUARD_GROUP)"
	-sudo dscl . -delete /Groups/$(GUARD_GROUP)
	@echo "==> Removing $(OPT_DIR)"
	-sudo rm -rf $(OPT_DIR)
	@echo "✓ Teardown complete"

# ---------------------------------------------------------------------------
# uninstall-legacy — remove old LaunchAgent-based installation
# ---------------------------------------------------------------------------
uninstall-legacy:
	@echo "==> Removing legacy installation"
	-launchctl unload $(HOME)/Library/LaunchAgents/$(PLIST_NAME) 2>/dev/null
	-rm -f $(HOME)/Library/LaunchAgents/$(PLIST_NAME)
	-sudo rm -f /usr/local/bin/orbital-server
	@echo "✓ Legacy installation removed"
	@echo "  Note: ~/.orbital.env and ~/.orbital/certs/ left in place"

# ---------------------------------------------------------------------------
# clean — remove local build artifact
# ---------------------------------------------------------------------------
clean:
	rm -f $(BINARY)

# ---------------------------------------------------------------------------
# help
# ---------------------------------------------------------------------------
help:
	@echo "Orbital Makefile — build service for agentic Android development"
	@echo ""
	@echo "First-time setup:"
	@echo "  make create-signing-cert  Create code signing certificate (HUMAN)"
	@echo "  make setup-guard          Create orbital-guard user & dirs (sudo)"
	@echo ""
	@echo "Build & deploy:"
	@echo "  make build                Compile Go binary"
	@echo "  make sign                 Sign binary (HUMAN ONLY)"
	@echo "  make verify               Verify binary signature"
	@echo "  make install              Install signed binary + LaunchDaemon"
	@echo ""
	@echo "Service management:"
	@echo "  make start                Start the service"
	@echo "  make stop                 Stop the service"
	@echo "  make restart              Restart the service"
	@echo "  make status               Check service status"
	@echo "  make logs                 Tail service logs"
	@echo ""
	@echo "Cleanup:"
	@echo "  make uninstall            Remove binary + plist (keep data)"
	@echo "  make teardown-guard       Remove user, group, ALL data"
	@echo "  make uninstall-legacy     Remove old LaunchAgent installation"
	@echo "  make clean                Remove local build artifact"
