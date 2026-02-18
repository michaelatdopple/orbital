# ===========================================================================
# Orbital — host-side Makefile for macOS
#
# Builds the Go service, installs it as a launchd agent, and provides
# convenience targets for managing the running service.
#
# Binary name on host: orbital-server  (avoids conflict with the container
#                                        client binary named "orbital")
# Install location:    /usr/local/bin/orbital-server
# Config file:         ~/.orbital.env
# Log file:            /tmp/orbital.log
# launchd plist:       ~/Library/LaunchAgents/com.claude.orbital.plist
# ===========================================================================

BINARY      := orbital
INSTALL_BIN := /usr/local/bin/orbital-server
PLIST_NAME  := com.claude.orbital.plist
PLIST_SRC   := $(CURDIR)/$(PLIST_NAME)
PLIST_DST   := $(HOME)/Library/LaunchAgents/$(PLIST_NAME)
ENV_EXAMPLE := $(CURDIR)/orbital.env.example
ENV_DST     := $(HOME)/.orbital.env
LOG_FILE    := /tmp/orbital.log

.PHONY: build install uninstall start stop restart logs status clean

# ---------------------------------------------------------------------------
# build — compile the Go binary locally
# ---------------------------------------------------------------------------
build:
	go build -o $(BINARY) .

# ---------------------------------------------------------------------------
# install — build, copy binary + plist, seed config, load the service
# ---------------------------------------------------------------------------
install: build
	@echo "==> Installing binary to $(INSTALL_BIN)"
	sudo cp $(BINARY) $(INSTALL_BIN)
	sudo chmod 755 $(INSTALL_BIN)

	@echo "==> Installing plist to $(PLIST_DST)"
	@mkdir -p $(HOME)/Library/LaunchAgents
	sed 's|__HOME__|$(HOME)|g' $(PLIST_SRC) > $(PLIST_DST)

	@# Seed the config file from the example if it doesn't already exist.
	@if [ ! -f "$(ENV_DST)" ]; then \
		echo "==> Creating $(ENV_DST) from example (edit paths for your system)"; \
		cp $(ENV_EXAMPLE) $(ENV_DST); \
	else \
		echo "==> $(ENV_DST) already exists — skipping"; \
	fi

	@echo "==> Loading launchd agent"
	launchctl load $(PLIST_DST) 2>/dev/null || true
	@echo "==> Done. Check status with: make status"

# ---------------------------------------------------------------------------
# uninstall — stop the service, remove binary and plist
# ---------------------------------------------------------------------------
uninstall:
	@echo "==> Unloading launchd agent"
	-launchctl unload $(PLIST_DST) 2>/dev/null
	@echo "==> Removing binary $(INSTALL_BIN)"
	-sudo rm -f $(INSTALL_BIN)
	@echo "==> Removing plist $(PLIST_DST)"
	-rm -f $(PLIST_DST)
	@echo "==> Done (config file $(ENV_DST) left in place)"

# ---------------------------------------------------------------------------
# start — load the launchd agent (starts the service)
# ---------------------------------------------------------------------------
start:
	@if launchctl list | grep -q $(PLIST_NAME:.plist=); then \
		echo "==> Service already loaded — restarting"; \
		launchctl unload $(PLIST_DST) 2>/dev/null; \
	fi
	launchctl load $(PLIST_DST)
	@echo "==> Service started"

# ---------------------------------------------------------------------------
# stop — unload the launchd agent (stops the service)
# ---------------------------------------------------------------------------
stop:
	launchctl unload $(PLIST_DST)
	@echo "==> Service stopped"

# ---------------------------------------------------------------------------
# restart — stop + start
# ---------------------------------------------------------------------------
restart: stop start

# ---------------------------------------------------------------------------
# logs — tail the log file
# ---------------------------------------------------------------------------
logs:
	@if [ -f "$(LOG_FILE)" ]; then \
		tail -f $(LOG_FILE); \
	else \
		echo "No log file found at $(LOG_FILE)"; \
	fi

# ---------------------------------------------------------------------------
# status — check if the service is running
# ---------------------------------------------------------------------------
status:
	@if launchctl list | grep -q $(PLIST_NAME:.plist=); then \
		echo "orbital-server is RUNNING"; \
		launchctl list | grep $(PLIST_NAME:.plist=); \
	else \
		echo "orbital-server is NOT running"; \
	fi

# ---------------------------------------------------------------------------
# clean — remove local build artifact
# ---------------------------------------------------------------------------
clean:
	rm -f $(BINARY)
