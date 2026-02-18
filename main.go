package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	// -----------------------------------------------------------------------
	// Flags
	// -----------------------------------------------------------------------
	port := flag.Int("port", 9090, "HTTP listen port")
	baseDir := flag.String("base-dir", "", "Base directory for workspaces and artifacts (default: ~/claude-share/orbital)")
	configFile := flag.String("config", "", "Path to config env file (default: ~/.orbital.env)")
	tlsCert := flag.String("tls-cert", "", "Path to TLS certificate file (enables HTTPS)")
	tlsKey := flag.String("tls-key", "", "Path to TLS private key file")
	flag.Parse()

	// Set umask for group-writable files (shared with container via orbital group).
	syscall.Umask(0o002)

	if *baseDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("cannot determine home directory: %v", err)
		}
		*baseDir = filepath.Join(home, "claude-share", "orbital")
	}

	// -----------------------------------------------------------------------
	// Load optional config from env file
	// -----------------------------------------------------------------------
	loadEnvFile(*configFile)

	// -----------------------------------------------------------------------
	// Ensure base directories exist
	// -----------------------------------------------------------------------
	for _, sub := range []string{"workspaces", "artifacts"} {
		dir := filepath.Join(*baseDir, sub)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("failed to create directory %s: %v", dir, err)
		}
	}

	// -----------------------------------------------------------------------
	// Resolve TLS cert/key from flags or environment
	// -----------------------------------------------------------------------
	if *tlsCert == "" {
		*tlsCert = os.Getenv("ORBITAL_TLS_CERT")
	}
	if *tlsKey == "" {
		*tlsKey = os.Getenv("ORBITAL_TLS_KEY")
	}
	useTLS := *tlsCert != "" && *tlsKey != ""

	log.Printf("orbital: base directory = %s", *baseDir)
	log.Printf("orbital: ANDROID_HOME = %s", os.Getenv("ANDROID_HOME"))
	log.Printf("orbital: JAVA_HOME = %s", os.Getenv("JAVA_HOME"))
	log.Printf("orbital: GRADLE_USER_HOME = %s", os.Getenv("GRADLE_USER_HOME"))
	if useTLS {
		log.Printf("orbital: TLS enabled (cert=%s)", *tlsCert)
	}

	// -----------------------------------------------------------------------
	// Security
	// -----------------------------------------------------------------------
	policy := DefaultPolicy()
	if auditPath := os.Getenv("ORBITAL_AUDIT_LOG"); auditPath != "" {
		policy.AuditLogPath = auditPath
	}
	audit := NewAuditLogger(policy.AuditLogPath)
	defer audit.Close()

	// -----------------------------------------------------------------------
	// Managers
	// -----------------------------------------------------------------------
	bm := NewBuildManager(*baseDir, policy, audit)
	wm := NewWorkspaceManager(*baseDir)
	doc := NewDoctorManager(*baseDir)

	// Start the background cleanup goroutine.
	cleanupDone := make(chan struct{})
	wm.StartCleanupLoop(cleanupDone)

	// -----------------------------------------------------------------------
	// Routes
	// -----------------------------------------------------------------------
	mux := http.NewServeMux()

	// POST /build — start a new build
	mux.HandleFunc("/build", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			bm.handleStartBuild(w, r)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})

	// GET /builds — list all builds
	mux.HandleFunc("/builds", bm.handleListBuilds)

	// /build/ prefix — route to specific build handlers
	mux.HandleFunc("/build/", func(w http.ResponseWriter, r *http.Request) {
		// Parse: /build/<id> or /build/<id>/logs
		path := strings.TrimPrefix(r.URL.Path, "/build/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) == 0 || parts[0] == "" {
			http.Error(w, "build ID required", http.StatusBadRequest)
			return
		}

		id := parts[0]
		suffix := ""
		if len(parts) == 2 {
			suffix = parts[1]
		}

		switch {
		case suffix == "" && r.Method == http.MethodGet:
			bm.handleGetBuild(w, r, id)
		case suffix == "" && r.Method == http.MethodDelete:
			bm.handleCancelBuild(w, r, id)
		case suffix == "logs" && r.Method == http.MethodGet:
			bm.handleGetBuildLogs(w, r, id)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})

	// /workspaces — list or bulk delete
	mux.HandleFunc("/workspaces", wm.handleWorkspaces)

	// /workspaces/ prefix — specific workspace operations
	mux.HandleFunc("/workspaces/", func(w http.ResponseWriter, r *http.Request) {
		hash := strings.TrimPrefix(r.URL.Path, "/workspaces/")
		if hash == "" {
			wm.handleWorkspaces(w, r)
			return
		}
		wm.handleWorkspaceByHash(w, r, hash)
	})

	// Doctor — host-side health checks.
	mux.HandleFunc("/doctor", doc.handleDoctor)
	mux.HandleFunc("/doctor/fix", doc.handleDoctorFix)
	mux.HandleFunc("/doctor/token", doc.handleDoctorToken)
	mux.HandleFunc("/doctor/verify", doc.handleDoctorVerify)

	// Health check.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// -----------------------------------------------------------------------
	// Server
	// -----------------------------------------------------------------------
	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // SSE streams can be long-lived
		IdleTimeout:  120 * time.Second,
	}

	if useTLS {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("orbital: failed to load TLS cert/key: %v", err)
		}
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	// Graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("orbital: received %v, shutting down...", sig)
		close(cleanupDone)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("orbital: shutdown error: %v", err)
		}
	}()

	if useTLS {
		log.Printf("orbital: listening on %s (HTTPS)", addr)
		if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.Fatalf("orbital: server error: %v", err)
		}
	} else {
		log.Printf("orbital: listening on %s (HTTP)", addr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("orbital: server error: %v", err)
		}
	}
	log.Println("orbital: stopped")
}

// loadEnvFile reads a config file and sets environment variables.
// Falls back to ~/.orbital.env if no explicit path is given.
// Format: KEY=VALUE (one per line, # comments, empty lines ignored).
func loadEnvFile(path string) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return
		}
		path = filepath.Join(home, ".orbital.env")
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	log.Printf("orbital: loading config from %s", path)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		// Only set if not already in environment (don't override explicit env).
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}
}
