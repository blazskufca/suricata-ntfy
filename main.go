package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/goccy/go-yaml"
)

type Config struct {
	TemplateString string            `yaml:"template"`
	Endpoint       string            `yaml:"endpoint"`
	Headers        map[string]string `yaml:"headers"`
	GlobPath       string            `yaml:"glob_path"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}
	return &cfg, nil
}

// LogFile wraps the file handle and its buffered reader.
type LogFile struct {
	Path   string
	File   *os.File
	Reader *bufio.Reader
}

// Tailer manages the watcher and the state of open files.
type Tailer struct {
	tmpl       *template.Template
	watcher    *fsnotify.Watcher
	mu         sync.Mutex
	files      map[string]*LogFile
	httpClient http.Client
	cfg        *Config
	syslogger  *syslog.Writer
}

// Helper logging functions
func (t *Tailer) logInfo(msg string) {
	if t.syslogger != nil {
		t.syslogger.Info(msg)
	} else {
		log.Println(msg)
	}
}

func (t *Tailer) logWarning(msg string) {
	if t.syslogger != nil {
		t.syslogger.Warning(msg)
	} else {
		log.Println("WARNING:", msg)
	}
}

func (t *Tailer) logError(msg string) {
	if t.syslogger != nil {
		t.syslogger.Err(msg)
	} else {
		log.Println("ERROR:", msg)
	}
}

func NewTailer(cfg *Config) (*Tailer, error) {
	tmpl, err := template.New("log").Option("missingkey=zero").Parse(cfg.TemplateString)
	if err != nil {
		return nil, fmt.Errorf("invalid template: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	// Connect to syslog - use LOG_DAEMON for pfSense compatibility
	syslogger, err := syslog.New(syslog.LOG_NOTICE|syslog.LOG_DAEMON, "suricata-tailer")
	if err != nil {
		// If syslog fails, fall back to stderr
		log.Printf("Warning: failed to connect to syslog: %v, using stderr", err)
		syslogger = nil
	} else {
		// Also set the standard logger to use syslog
		log.SetOutput(syslogger)
		log.SetFlags(0) // syslog handles timestamps
	}

	t := &Tailer{
		tmpl:      tmpl,
		watcher:   watcher,
		files:     make(map[string]*LogFile),
		cfg:       cfg,
		syslogger: syslogger,
		httpClient: http.Client{
			Timeout: 10 * time.Second,
		},
	}

	matches, _ := filepath.Glob(cfg.GlobPath)
	if len(matches) == 0 {
		return nil, fmt.Errorf("warning: no log files found matching pattern %s initially", cfg.GlobPath)
	}

	for _, path := range matches {
		if err := t.addFile(path); err != nil {
			return nil, fmt.Errorf("failed to track file %s: %v", path, err)
		}
	}

	return t, nil
}

// Run starts the event loop. It blocks until context is canceled.
func (t *Tailer) Run(ctx context.Context) error {
	defer t.Close()

	log.Println("Tailer started...")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case event, ok := <-t.watcher.Events:
			if !ok {
				return nil
			}
			t.handleEvent(event)

		case err, ok := <-t.watcher.Errors:
			if !ok {
				return nil
			}
			t.logError(fmt.Sprintf("Watcher error: %v", err))
		}
	}
}

// Close cleans up file handles and the watcher.
func (t *Tailer) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()

	_ = t.watcher.Close()
	for _, lf := range t.files {
		_ = lf.File.Close()
	}
	t.files = make(map[string]*LogFile)
	if t.syslogger != nil {
		_ = t.syslogger.Close()
	}
}

func (t *Tailer) handleEvent(event fsnotify.Event) {
	switch {
	case event.Op&fsnotify.Write == fsnotify.Write:
		t.handleWrite(event.Name)

	case event.Op&fsnotify.Remove == fsnotify.Remove, event.Op&fsnotify.Rename == fsnotify.Rename:
		t.handleRotation(event.Name)
	}
}

func (t *Tailer) handleWrite(path string) {
	t.mu.Lock()
	lf, exists := t.files[path]
	t.mu.Unlock()

	if !exists {
		return
	}

	for {
		line, err := lf.Reader.ReadBytes('\n')
		if len(line) > 0 {
			t.processLine(line)
		}

		if err != nil {
			if err != io.EOF {
				t.logError(fmt.Sprintf("error reading %s: %v", path, err))
			}
			return
		}
	}
}

func (t *Tailer) handleRotation(path string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if lf, exists := t.files[path]; exists {
		t.logInfo(fmt.Sprintf("File rotated/removed: %s", path))
		_ = lf.File.Close()
		delete(t.files, path)
	}
}

// addFile opens a file, seeks to end, and adds to watcher.
func (t *Tailer) addFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}

	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return err
	}

	if err := t.watcher.Add(path); err != nil {
		_ = f.Close()
		return err
	}

	t.mu.Lock()
	t.files[path] = &LogFile{
		Path:   path,
		File:   f,
		Reader: bufio.NewReader(f),
	}
	t.mu.Unlock()

	return nil
}

func (t *Tailer) processLine(raw []byte) {
	var entry map[string]any
	if err := json.Unmarshal(raw, &entry); err != nil {
		return
	}

	var buf bytes.Buffer
	if err := t.tmpl.Execute(&buf, entry); err != nil {
		t.logError(fmt.Sprintf("Template execute error: %v", err))
		return
	}

	buf.WriteByte('\n')
	req, err := http.NewRequest(http.MethodPost, t.cfg.Endpoint, &buf)
	if err != nil {
		t.logError(fmt.Sprintf("Request creation error: %v", err))
		return
	}

	for k, v := range t.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		t.logError(fmt.Sprintf("Request error to %s: %v", t.cfg.Endpoint, err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.logWarning(fmt.Sprintf("Non-OK response from %s: %v", t.cfg.Endpoint, resp.Status))
		return
	}

	t.logInfo("Alert sent successfully")
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	cfs := flag.String("config", "/usr/local/etc/suricata-tailer/config.yaml", "Path to config file")
	if cfs == nil || *cfs == "" {
		log.Fatalf("missing required flag: -config")
	}

	cfg, err := LoadConfig(*cfs)
	if err != nil {
		log.Fatalf("Config error: %v", err)
	}

	app, err := NewTailer(cfg)
	if err != nil {
		log.Fatalf("Initialization error: %v", err)
	}

	if err := app.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("Runtime error: %v", err)
	}

	log.Println("Shutdown complete.")
}
