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
	"golang.org/x/time/rate"
)

type Config struct {
	TemplateString string            `yaml:"template"`
	Endpoint       string            `yaml:"endpoint"`
	Headers        map[string]string `yaml:"headers"`
	GlobPath       string            `yaml:"glob_path"`
	RateLimit      float64           `yaml:"rate_limit"`
	Burst          int               `yaml:"burst"`
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
	if cfg.Headers == nil {
		cfg.Headers = make(map[string]string)
	}
	return &cfg, nil
}

type LogFile struct {
	Path   string
	File   *os.File
	Reader *bufio.Reader
}

type Tailer struct {
	tmpl       *template.Template
	watcher    *fsnotify.Watcher
	mu         sync.Mutex
	files      map[string]*LogFile
	httpClient http.Client
	cfg        *Config
	syslogger  *syslog.Writer
	limiter    *rate.Limiter
	queue      chan []byte
	wg         sync.WaitGroup
}

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

	syslogger, err := syslog.New(syslog.LOG_NOTICE|syslog.LOG_DAEMON, "suricata-tailer")
	if err != nil {
		log.Printf("Warning: failed to connect to syslog: %v, using stderr", err)
		syslogger = nil
	} else {
		log.SetOutput(syslogger)
		log.SetFlags(0)
	}

	var limit rate.Limit
	if cfg.RateLimit > 0 {
		limit = rate.Limit(cfg.RateLimit)
	} else {
		limit = rate.Inf
	}

	burst := cfg.Burst
	if burst <= 0 {
		burst = 1
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
		limiter: rate.NewLimiter(limit, burst),
		queue:   make(chan []byte, 1000),
	}

	matches, _ := filepath.Glob(cfg.GlobPath)
	if len(matches) == 0 {
		t.logWarning(fmt.Sprintf("warning: no log files found matching pattern %s initially", cfg.GlobPath))
	}

	for _, path := range matches {
		if err := t.addFile(path); err != nil {
			return nil, fmt.Errorf("failed to track file %s: %v", path, err)
		}
	}

	return t, nil
}

func (t *Tailer) Run(ctx context.Context) error {
	defer t.Close()
	t.wg.Add(1)
	go t.worker(ctx)

	t.logInfo("Tailer started with rate limiting...")

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

// worker consumes the queue, respects the rate limit, and sends requests.
func (t *Tailer) worker(ctx context.Context) {
	defer t.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case rawLine, ok := <-t.queue:
			if err := t.limiter.Wait(ctx); err != nil {
				return
			}
			if !ok {
				t.logError("the queue has been closed")
				return
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.logError(fmt.Sprintf("Recovered from panic: %v", r))
					}
				}()
				t.sendAlert(rawLine)
			}()
		}
	}
}

func (t *Tailer) Close() {
	t.mu.Lock()

	_ = t.watcher.Close()
	for _, lf := range t.files {
		_ = lf.File.Close()
	}
	t.files = make(map[string]*LogFile)
	if t.syslogger != nil {
		_ = t.syslogger.Close()
	}
	t.mu.Unlock()
	t.wg.Wait()
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
			lineCopy := make([]byte, len(line))
			copy(lineCopy, line)

			t.queue <- lineCopy
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

func (t *Tailer) sendAlert(raw []byte) {
	var entry map[string]any
	if err := json.Unmarshal(raw, &entry); err != nil {
		t.logError(fmt.Sprintf("failed to unmarshal JSON: %v", err))
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
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	cfs := flag.String("config", "/usr/local/etc/suricata-tailer/config.yaml", "Path to config file")
	flag.Parse()

	if *cfs == "" {
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
