package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type config struct {
	SSHAddr             string
	SSHUser             string
	SSHPassword         string
	SSHPrivateKeyPath   string
	SSHKnownHostsPath   string
	SSHInsecureHostKey  bool
	RemoteBindAddr      string
	TargetHTTPS         string
	RecordDir           string
	RequestBodyLimitB   int64
	ResponseBodyLimitB  int64
	IdleTimeout         time.Duration
	ReadHeaderTimeout   time.Duration
	ShutdownGracePeriod time.Duration
}

type recorder struct {
	mu   sync.Mutex
	fh   *os.File
	path string
}

type trafficRecord struct {
	Timestamp          time.Time           `json:"timestamp"`
	SessionID          string              `json:"session_id"`
	RemoteAddr         string              `json:"remote_addr"`
	Method             string              `json:"method"`
	URL                string              `json:"url"`
	RequestHeaders     map[string][]string `json:"request_headers"`
	RequestBodyBase64  string              `json:"request_body_base64"`
	RequestBodyBytes   int                 `json:"request_body_bytes"`
	RequestBodyCut     bool                `json:"request_body_truncated"`
	StatusCode         int                 `json:"status_code"`
	ResponseHeaders    map[string][]string `json:"response_headers"`
	ResponseBodyBase64 string              `json:"response_body_base64"`
	ResponseBodyBytes  int                 `json:"response_body_bytes"`
	ResponseBodyCut    bool                `json:"response_body_truncated"`
	Upgraded           bool                `json:"upgraded"`
}

func (r *recorder) write(v any) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := r.fh.Write(append(b, '\n')); err != nil {
		return err
	}
	return r.fh.Sync()
}

func (r *recorder) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fh == nil {
		return nil
	}
	err := r.fh.Close()
	r.fh = nil
	return err
}

type bodyCapture struct {
	buf       bytes.Buffer
	written   int
	limit     int64
	truncated bool
}

func (c *bodyCapture) Write(p []byte) {
	c.written += len(p)
	if c.limit <= 0 {
		c.buf.Write(p)
		return
	}

	remaining := int(c.limit) - c.buf.Len()
	if remaining <= 0 {
		c.truncated = true
		return
	}
	if len(p) > remaining {
		c.buf.Write(p[:remaining])
		c.truncated = true
		return
	}
	c.buf.Write(p)
}

type loggingResponseWriter struct {
	w           http.ResponseWriter
	headersSeen map[string][]string
	statusCode  int
	body        bodyCapture
	wroteHeader bool
}

func newLoggingResponseWriter(w http.ResponseWriter, bodyLimit int64) *loggingResponseWriter {
	return &loggingResponseWriter{
		w:          w,
		statusCode: http.StatusOK,
		body: bodyCapture{
			limit: bodyLimit,
		},
	}
}

func (l *loggingResponseWriter) Header() http.Header {
	return l.w.Header()
}

func (l *loggingResponseWriter) WriteHeader(statusCode int) {
	if l.wroteHeader {
		l.w.WriteHeader(statusCode)
		return
	}
	l.statusCode = statusCode
	l.headersSeen = cloneHeader(l.w.Header())
	l.wroteHeader = true
	l.w.WriteHeader(statusCode)
}

func (l *loggingResponseWriter) Write(p []byte) (int, error) {
	if !l.wroteHeader {
		l.WriteHeader(http.StatusOK)
	}
	l.body.Write(p)
	return l.w.Write(p)
}

func (l *loggingResponseWriter) Flush() {
	if f, ok := l.w.(http.Flusher); ok {
		f.Flush()
	}
}

func (l *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := l.w.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	return h.Hijack()
}

func (l *loggingResponseWriter) Push(target string, opts *http.PushOptions) error {
	p, ok := l.w.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return p.Push(target, opts)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if err := newRootCmd().Execute(); err != nil {
		log.Fatalf("command failed: %v", err)
	}
}

func newRootCmd() *cobra.Command {
	var cfg config

	cmd := &cobra.Command{
		Use:   "hrp",
		Short: "SSH remote-bind HTTP reverse proxy to localhost HTTPS",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runApp(cfg)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	flags := cmd.Flags()
	flags.StringVar(&cfg.SSHAddr, "ssh-addr", "", "SSH server address host:port")
	flags.StringVar(&cfg.SSHUser, "ssh-user", "", "SSH username")
	flags.StringVar(&cfg.SSHPassword, "ssh-password", "", "SSH password (optional if using key auth)")
	flags.StringVar(&cfg.SSHPrivateKeyPath, "ssh-key", "", "Path to SSH private key (optional)")
	flags.StringVar(&cfg.SSHKnownHostsPath, "ssh-known-hosts", "", "Path to known_hosts file")
	flags.BoolVar(&cfg.SSHInsecureHostKey, "ssh-insecure-host-key", true, "Skip SSH host key verification")
	flags.StringVar(&cfg.RemoteBindAddr, "remote-bind", "127.0.0.1:18080", "Remote TCP listen address on SSH server")
	flags.StringVar(&cfg.TargetHTTPS, "target-https", "https://localhost:8443", "Target HTTPS server URL")
	flags.StringVar(&cfg.RecordDir, "record-dir", "./sessions", "Directory where per-session logs are written")
	flags.Int64Var(&cfg.RequestBodyLimitB, "request-body-limit", 10*1024*1024, "Max request body bytes to store per exchange (0 = unlimited)")
	flags.Int64Var(&cfg.ResponseBodyLimitB, "response-body-limit", 10*1024*1024, "Max response body bytes to store per exchange (0 = unlimited)")
	flags.DurationVar(&cfg.IdleTimeout, "idle-timeout", 120*time.Second, "HTTP idle timeout per proxied connection")
	flags.DurationVar(&cfg.ReadHeaderTimeout, "read-header-timeout", 10*time.Second, "HTTP read header timeout")
	flags.DurationVar(&cfg.ShutdownGracePeriod, "shutdown-grace", 3*time.Second, "Grace period before forcibly closing session server")

	_ = cmd.MarkFlagRequired("ssh-addr")
	_ = cmd.MarkFlagRequired("ssh-user")

	return cmd
}

func runApp(cfg config) error {

	if err := validateConfig(cfg); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	if err := os.MkdirAll(cfg.RecordDir, 0o755); err != nil {
		return fmt.Errorf("create record dir: %w", err)
	}

	targetURL, err := url.Parse(cfg.TargetHTTPS)
	if err != nil {
		return fmt.Errorf("parse target URL: %w", err)
	}

	sshClient, err := connectSSH(cfg)
	if err != nil {
		return fmt.Errorf("SSH connect failed: %w", err)
	}
	defer sshClient.Close()

	remoteListener, err := sshClient.Listen("tcp", cfg.RemoteBindAddr)
	if err != nil {
		return fmt.Errorf("remote listen failed on %q: %w", cfg.RemoteBindAddr, err)
	}
	defer remoteListener.Close()

	log.Printf("SSH connected to %s, serving remote TCP %s -> %s", cfg.SSHAddr, cfg.RemoteBindAddr, cfg.TargetHTTPS)

	proxy := makeProxy(targetURL)
	var seq uint64

	for {
		conn, err := remoteListener.Accept()
		if err != nil {
			if isTemporary(err) {
				log.Printf("accept temporary error: %v", err)
				continue
			}
			return fmt.Errorf("accept error: %w", err)
		}

		sessionID := makeSessionID(atomic.AddUint64(&seq, 1))
		rec, err := newRecorder(cfg.RecordDir, sessionID)
		if err != nil {
			log.Printf("session %s: recorder create failed: %v", sessionID, err)
			_ = conn.Close()
			continue
		}

		log.Printf("session %s: accepted %s", sessionID, conn.RemoteAddr())
		go serveSession(conn, sessionID, proxy, rec, cfg)
	}
}

func validateConfig(cfg config) error {
	if cfg.SSHAddr == "" {
		return errors.New("-ssh-addr is required")
	}
	if cfg.SSHUser == "" {
		return errors.New("-ssh-user is required")
	}
	target, err := url.Parse(cfg.TargetHTTPS)
	if err != nil {
		return fmt.Errorf("invalid -target-https: %w", err)
	}
	if !strings.EqualFold(target.Scheme, "https") {
		return errors.New("-target-https must use https://")
	}
	if target.Host == "" {
		return errors.New("-target-https host is empty")
	}
	return nil
}

func connectSSH(cfg config) (*ssh.Client, error) {
	authMethods, err := buildAuthMethods(cfg)
	if err != nil {
		return nil, err
	}

	hostKeyCallback, err := buildHostKeyCallback(cfg)
	if err != nil {
		return nil, err
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.SSHUser,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         15 * time.Second,
	}

	return ssh.Dial("tcp", cfg.SSHAddr, sshConfig)
}

func buildAuthMethods(cfg config) ([]ssh.AuthMethod, error) {
	methods := make([]ssh.AuthMethod, 0, 2)
	if cfg.SSHPassword != "" {
		methods = append(methods, ssh.Password(cfg.SSHPassword))
	}

	// Determine key path: use explicit path or try default keys
	keyPath := cfg.SSHPrivateKeyPath
	if keyPath == "" {
		defaultPath := findDefaultSSHKey()
		if defaultPath != "" {
			keyPath = defaultPath
		}
	}

	// Try to load the private key
	if keyPath != "" {
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read private key: %w", err)
		}

		// Try to parse without passphrase first
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			// If parsing failed due to encryption, prompt for passphrase
			errMsg := err.Error()
			if strings.Contains(errMsg, "encrypted") || strings.Contains(errMsg, "passphrase protected") {
				passphrase, err := promptPassphrase()
				if err != nil {
					return nil, fmt.Errorf("passphrase prompt failed: %w", err)
				}
				signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
				if err != nil {
					return nil, fmt.Errorf("parse private key with passphrase: %w", err)
				}
			} else {
				return nil, fmt.Errorf("parse private key: %w", err)
			}
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if len(methods) == 0 {
		return nil, errors.New("no SSH auth methods configured (provide -ssh-password or -ssh-key, or have a default key in ~/.ssh/)")
	}
	return methods, nil
}

func findDefaultSSHKey() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	// Try common default key locations
	defaultKeys := []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_ecdsa"),
		filepath.Join(home, ".ssh", "id_rsa"),
	}

	for _, path := range defaultKeys {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func promptPassphrase() (string, error) {
	fmt.Print("Enter passphrase for SSH key: ")
	reader := bufio.NewReader(os.Stdin)
	passphrase, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(passphrase, "\n"), nil
}

func buildHostKeyCallback(cfg config) (ssh.HostKeyCallback, error) {
	if cfg.SSHInsecureHostKey {
		return ssh.InsecureIgnoreHostKey(), nil
	}

	knownHostsPath := cfg.SSHKnownHostsPath
	if knownHostsPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home dir for known_hosts: %w", err)
		}
		knownHostsPath = filepath.Join(home, ".ssh", "known_hosts")
	}

	return knownhosts.New(knownHostsPath)
}

func makeProxy(target *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
	}

	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "localhost",
			MinVersion:         tls.VersionTLS12,
		},
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy error for %s %s: %v", r.Method, r.URL.String(), err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	return proxy
}

func serveSession(conn net.Conn, sessionID string, proxy *httputil.ReverseProxy, rec *recorder, cfg config) {
	defer conn.Close()
	defer rec.close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCapture := captureRequestBody(r, cfg.RequestBodyLimitB)
		lrw := newLoggingResponseWriter(w, cfg.ResponseBodyLimitB)

		proxy.ServeHTTP(lrw, r)

		respHeaders := lrw.headersSeen
		if respHeaders == nil {
			respHeaders = cloneHeader(lrw.Header())
		}

		record := trafficRecord{
			Timestamp:          time.Now().UTC(),
			SessionID:          sessionID,
			RemoteAddr:         r.RemoteAddr,
			Method:             r.Method,
			URL:                r.URL.String(),
			RequestHeaders:     cloneHeader(r.Header),
			RequestBodyBase64:  base64.StdEncoding.EncodeToString(requestCapture.buf.Bytes()),
			RequestBodyBytes:   requestCapture.written,
			RequestBodyCut:     requestCapture.truncated,
			StatusCode:         lrw.statusCode,
			ResponseHeaders:    respHeaders,
			ResponseBodyBase64: base64.StdEncoding.EncodeToString(lrw.body.buf.Bytes()),
			ResponseBodyBytes:  lrw.body.written,
			ResponseBodyCut:    lrw.body.truncated,
			Upgraded:           isUpgradeRequest(r) || lrw.statusCode == http.StatusSwitchingProtocols,
		}

		if err := rec.write(record); err != nil {
			log.Printf("session %s: write record failed: %v", sessionID, err)
		}
	})

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		if err := srv.Serve(&singleConnListener{conn: conn}); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("session %s: serve error: %v", sessionID, err)
		}
	}()

	<-serveDone
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGracePeriod)
	defer cancel()
	_ = srv.Shutdown(ctx)

	log.Printf("session %s: closed", sessionID)
}

func captureRequestBody(r *http.Request, limit int64) bodyCapture {
	if r.Body == nil {
		return bodyCapture{limit: limit}
	}

	data, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(data))

	cap := bodyCapture{limit: limit}
	cap.Write(data)
	return cap
}

func isUpgradeRequest(r *http.Request) bool {
	if !headerContainsToken(r.Header, "Connection", "upgrade") {
		return false
	}
	return r.Header.Get("Upgrade") != ""
}

func headerContainsToken(h http.Header, key, token string) bool {
	for _, value := range h.Values(key) {
		parts := strings.Split(value, ",")
		for _, part := range parts {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func cloneHeader(src http.Header) map[string][]string {
	if src == nil {
		return nil
	}
	dst := make(map[string][]string, len(src))
	for k, values := range src {
		copied := make([]string, len(values))
		copy(copied, values)
		dst[k] = copied
	}
	return dst
}

func newRecorder(dir, sessionID string) (*recorder, error) {
	path := filepath.Join(dir, sessionID+".jsonl")
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &recorder{fh: fh, path: path}, nil
}

func makeSessionID(seq uint64) string {
	randomPart := make([]byte, 4)
	if _, err := rand.Read(randomPart); err != nil {
		return fmt.Sprintf("%d-%d", time.Now().UTC().UnixNano(), seq)
	}
	return fmt.Sprintf("%d-%d-%s", time.Now().UTC().UnixNano(), seq, hex.EncodeToString(randomPart))
}

type singleConnListener struct {
	conn net.Conn
	used atomic.Bool
}

func (s *singleConnListener) Accept() (net.Conn, error) {
	if s.used.Swap(true) {
		return nil, net.ErrClosed
	}
	return s.conn, nil
}

func (s *singleConnListener) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *singleConnListener) Addr() net.Addr {
	if s.conn != nil {
		return s.conn.LocalAddr()
	}
	return &net.TCPAddr{}
}

func isTemporary(err error) bool {
	type temporary interface {
		Temporary() bool
	}
	var te temporary
	if errors.As(err, &te) {
		return te.Temporary()
	}
	return false
}
