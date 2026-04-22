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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

type config struct {
	SSHAddr             string
	SSHUser             string
	SSHPassword         string
	SSHPrivateKeyPath   string
	SSHKnownHostsPath   string
	SSHInsecureHostKey  bool
	PublicOrigin        string
	PublicPrefix        string
	PreserveHost        bool
	Verbose             bool
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
	flags.StringVar(&cfg.SSHAddr, "ssh-addr", "", "SSH server address (host or host:port; defaults to port 22 if not specified)")
	flags.StringVar(&cfg.SSHUser, "ssh-user", "", "SSH username")
	flags.StringVar(&cfg.SSHPassword, "ssh-password", "", "SSH password (optional if using key auth)")
	flags.StringVar(&cfg.SSHPrivateKeyPath, "ssh-key", "", "Path to SSH private key (optional)")
	flags.StringVar(&cfg.SSHKnownHostsPath, "ssh-known-hosts", "", "Path to known_hosts file")
	flags.BoolVar(&cfg.SSHInsecureHostKey, "ssh-insecure-host-key", true, "Skip SSH host key verification")
	flags.StringVar(&cfg.PublicOrigin, "public-origin", "", "External public origin used for URL rewriting, e.g. https://partner-test.eu.socionext.com")
	flags.StringVar(&cfg.PublicPrefix, "public-prefix", "", "External path prefix mounted in front of hrp, e.g. /45e2383441efdf24b815a0c055227d9009a39f09")
	flags.BoolVar(&cfg.PreserveHost, "preserve-host", false, "Forward the incoming Host header to upstream instead of forcing the target host")
	flags.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose diagnostics for proxy and upstream behavior")
	flags.StringVar(&cfg.RemoteBindAddr, "remote-bind", "127.0.0.1:18080", "Remote TCP listen address on SSH server (can be just a port number for 127.0.0.1:port)")
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
	if err := validateConfig(&cfg); err != nil {
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

	if cfg.Verbose {
		log.Printf("verbose enabled: ssh=%s remote-bind=%s target=%s", cfg.SSHAddr, cfg.RemoteBindAddr, cfg.TargetHTTPS)
	}

	proxy := makeProxy(targetURL, cfg)
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

func validateConfig(cfg *config) error {
	if cfg.SSHAddr == "" {
		return errors.New("-ssh-addr is required")
	}
	if cfg.SSHUser == "" {
		return errors.New("-ssh-user is required")
	}

	// Normalize ssh-addr: add :22 if no port specified
	cfg.SSHAddr = normalizeSSHAddr(cfg.SSHAddr)

	// Normalize remote-bind: convert bare port number to 127.0.0.1:port
	cfg.RemoteBindAddr = normalizeRemoteBindAddr(cfg.RemoteBindAddr)
	cfg.PublicPrefix = normalizePublicPrefix(cfg.PublicPrefix)

	if cfg.PublicOrigin != "" {
		publicURL, err := url.Parse(cfg.PublicOrigin)
		if err != nil {
			return fmt.Errorf("invalid -public-origin: %w", err)
		}
		if publicURL.Scheme == "" || publicURL.Host == "" {
			return errors.New("-public-origin must include scheme and host")
		}
		if publicURL.Path != "" && publicURL.Path != "/" {
			return errors.New("-public-origin must not include a path; use -public-prefix for the path component")
		}
		cfg.PublicOrigin = strings.TrimRight(publicURL.String(), "/")
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

func normalizeSSHAddr(addr string) string {
	// If addr doesn't have a port, add :22
	if !strings.Contains(addr, ":") {
		return addr + ":22"
	}
	return addr
}

func normalizeRemoteBindAddr(addr string) string {
	// If addr is just a number (1-65535), assume it's a port on localhost
	if port, err := strconv.Atoi(strings.TrimSpace(addr)); err == nil && port > 0 && port <= 65535 {
		return fmt.Sprintf("127.0.0.1:%d", port)
	}
	return addr
}

func normalizePublicPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "/" {
		return ""
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return strings.TrimRight(prefix, "/")
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

	// Determine key paths: use explicit key, otherwise try all common defaults.
	keyPaths := make([]string, 0, 4)
	if cfg.SSHPrivateKeyPath != "" {
		keyPaths = append(keyPaths, cfg.SSHPrivateKeyPath)
	} else {
		keyPaths = findDefaultSSHKeys()
	}

	// Load all valid private keys so SSH can try each signer during auth.
	if len(keyPaths) > 0 {
		keyCallback := func() ([]ssh.Signer, error) {
			signers := make([]ssh.Signer, 0, len(keyPaths))
			cachedPassphrase := ""
			hasCachedPassphrase := false
			for _, keyPath := range keyPaths {
				key, err := os.ReadFile(keyPath)
				if err != nil {
					if cfg.SSHPrivateKeyPath != "" {
						return nil, fmt.Errorf("read private key %q: %w", keyPath, err)
					}
					log.Printf("skip unreadable default SSH key %q: %v", keyPath, err)
					continue
				}

				// Try to parse without passphrase first.
				signer, err := ssh.ParsePrivateKey(key)
				if err != nil {
					// If parsing failed due to encryption, prompt for passphrase.
					errMsg := err.Error()
					if strings.Contains(errMsg, "encrypted") || strings.Contains(errMsg, "passphrase protected") || strings.Contains(errMsg, "permission denied") {
						// Try previously entered passphrase first to avoid re-prompting.
						if hasCachedPassphrase {
							signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(cachedPassphrase))
						}
						if !hasCachedPassphrase || err != nil {
							passphrase, promptErr := promptPassphraseForKey(keyPath)
							if promptErr != nil {
								return nil, fmt.Errorf("passphrase prompt failed for %q: %w", keyPath, promptErr)
							}
							signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
							if err != nil {
								if cfg.SSHPrivateKeyPath != "" {
									return nil, fmt.Errorf("parse private key with passphrase %q: %w", keyPath, err)
								}
								log.Printf("skip default SSH key %q (passphrase parse failed): %v", keyPath, err)
								continue
							}
							cachedPassphrase = passphrase
							hasCachedPassphrase = true
						}
					} else {
						if cfg.SSHPrivateKeyPath != "" {
							return nil, fmt.Errorf("parse private key %q: %w", keyPath, err)
						}
						log.Printf("skip default SSH key %q (parse failed): %v", keyPath, err)
						continue
					}
				}

				signers = append(signers, signer)
			}

			if len(signers) == 0 {
				return nil, errors.New("no usable SSH private keys found")
			}
			return signers, nil
		}
		methods = append(methods, ssh.PublicKeysCallback(keyCallback))
	}

	if len(methods) == 0 {
		return nil, errors.New("no SSH auth methods configured (provide -ssh-password or -ssh-key, or have a default key in ~/.ssh/)")
	}
	return methods, nil
}

func findDefaultSSHKeys() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	// Try common default key locations
	defaultKeys := []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_ecdsa"),
		filepath.Join(home, ".ssh", "id_rsa"),
	}

	found := make([]string, 0, len(defaultKeys))
	for _, path := range defaultKeys {
		if _, err := os.Stat(path); err == nil {
			found = append(found, path)
		}
	}
	return found
}

func promptPassphraseForKey(keyPath string) (string, error) {
	fmt.Printf("Enter passphrase for SSH key %s: ", keyPath)
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println() // newline after hidden input
	return string(passphrase), nil
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

func makeProxy(target *url.URL, cfg config) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalPath := req.URL.Path
		publicInfo := resolvePublicRequestInfo(req, cfg)
		rewrittenPath := rewriteConnectAssetPath(req.URL.Path)
		if rewrittenPath != req.URL.Path {
			if cfg.Verbose {
				log.Printf("rewrite inbound path %q -> %q", req.URL.Path, rewrittenPath)
			}
			req.URL.Path = rewrittenPath
			req.URL.RawPath = rewrittenPath
		}
		incomingHost := req.Host
		originalDirector(req)
		if cfg.PreserveHost {
			req.Host = incomingHost
		} else {
			req.Host = target.Host
		}
		applyPublicForwardedHeaders(req, publicInfo, incomingHost)
		if cfg.Verbose && originalPath != req.URL.Path {
			log.Printf("director outbound path %q -> %q", originalPath, req.URL.Path)
		}
	}

	baseTransport := &http.Transport{
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
	if cfg.Verbose {
		proxy.Transport = &verboseRoundTripper{next: baseTransport}
	} else {
		proxy.Transport = baseTransport
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		return rewriteProxyResponse(resp, target, cfg)
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if cfg.Verbose {
			log.Printf("proxy error for %s %s: %v (req_ctx_err=%v)", r.Method, r.URL.String(), err, r.Context().Err())
		} else {
			log.Printf("proxy error for %s %s: %v", r.Method, r.URL.String(), err)
		}
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	return proxy
}

func serveSession(conn net.Conn, sessionID string, proxy *httputil.ReverseProxy, rec *recorder, cfg config) {
	defer conn.Close()
	defer rec.close()
	listener := newSingleConnListener(conn)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if cfg.Verbose {
			log.Printf("session %s: request start %s %s host=%s from=%s", sessionID, r.Method, r.URL.String(), r.Host, r.RemoteAddr)
		}

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

		if cfg.Verbose {
			log.Printf("session %s: request done %s %s status=%d duration=%s", sessionID, r.Method, r.URL.String(), lrw.statusCode, time.Since(start))
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
		if err := srv.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("session %s: serve error: %v", sessionID, err)
		}
	}()

	<-serveDone
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGracePeriod)
	defer cancel()
	_ = srv.Shutdown(ctx)

	log.Printf("session %s: closed", sessionID)
}

type verboseRoundTripper struct {
	next http.RoundTripper
}

func (v *verboseRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	log.Printf("upstream start: %s %s host=%s", req.Method, req.URL.String(), req.Host)
	resp, err := v.next.RoundTrip(req)
	if err != nil {
		log.Printf("upstream error: %s %s err=%T %v duration=%s", req.Method, req.URL.String(), err, err, time.Since(start))
		return nil, err
	}
	log.Printf("upstream done: %s %s status=%d duration=%s", req.Method, req.URL.String(), resp.StatusCode, time.Since(start))
	return resp, nil
}

func rewriteConnectAssetPath(path string) string {
	_, remainder, ok := splitConnectPath(path)
	if !ok {
		return path
	}
	for _, candidate := range []string{"/styles", "/images", "/js", "/app"} {
		if remainder == candidate || strings.HasPrefix(remainder, candidate+"/") {
			return remainder
		}
	}
	return path
}

func splitConnectPath(path string) (string, string, bool) {
	if !strings.HasPrefix(path, "/connect/") {
		return "", "", false
	}
	rest := strings.TrimPrefix(path, "/connect/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", "", false
	}
	return parts[0], "/" + parts[1], true
}

type publicRequestInfo struct {
	origin string
	host   string
	proto  string
	prefix string
}

func resolvePublicRequestInfo(req *http.Request, cfg config) publicRequestInfo {
	info := publicRequestInfo{}
	if cfg.PublicOrigin != "" {
		if publicURL, err := url.Parse(cfg.PublicOrigin); err == nil {
			info.origin = strings.TrimRight(cfg.PublicOrigin, "/")
			info.host = publicURL.Host
			info.proto = publicURL.Scheme
		}
	}

	if info.host == "" {
		info.host = firstHeaderValue(req.Header, "X-Forwarded-Host")
		if info.host == "" {
			info.host = req.Host
		}
	}
	if info.proto == "" {
		info.proto = firstHeaderValue(req.Header, "X-Forwarded-Proto")
		if info.proto == "" {
			if req.TLS != nil {
				info.proto = "https"
			} else {
				info.proto = "http"
			}
		}
	}
	if info.origin == "" && info.host != "" && info.proto != "" {
		info.origin = info.proto + "://" + info.host
	}

	info.prefix = cfg.PublicPrefix
	headerPrefix := firstHeaderValue(req.Header, "X-Forwarded-Prefix")
	if headerPrefix != "" {
		info.prefix = normalizePublicPrefix(headerPrefix)
	}

	return info
}

func firstHeaderValue(h http.Header, key string) string {
	value := strings.TrimSpace(h.Get(key))
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	return strings.TrimSpace(parts[0])
}

func applyPublicForwardedHeaders(req *http.Request, info publicRequestInfo, incomingHost string) {
	if info.host != "" {
		req.Header.Set("X-Forwarded-Host", info.host)
	} else if incomingHost != "" {
		req.Header.Set("X-Forwarded-Host", incomingHost)
	}
	if info.proto != "" {
		req.Header.Set("X-Forwarded-Proto", info.proto)
	}
	if info.prefix != "" {
		req.Header.Set("X-Forwarded-Prefix", info.prefix)
	}
}

func rewriteProxyResponse(resp *http.Response, target *url.URL, cfg config) error {
	publicInfo := resolvePublicRequestInfo(resp.Request, cfg)

	if location := resp.Header.Get("Location"); location != "" {
		if rewritten := rewriteLocation(location, resp.Request.URL.Path, target, publicInfo); rewritten != "" && rewritten != location {
			resp.Header.Set("Location", rewritten)
		}
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(contentType, "text/html") {
		return nil
	}
	contentEncoding := strings.TrimSpace(strings.ToLower(resp.Header.Get("Content-Encoding")))
	if contentEncoding != "" && contentEncoding != "identity" {
		if cfg.Verbose {
			log.Printf("skip HTML rewrite for encoded response: %s", contentEncoding)
		}
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}

	rewrittenBody := rewriteHTMLBody(string(body), resp.Request.URL.Path, target, publicInfo)
	resp.Body = io.NopCloser(strings.NewReader(rewrittenBody))
	resp.ContentLength = int64(len(rewrittenBody))
	resp.Header.Set("Content-Length", strconv.Itoa(len(rewrittenBody)))
	return nil
}

func rewriteLocation(location, requestPath string, target *url.URL, publicInfo publicRequestInfo) string {
	publicPathPrefix := publicInfo.prefix
	if strings.HasPrefix(location, "/") {
		if publicInfo.origin == "" && publicPathPrefix == "" {
			return ""
		}
		return publicInfo.origin + joinPublicPath(publicPathPrefix, location)
	}

	locationURL, err := url.Parse(location)
	if err != nil || locationURL.Scheme == "" || locationURL.Host == "" {
		return ""
	}

	if server, _, ok := splitConnectPath(requestPath); ok && locationURL.Path == "/agent" && samePort(locationURL, target) {
		return publicInfo.origin + joinPublicPath(publicPathPrefix, "/connect/"+server+"/agent")
	}
	if sameHost(locationURL, target) {
		return publicInfo.origin + joinPublicPath(publicPathPrefix, locationURL.Path)
	}
	return ""
}

func sameHost(left, right *url.URL) bool {
	return strings.EqualFold(left.Hostname(), right.Hostname())
}

func samePort(left, right *url.URL) bool {
	return effectivePort(left) == effectivePort(right)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	return ""
}

func rewriteHTMLBody(body, requestPath string, target *url.URL, publicInfo publicRequestInfo) string {
	publicRoot := publicBasePath(publicInfo.prefix)
	publicRootWithSlash := publicRoot
	if !strings.HasSuffix(publicRootWithSlash, "/") {
		publicRootWithSlash += "/"
	}

	replacements := []string{
		`href="styles/`, `href="` + publicRootWithSlash + `styles/`,
		`href="images/`, `href="` + publicRootWithSlash + `images/`,
		`href="js/`, `href="` + publicRootWithSlash + `js/`,
		`href="app/`, `href="` + publicRootWithSlash + `app/`,
		`src="styles/`, `src="` + publicRootWithSlash + `styles/`,
		`src="images/`, `src="` + publicRootWithSlash + `images/`,
		`src="js/`, `src="` + publicRootWithSlash + `js/`,
		`src="app/`, `src="` + publicRootWithSlash + `app/`,
		`action="styles/`, `action="` + publicRootWithSlash + `styles/`,
		`action="images/`, `action="` + publicRootWithSlash + `images/`,
		`action="js/`, `action="` + publicRootWithSlash + `js/`,
		`action="app/`, `action="` + publicRootWithSlash + `app/`,
		`href='styles/`, `href='` + publicRootWithSlash + `styles/`,
		`href='images/`, `href='` + publicRootWithSlash + `images/`,
		`href='js/`, `href='` + publicRootWithSlash + `js/`,
		`href='app/`, `href='` + publicRootWithSlash + `app/`,
		`src='styles/`, `src='` + publicRootWithSlash + `styles/`,
		`src='images/`, `src='` + publicRootWithSlash + `images/`,
		`src='js/`, `src='` + publicRootWithSlash + `js/`,
		`src='app/`, `src='` + publicRootWithSlash + `app/`,
		`action='styles/`, `action='` + publicRootWithSlash + `styles/`,
		`action='images/`, `action='` + publicRootWithSlash + `images/`,
		`action='js/`, `action='` + publicRootWithSlash + `js/`,
		`action='app/`, `action='` + publicRootWithSlash + `app/`,
	}
	body = strings.NewReplacer(replacements...).Replace(body)

	if strings.Contains(body, `<base href="../../">`) {
		body = strings.Replace(body, `<base href="../../">`, `<base href="`+publicRootWithSlash+`">`, 1)
	}
	if strings.Contains(body, `<base href='../../'>`) {
		body = strings.Replace(body, `<base href='../../'>`, `<base href='`+publicRootWithSlash+`'>`, 1)
	}

	if server, _, ok := splitConnectPath(requestPath); ok {
		backendAgentURL := target.Scheme + "://" + net.JoinHostPort(server, effectivePort(target)) + "/agent"
		publicAgentPath := joinPublicPath(publicInfo.prefix, "/connect/"+server+"/agent")
		if publicInfo.origin != "" {
			publicAgentPath = publicInfo.origin + publicAgentPath
		}
		body = strings.ReplaceAll(body, `action="`+backendAgentURL+`"`, `action="`+publicAgentPath+`"`)
		body = strings.ReplaceAll(body, `action='`+backendAgentURL+`'`, `action='`+publicAgentPath+`'`)

		publicHome := joinPublicPath(publicInfo.prefix, "/")
		if publicInfo.origin != "" {
			publicHome = publicInfo.origin + publicHome
		}
		body = strings.ReplaceAll(body, `document.location.href = '../';`, `document.location.href = '`+publicHome+`';`)
	}

	return body
}

func joinPublicPath(prefix, path string) string {
	prefix = normalizePublicPrefix(prefix)
	if path == "" {
		if prefix == "" {
			return "/"
		}
		return prefix + "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if prefix == "" {
		return path
	}
	return prefix + path
}

func publicBasePath(prefix string) string {
	if prefix == "" {
		return "/"
	}
	return prefix
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
	done chan struct{}
	once sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{
		conn: conn,
		done: make(chan struct{}),
	}
}

func (s *singleConnListener) Accept() (net.Conn, error) {
	if s.used.Swap(true) {
		<-s.done
		return nil, net.ErrClosed
	}
	return &trackedConn{Conn: s.conn, onClose: s.signalDone}, nil
}

func (s *singleConnListener) Close() error {
	s.signalDone()
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

func (s *singleConnListener) signalDone() {
	s.once.Do(func() {
		close(s.done)
	})
}

type trackedConn struct {
	net.Conn
	onClose func()
	once    sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.onClose)
	return err
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
