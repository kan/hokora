// Package hokora is a client for the hokora secret management server.
//
// A hokora server hands a machine a short-lived token in exchange for its
// client credential, then returns the secrets that the machine is granted.
// This package performs that exchange and holds the returned values in
// memory only; it never writes them to disk and keeps no cache.
//
// # Credentials
//
// New resolves the client credential, server address, project, and
// environment from three sources, in order:
//
//  1. Options passed to New (WithAddress, WithCredentials, WithProject, WithEnv).
//  2. A credentials file. Under systemd this is $CREDENTIALS_DIRECTORY/hokora,
//     populated by LoadCredential=; the path can also be set with
//     WithCredentialsFile. The file holds KEY=VALUE lines:
//     HOKORA_ADDR, HOKORA_CLIENT_ID, HOKORA_CLIENT_SECRET, HOKORA_PROJECT,
//     HOKORA_ENV.
//  3. The same names as environment variables.
//
// A value found earlier in this list wins over a value found later.
//
// # Security
//
// This package does not defend against an attacker who has obtained the same
// operating-system user as your application. Such an attacker can read the
// machine credential (from $CREDENTIALS_DIRECTORY or the environment) and
// fetch the very same secrets, or read your process memory directly. Nor does
// it prevent the operating system from writing process memory to disk through
// swap, core dumps, or kernel crash dumps. See the project's threat model.
//
// This package never disables TLS certificate verification. To trust an
// internal certificate authority, pass its pool with WithRootCAs; there is no
// insecure-skip-verify option.
package hokora

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Credential and configuration key names, shared by the credentials file and
// the environment.
//
//nolint:gosec // G101: 認証情報ではなく、環境変数 / 設定キーの名前である
const (
	envAddr         = "HOKORA_ADDR"
	envClientID     = "HOKORA_CLIENT_ID"
	envClientSecret = "HOKORA_CLIENT_SECRET"
	envProject      = "HOKORA_PROJECT"
	envEnv          = "HOKORA_ENV"
)

// credentialsFileName is the file systemd's LoadCredential= exposes under
// $CREDENTIALS_DIRECTORY.
const credentialsFileName = "hokora"

// defaultTimeout bounds a single request to the server.
const defaultTimeout = 15 * time.Second

// maxResponseBytes caps a server response. Secret payloads are small; a
// response larger than this indicates the wrong endpoint or a hostile peer.
const maxResponseBytes = 4 << 20

// Config carries the resolved connection settings. Fields are filled from
// options, then the credentials file, then the environment.
type config struct {
	addr         string
	clientID     string
	clientSecret string
	project      string
	env          string

	credentialsFile string
	rootCAs         *x509.CertPool
	httpClient      *http.Client
}

// Option configures a Client. See New for the resolution order.
type Option func(*config)

// WithAddress sets the base URL of the hokora server, for example
// "https://hokora.example.com:9443".
func WithAddress(addr string) Option {
	return func(c *config) { c.addr = addr }
}

// WithCredentials sets the machine credential explicitly.
func WithCredentials(clientID, clientSecret string) Option {
	return func(c *config) { c.clientID, c.clientSecret = clientID, clientSecret }
}

// WithProject sets the project slug to fetch.
func WithProject(project string) Option {
	return func(c *config) { c.project = project }
}

// WithEnv sets the environment slug to fetch.
func WithEnv(env string) Option {
	return func(c *config) { c.env = env }
}

// WithCredentialsFile reads settings from a KEY=VALUE file. When unset, New
// falls back to $CREDENTIALS_DIRECTORY/hokora if that variable is present.
func WithCredentialsFile(path string) Option {
	return func(c *config) { c.credentialsFile = path }
}

// WithRootCAs verifies the server against the given certificate pool,
// replacing the system roots. Use it when the server presents a certificate
// from an internal CA. To trust the internal CA in addition to the public
// roots, seed the pool from x509.SystemCertPool() before adding the CA;
// a pool cannot be merged with the system roots after the fact.
//
// There is no option to skip verification.
func WithRootCAs(pool *x509.CertPool) Option {
	return func(c *config) { c.rootCAs = pool }
}

// WithHTTPClient uses a caller-provided HTTP client instead of the default.
//
// The provided client's TLS configuration is used as-is; WithRootCAs is
// ignored when this option is set.
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) { c.httpClient = client }
}

var (
	// ErrMissingConfig indicates that a required setting could not be
	// resolved from options, the credentials file, or the environment.
	ErrMissingConfig = errors.New("hokora: missing configuration")

	// ErrUnauthorized indicates that the server rejected the credential.
	ErrUnauthorized = errors.New("hokora: invalid credentials")

	// ErrForbidden indicates that the machine is not granted the requested
	// project and environment.
	ErrForbidden = errors.New("hokora: forbidden")

	// ErrSealed indicates that the server is sealed and cannot serve secrets.
	ErrSealed = errors.New("hokora: server is sealed")
)

// Client fetches secrets from a hokora server. It is safe for concurrent use.
type Client struct {
	cfg  config
	http *http.Client
}

// New creates a Client, resolving settings as described in the package
// documentation.
func New(opts ...Option) (*Client, error) {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}
	if err := resolveConfig(&cfg, os.Getenv, os.ReadFile); err != nil {
		return nil, err
	}

	// **アドレスは https:// のみ許す。** http:// を受け入れると、設定ミスや
	// タイプミスで client_secret / トークン / secret 値が平文で流れる。TLS を
	// 無効化する手段は提供しない(AGENTS.md ルール 31、THREAT_MODEL §5.2)。
	if !strings.HasPrefix(cfg.addr, "https://") {
		return nil, fmt.Errorf("%w: server address must use https://", ErrMissingConfig)
	}

	httpClient := cfg.httpClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: defaultTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					RootCAs:    cfg.rootCAs,
				},
			},
		}
	}

	return &Client{cfg: cfg, http: httpClient}, nil
}

// resolveConfig fills the blanks in cfg from the credentials file and the
// environment. getenv and readFile are injected so the resolution can be
// tested without touching the real environment.
func resolveConfig(cfg *config, getenv func(string) string, readFile func(string) ([]byte, error)) error {
	fileValues, err := loadCredentialsFile(cfg.credentialsFile, getenv, readFile)
	if err != nil {
		return err
	}

	resolve := func(current *string, key string) {
		if *current != "" {
			return
		}
		if v := fileValues[key]; v != "" {
			*current = v
			return
		}
		*current = getenv(key)
	}

	resolve(&cfg.addr, envAddr)
	resolve(&cfg.clientID, envClientID)
	resolve(&cfg.clientSecret, envClientSecret)
	resolve(&cfg.project, envProject)
	resolve(&cfg.env, envEnv)

	var missing []string
	for _, f := range []struct {
		val, name string
	}{
		{cfg.addr, envAddr},
		{cfg.clientID, envClientID},
		{cfg.clientSecret, envClientSecret},
		{cfg.project, envProject},
		{cfg.env, envEnv},
	} {
		if f.val == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrMissingConfig, strings.Join(missing, ", "))
	}
	return nil
}

// loadCredentialsFile reads the KEY=VALUE file, if one is available.
//
// An explicit WithCredentialsFile path that cannot be read is an error. The
// systemd fallback ($CREDENTIALS_DIRECTORY/hokora) is optional: if the
// directory is set but the file is absent, resolution continues with the
// environment.
func loadCredentialsFile(explicit string, getenv func(string) string, readFile func(string) ([]byte, error)) (map[string]string, error) {
	path := explicit
	optional := false
	if path == "" {
		dir := getenv("CREDENTIALS_DIRECTORY")
		if dir == "" {
			return nil, nil
		}
		path = filepath.Join(dir, credentialsFileName)
		optional = true
	}

	data, err := readFile(path)
	if err != nil {
		if optional && errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("hokora: read credentials file %s: %w", path, err)
	}
	return parseCredentials(data), nil
}

// parseCredentials reads KEY=VALUE lines. Blank lines and lines beginning
// with '#' are ignored. Surrounding whitespace on the key is trimmed; the
// value is taken verbatim after the first '='.
func parseCredentials(data []byte) map[string]string {
	out := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(key)] = value
	}
	return out
}

// Fetch retrieves every secret the machine is granted for the configured
// project and environment.
//
// Each call authenticates and fetches; nothing is cached between calls. The
// caller owns the returned Secrets and should call Zero when finished.
func (c *Client) Fetch(ctx context.Context) (*Secrets, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	defer zero(token)

	req, err := c.newRequest(ctx, http.MethodGet,
		fmt.Sprintf("/v1/secrets?project=%s&env=%s",
			url.QueryEscape(c.cfg.project), url.QueryEscape(c.cfg.env)), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+string(token))

	var payload struct {
		Secrets map[string]string `json:"secrets"`
	}
	if err := c.do(req, &payload); err != nil {
		return nil, err
	}

	return newSecrets(payload.Secrets), nil
}

// FetchKey retrieves a single secret by key for the configured project and
// environment. It hits the server's single-key endpoint, so only that one key
// is read and audited — unlike Fetch, which reads (and audits) every granted
// key. Prefer FetchKey when you need one value.
//
// The returned Secrets holds just that key. As with Fetch, nothing is cached;
// the caller owns the result and should call Zero when finished. A key that
// does not exist is reported as ErrForbidden, indistinguishable from a missing
// grant (the server does not reveal which keys exist).
func (c *Client) FetchKey(ctx context.Context, key string) (*Secrets, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	defer zero(token)

	req, err := c.newRequest(ctx, http.MethodGet,
		fmt.Sprintf("/v1/secrets/%s?project=%s&env=%s",
			url.PathEscape(key),
			url.QueryEscape(c.cfg.project), url.QueryEscape(c.cfg.env)), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+string(token))

	var payload struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := c.do(req, &payload); err != nil {
		return nil, err
	}

	return newSecrets(map[string]string{payload.Key: payload.Value}), nil
}

// authenticate exchanges the credential for a bearer token.
func (c *Client) authenticate(ctx context.Context) ([]byte, error) {
	body, err := json.Marshal(map[string]string{
		"client_id":     c.cfg.clientID,
		"client_secret": c.cfg.clientSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("hokora: encode auth request: %w", err)
	}
	// client_secret を含むボディは best effort で消す(cfg.clientSecret 自体は
	// string で残るが、消せるバッファはトークン処理と揃えて消す)。
	defer zero(body)

	req, err := c.newRequest(ctx, http.MethodPost, "/v1/auth/token", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	var payload struct {
		Token string `json:"token"`
	}
	if err := c.do(req, &payload); err != nil {
		return nil, err
	}
	if payload.Token == "" {
		return nil, errors.New("hokora: server returned an empty token")
	}
	return []byte(payload.Token), nil
}

// newRequest builds a request against the configured server address.
func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.cfg.addr, "/")+path, body)
	if err != nil {
		return nil, fmt.Errorf("hokora: build request: %w", err)
	}
	return req, nil
}

// do sends the request and decodes a successful JSON body into dst. It maps
// the server's error responses to the package's sentinel errors.
func (c *Client) do(req *http.Request, dst any) (err error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("hokora: request to %s: %w", c.cfg.addr, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("hokora: close response: %w", cerr)
		}
	}()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("hokora: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return c.statusError(resp.StatusCode, data)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("hokora: decode response: %w", err)
	}
	return nil
}

// statusError maps a non-200 status to a sentinel error.
func (c *Client) statusError(status int, body []byte) error {
	var e struct {
		Error string `json:"error"`
	}
	if jsonErr := json.Unmarshal(body, &e); jsonErr != nil {
		e.Error = "" // エラーボディが JSON でなければ理由は不明とする
	}

	switch status {
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusServiceUnavailable:
		if e.Error == "sealed" {
			return ErrSealed
		}
		return fmt.Errorf("hokora: server unavailable: %s", e.Error)
	case http.StatusTooManyRequests:
		return fmt.Errorf("hokora: rate limited")
	default:
		if e.Error != "" {
			return fmt.Errorf("hokora: server returned status %d: %s", status, e.Error)
		}
		return fmt.Errorf("hokora: server returned status %d", status)
	}
}
