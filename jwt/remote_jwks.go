package jwt

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v5"
)

const (
	// DefaultJWKSTimeout bounds a remote JWKS request, including reading the
	// response body.
	DefaultJWKSTimeout = 5 * time.Second
	// DefaultJWKSCacheTTL is used when a JWKS response has no valid max-age
	// Cache-Control directive.
	DefaultJWKSCacheTTL = 10 * time.Minute
	// DefaultJWKSMaxResponseBytes limits the serialized JWKS response size.
	DefaultJWKSMaxResponseBytes int64 = 1 << 20
)

var (
	// ErrJWKSInsecureEndpoint is returned for a JWKS endpoint which is not HTTPS.
	ErrJWKSInsecureEndpoint = errors.New("go-jose/go-jose/jwt: JWKS endpoint must use HTTPS")
	// ErrJWKSFetchFailed is returned when a JWKS request failed before a usable
	// HTTP response was received.
	ErrJWKSFetchFailed = errors.New("go-jose/go-jose/jwt: JWKS fetch failed")
	// ErrJWKSHTTPStatus is returned when a JWKS endpoint responds with a status
	// other than 200 OK.
	ErrJWKSHTTPStatus = errors.New("go-jose/go-jose/jwt: JWKS endpoint returned unexpected HTTP status")
	// ErrJWKSInvalidResponse is returned when a JWKS response is not a valid
	// public JWK Set.
	ErrJWKSInvalidResponse = errors.New("go-jose/go-jose/jwt: invalid JWKS response")
	// ErrJWKSResponseTooLarge is returned when a JWKS response exceeds the
	// configured body size limit.
	ErrJWKSResponseTooLarge = errors.New("go-jose/go-jose/jwt: JWKS response too large")
	// ErrUnknownIssuer is returned when a JWKS resolver has no endpoint for an
	// issuer.
	ErrUnknownIssuer = errors.New("go-jose/go-jose/jwt: no JWKS endpoint configured for issuer")
)

// JWKSHTTPStatusError describes a non-200 JWKS response.
type JWKSHTTPStatusError struct {
	Endpoint   string
	StatusCode int
	Status     string
}

func (e *JWKSHTTPStatusError) Error() string {
	return fmt.Sprintf("%s: %s returned %s", ErrJWKSHTTPStatus, e.Endpoint, e.Status)
}

func (e *JWKSHTTPStatusError) Unwrap() error {
	return ErrJWKSHTTPStatus
}

// RemoteJWKSConfig configures a lazy, caching remote JWKS provider.
type RemoteJWKSConfig struct {
	// Endpoint is the JWKS URL. It must use HTTPS.
	Endpoint string
	// Timeout bounds each fetch, including reading the response body. The
	// default is DefaultJWKSTimeout.
	Timeout time.Duration
	// DefaultTTL is used when Cache-Control does not contain a usable max-age
	// directive. The default is DefaultJWKSCacheTTL.
	DefaultTTL time.Duration
	// MaxResponseBytes limits the JWKS body size. The default is
	// DefaultJWKSMaxResponseBytes.
	MaxResponseBytes int64
	// StaleIfError allows an expired cached key to be used when a refresh
	// fails. The default is false, which rejects the token.
	StaleIfError bool
	// HTTPClient is used for JWKS requests. A nil value uses a standard client.
	HTTPClient *http.Client
	// Now supplies the current time. A nil value uses time.Now.
	Now func() time.Time
}

// JWKSStats is an immutable snapshot of a RemoteJWKS provider's counters.
type JWKSStats struct {
	Fetches         uint64
	FetchSuccesses  uint64
	RefreshFailures uint64
	CacheHits       uint64
	CacheMisses     uint64
	StaleServed     uint64
	LastFetchError  string
}

type cachedJWK struct {
	key         jose.JSONWebKey
	fingerprint string
	source      string
	expiresAt   time.Time
}

type jwksCache struct {
	source    string
	expiresAt time.Time
	keys      map[string][]cachedJWK
}

type jwksRefreshResult struct {
	generation uint64
	source     string
	err        error
	keys       []jose.JSONWebKey
}

type jwksRefresh struct {
	done   chan struct{}
	result jwksRefreshResult
}

// RemoteJWKS lazily fetches and caches a remote JSON Web Key Set.
//
// It implements jose.JWKSProvider and can be passed directly to
// JSONWebToken.Claims. A cache miss or expired cache triggers at most one
// in-flight refresh; concurrent callers wait for and share that result.
type RemoteJWKS struct {
	endpoint         string
	source           string
	timeout          time.Duration
	defaultTTL       time.Duration
	maxResponseBytes int64
	staleIfError     bool
	client           *http.Client
	now              func() time.Time

	mu         sync.Mutex
	generation uint64
	cache      *jwksCache
	inflight   *jwksRefresh
	stats      JWKSStats
}

// NewRemoteJWKS creates a remote JWKS provider.
func NewRemoteJWKS(config RemoteJWKSConfig) (*RemoteJWKS, error) {
	endpoint, source, err := normalizeJWKSEndpoint(config.Endpoint)
	if err != nil {
		return nil, err
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = DefaultJWKSTimeout
	}
	ttl := config.DefaultTTL
	if ttl <= 0 {
		ttl = DefaultJWKSCacheTTL
	}
	maxResponseBytes := config.MaxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = DefaultJWKSMaxResponseBytes
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}

	return &RemoteJWKS{
		endpoint:         endpoint,
		source:           source,
		timeout:          timeout,
		defaultTTL:       ttl,
		maxResponseBytes: maxResponseBytes,
		staleIfError:     config.StaleIfError,
		client:           jwksHTTPClient(config.HTTPClient),
		now:              now,
	}, nil
}

// SetEndpoint changes the JWKS endpoint and discards the current cache. Any
// in-flight response from the previous endpoint is not installed in the new
// cache.
func (r *RemoteJWKS) SetEndpoint(endpoint string) error {
	normalized, source, err := normalizeJWKSEndpoint(endpoint)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.generation++
	r.endpoint = normalized
	r.source = source
	r.cache = nil
	return nil
}

// Keys returns all cached or freshly fetched public keys matching the kid in
// header. If the cache is fresh and contains the kid, it does not perform I/O.
func (r *RemoteJWKS) Keys(header jose.Header) ([]jose.JSONWebKey, error) {
	kid := header.KeyID
	if kid == "" {
		return nil, jose.ErrJWKSKidNotFound
	}

	for {
		now := r.now()

		r.mu.Lock()
		keys, fresh := r.lookupLocked(kid, now)
		if len(keys) > 0 && fresh {
			r.stats.CacheHits++
			result := cloneJWKs(keys)
			r.mu.Unlock()
			return result, nil
		}
		r.stats.CacheMisses++
		r.mu.Unlock()

		refresh := r.refresh()

		r.mu.Lock()
		if refresh.generation != r.generation || refresh.source != r.source {
			r.mu.Unlock()
			continue
		}

		if refresh.err != nil {
			if r.staleIfError && len(keys) > 0 {
				r.stats.StaleServed++
				result := cloneJWKs(keys)
				r.mu.Unlock()
				return result, nil
			}
			r.mu.Unlock()
			return nil, refresh.err
		}

		keys, _ = r.lookupLocked(kid, r.now())
		if len(keys) == 0 {
			keys = filterJWKs(refresh.keys, kid)
		}
		r.mu.Unlock()
		if len(keys) == 0 {
			return nil, jose.ErrJWKSKidNotFound
		}
		return cloneJWKs(keys), nil
	}
}

// Stats returns a snapshot of provider counters. RefreshFailures counts actual
// fetch failures, not callers which waited on a shared in-flight refresh.
func (r *RemoteJWKS) Stats() JWKSStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

func (r *RemoteJWKS) lookupLocked(kid string, now time.Time) ([]jose.JSONWebKey, bool) {
	if r.cache == nil || r.cache.source != r.source {
		return nil, false
	}

	var (
		all       []jose.JSONWebKey
		unexpired []jose.JSONWebKey
	)
	for _, cached := range r.cache.keys[kid] {
		if cached.source != r.source {
			continue
		}
		all = append(all, cached.key)
		if now.Before(cached.expiresAt) {
			unexpired = append(unexpired, cached.key)
		}
	}
	if now.Before(r.cache.expiresAt) {
		return unexpired, true
	}
	return all, false
}

func (r *RemoteJWKS) refresh() *jwksRefreshResult {
	r.mu.Lock()
	if refresh := r.inflight; refresh != nil {
		r.mu.Unlock()
		<-refresh.done
		return &refresh.result
	}

	refresh := &jwksRefresh{done: make(chan struct{})}
	r.inflight = refresh
	r.stats.Fetches++
	endpoint := r.endpoint
	source := r.source
	generation := r.generation
	r.mu.Unlock()

	keys, ttl, err := r.fetch(endpoint)
	now := r.now()

	r.mu.Lock()
	if err != nil {
		r.stats.RefreshFailures++
		r.stats.LastFetchError = err.Error()
	} else {
		r.stats.FetchSuccesses++
	}

	// A response from an endpoint replaced by SetEndpoint must never populate
	// the cache for the new endpoint.
	if generation == r.generation && source == r.source {
		if err == nil {
			r.mergeLocked(keys, ttl, source, now)
		}
	}

	refresh.result = jwksRefreshResult{
		generation: generation,
		source:     source,
		err:        err,
		keys:       keys,
	}
	r.inflight = nil
	close(refresh.done)
	r.mu.Unlock()

	return &refresh.result
}

func (r *RemoteJWKS) mergeLocked(keys []jose.JSONWebKey, ttl time.Duration, source string, now time.Time) {
	cache := &jwksCache{
		source:    source,
		expiresAt: now.Add(ttl),
		keys:      make(map[string][]cachedJWK),
	}

	if r.cache != nil && r.cache.source == source {
		for kid, cachedKeys := range r.cache.keys {
			for _, cached := range cachedKeys {
				if cached.source == source && now.Before(cached.expiresAt) {
					cache.keys[kid] = append(cache.keys[kid], cached)
				}
			}
		}
	}

	for _, key := range keys {
		fingerprint, err := jwkFingerprint(key)
		if err != nil {
			continue
		}

		cached := cachedJWK{
			key:         key,
			fingerprint: fingerprint,
			source:      source,
			expiresAt:   now.Add(ttl),
		}
		replaced := false
		for i := range cache.keys[key.KeyID] {
			if cache.keys[key.KeyID][i].fingerprint == fingerprint {
				cache.keys[key.KeyID][i] = cached
				replaced = true
				break
			}
		}
		if !replaced {
			cache.keys[key.KeyID] = append(cache.keys[key.KeyID], cached)
		}
	}

	r.cache = cache
}

func (r *RemoteJWKS) fetch(endpoint string) ([]jose.JSONWebKey, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrJWKSFetchFailed, err)
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrJWKSFetchFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, &JWKSHTTPStatusError{
			Endpoint:   endpoint,
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
		}
	}
	if resp.ContentLength > r.maxResponseBytes {
		return nil, 0, fmt.Errorf("%w: Content-Length is %d, limit is %d", ErrJWKSResponseTooLarge, resp.ContentLength, r.maxResponseBytes)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, r.maxResponseBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: reading body: %w", ErrJWKSFetchFailed, err)
	}
	if int64(len(body)) > r.maxResponseBytes {
		return nil, 0, fmt.Errorf("%w: body exceeds %d bytes", ErrJWKSResponseTooLarge, r.maxResponseBytes)
	}

	keys, err := parseRemoteJWKS(body)
	if err != nil {
		return nil, 0, err
	}

	return keys, cacheTTL(resp.Header, r.defaultTTL), nil
}

func parseRemoteJWKS(body []byte) ([]jose.JSONWebKey, error) {
	var envelope struct {
		Keys *[]jsontext.Value `json:"keys"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWKSInvalidResponse, err)
	}
	if envelope.Keys == nil {
		return nil, fmt.Errorf("%w: missing keys array", ErrJWKSInvalidResponse)
	}

	keys := make([]jose.JSONWebKey, 0, len(*envelope.Keys))
	for i, raw := range *envelope.Keys {
		var key jose.JSONWebKey
		if err := json.Unmarshal(raw, &key); err != nil {
			return nil, fmt.Errorf("%w: key %d: %w", ErrJWKSInvalidResponse, i, err)
		}
		if !key.Valid() || !key.IsPublic() {
			return nil, fmt.Errorf("%w: key %d is not a valid public key", ErrJWKSInvalidResponse, i)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func cacheTTL(header http.Header, fallback time.Duration) time.Duration {
	var maxAge *time.Duration
	for _, value := range header.Values("Cache-Control") {
		for _, directive := range strings.Split(value, ",") {
			name, rawValue, _ := strings.Cut(strings.TrimSpace(directive), "=")
			switch {
			case strings.EqualFold(name, "no-store"), strings.EqualFold(name, "no-cache"):
				ttl := time.Duration(0)
				return ttl
			case strings.EqualFold(name, "max-age"):
				rawValue = strings.Trim(strings.TrimSpace(rawValue), `"`)
				seconds, err := strconv.ParseInt(rawValue, 10, 64)
				const maxCacheSeconds = int64((1<<63 - 1) / int64(time.Second))
				if err == nil && seconds >= 0 && seconds <= maxCacheSeconds {
					ttl := time.Duration(seconds) * time.Second
					maxAge = &ttl
				}
			}
		}
	}
	if maxAge != nil {
		return *maxAge
	}
	return fallback
}

func jwkFingerprint(key jose.JSONWebKey) (string, error) {
	raw, err := key.MarshalJSON()
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func cloneJWKs(keys []jose.JSONWebKey) []jose.JSONWebKey {
	out := make([]jose.JSONWebKey, len(keys))
	copy(out, keys)
	return out
}

func filterJWKs(keys []jose.JSONWebKey, kid string) []jose.JSONWebKey {
	var out []jose.JSONWebKey
	for _, key := range keys {
		if key.KeyID == kid {
			out = append(out, key)
		}
	}
	return out
}

func normalizeJWKSEndpoint(endpoint string) (string, string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", "", fmt.Errorf("%w: malformed URL %q", ErrJWKSInsecureEndpoint, endpoint)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return "", "", fmt.Errorf("%w: %q", ErrJWKSInsecureEndpoint, endpoint)
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)
	normalized := parsed.String()
	return normalized, normalized, nil
}

func jwksHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	cloned := *client
	previousCheck := cloned.CheckRedirect
	cloned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !strings.EqualFold(req.URL.Scheme, "https") {
			return fmt.Errorf("%w: redirect to %q", ErrJWKSInsecureEndpoint, req.URL.String())
		}
		if previousCheck != nil {
			return previousCheck(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &cloned
}

// IssuerKeyProvider selects a verification key provider from an unverified JWT
// issuer claim. The selected provider still has to verify the token signature.
type IssuerKeyProvider interface {
	KeyProviderForIssuer(issuer string) (any, error)
}

// IssuerJWKSConfig configures the JWKS endpoint for one issuer.
type IssuerJWKSConfig struct {
	Issuer           string
	Endpoint         string
	Timeout          time.Duration
	DefaultTTL       time.Duration
	MaxResponseBytes int64
	StaleIfError     bool
}

// JWKSResolverConfig configures issuer-isolated JWKS providers.
type JWKSResolverConfig struct {
	Issuers    []IssuerJWKSConfig
	HTTPClient *http.Client
	Now        func() time.Time
}

// JWKSResolver routes tokens to issuer-specific, isolated RemoteJWKS caches.
type JWKSResolver struct {
	providers map[string]*RemoteJWKS
}

// NewJWKSResolver builds a resolver with one independently locked and cached
// provider per issuer.
func NewJWKSResolver(config JWKSResolverConfig) (*JWKSResolver, error) {
	if len(config.Issuers) == 0 {
		return nil, errors.New("go-jose/go-jose/jwt: at least one issuer JWKS endpoint is required")
	}

	resolver := &JWKSResolver{providers: make(map[string]*RemoteJWKS, len(config.Issuers))}
	for _, issuerConfig := range config.Issuers {
		if issuerConfig.Issuer == "" {
			return nil, errors.New("go-jose/go-jose/jwt: issuer must not be empty")
		}
		if _, exists := resolver.providers[issuerConfig.Issuer]; exists {
			return nil, fmt.Errorf("go-jose/go-jose/jwt: duplicate issuer %q", issuerConfig.Issuer)
		}
		provider, err := NewRemoteJWKS(RemoteJWKSConfig{
			Endpoint:         issuerConfig.Endpoint,
			Timeout:          issuerConfig.Timeout,
			DefaultTTL:       issuerConfig.DefaultTTL,
			MaxResponseBytes: issuerConfig.MaxResponseBytes,
			StaleIfError:     issuerConfig.StaleIfError,
			HTTPClient:       config.HTTPClient,
			Now:              config.Now,
		})
		if err != nil {
			return nil, fmt.Errorf("go-jose/go-jose/jwt: issuer %q: %w", issuerConfig.Issuer, err)
		}
		resolver.providers[issuerConfig.Issuer] = provider
	}
	return resolver, nil
}

// KeyProviderForIssuer implements IssuerKeyProvider.
func (r *JWKSResolver) KeyProviderForIssuer(issuer string) (any, error) {
	provider, ok := r.providers[issuer]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownIssuer, issuer)
	}
	return provider, nil
}

// SetEndpoint changes the endpoint and clears the cache for one issuer.
func (r *JWKSResolver) SetEndpoint(issuer, endpoint string) error {
	provider, ok := r.providers[issuer]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownIssuer, issuer)
	}
	return provider.SetEndpoint(endpoint)
}

// Stats returns counters for an issuer's provider.
func (r *JWKSResolver) Stats(issuer string) (JWKSStats, bool) {
	provider, ok := r.providers[issuer]
	if !ok {
		return JWKSStats{}, false
	}
	return provider.Stats(), true
}
