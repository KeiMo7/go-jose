package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v5"
)

type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *mutableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mutableClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type jwksTestHandler struct {
	mu           sync.Mutex
	body         []byte
	status       int
	cacheControl string
	requests     int
	wait         <-chan struct{}
	started      chan struct{}
	startOnce    sync.Once
}

func (h *jwksTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.requests++
	body := append([]byte(nil), h.body...)
	status := h.status
	cacheControl := h.cacheControl
	wait := h.wait
	started := h.started
	h.mu.Unlock()

	if started != nil {
		h.startOnce.Do(func() { close(started) })
	}
	if wait != nil {
		<-wait
	}

	if status == 0 {
		status = http.StatusOK
	}
	if cacheControl != "" {
		w.Header().Set("Cache-Control", cacheControl)
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (h *jwksTestHandler) setKeys(t *testing.T, keys ...jose.JSONWebKey) {
	t.Helper()
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	h.setResponse(http.StatusOK, body, "max-age=3600")
}

func (h *jwksTestHandler) setResponse(status int, body []byte, cacheControl string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status = status
	h.body = append([]byte(nil), body...)
	h.cacheControl = cacheControl
}

func (h *jwksTestHandler) requestCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.requests
}

func newJWKSTestServer(t *testing.T) (*httptest.Server, *jwksTestHandler) {
	t.Helper()
	handler := &jwksTestHandler{}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return server, handler
}

func newTestECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func publicTestJWK(key *ecdsa.PrivateKey, kid string) jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       &key.PublicKey,
		KeyID:     kid,
		Algorithm: string(jose.ES256),
	}
}

func signTestJWT(t *testing.T, key *ecdsa.PrivateKey, kid, issuer string) *JSONWebToken {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       &jose.JSONWebKey{Key: key, KeyID: kid},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := Signed(signer).Claims(map[string]any{
		"iss": issuer,
		"sub": "remote-jwks-test",
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	token, err := ParseSigned(serialized, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func verifyTestJWT(token *JSONWebToken, key any) (Claims, error) {
	var claims Claims
	err := token.Claims(key, &claims)
	return claims, err
}

func TestRemoteJWKSRotationKeepsOldKeys(t *testing.T) {
	oldKey := newTestECKey(t)
	newKey := newTestECKey(t)
	server, handler := newJWKSTestServer(t)
	handler.setKeys(t, publicTestJWK(oldKey, "old-key"))

	provider, err := NewRemoteJWKS(RemoteJWKSConfig{
		Endpoint:   server.URL + "/jwks",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	oldToken := signTestJWT(t, oldKey, "old-key", "issuer-rotation")
	if _, err := verifyTestJWT(oldToken, provider); err != nil {
		t.Fatalf("verify old token before rotation: %v", err)
	}
	t.Logf("before rotation: old token verified; fetches=%d", handler.requestCount())

	// The refreshed set intentionally omits the old key. The provider must
	// merge the new key into its cache rather than replacing the old one.
	handler.setKeys(t, publicTestJWK(newKey, "new-key"))
	newToken := signTestJWT(t, newKey, "new-key", "issuer-rotation")
	if _, err := verifyTestJWT(newToken, provider); err != nil {
		t.Fatalf("verify new token after rotation: %v", err)
	}
	if _, err := verifyTestJWT(oldToken, provider); err != nil {
		t.Fatalf("verify old token after rotation: %v", err)
	}
	t.Logf("after rotation: old and new tokens verified; fetches=%d cacheHits=%d",
		handler.requestCount(), provider.Stats().CacheHits)

	if got := handler.requestCount(); got != 2 {
		t.Fatalf("JWKS requests = %d, want 2", got)
	}
}

func TestRemoteJWKSConcurrentRefreshIsSingleFlight(t *testing.T) {
	key := newTestECKey(t)
	server, handler := newJWKSTestServer(t)
	handler.setKeys(t, publicTestJWK(key, "concurrent-key"))

	started := make(chan struct{})
	release := make(chan struct{})
	handler.mu.Lock()
	handler.wait = release
	handler.started = started
	handler.mu.Unlock()

	provider, err := NewRemoteJWKS(RemoteJWKSConfig{
		Endpoint:   server.URL + "/jwks",
		HTTPClient: server.Client(),
		Timeout:    2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	token := signTestJWT(t, key, "concurrent-key", "issuer-concurrent")

	const callers = 24
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			<-start
			_, err := verifyTestJWT(token, provider)
			errs <- err
		}()
	}
	close(start)
	<-started
	close(release)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent verification failed: %v", err)
		}
	}
	if got := handler.requestCount(); got != 1 {
		t.Fatalf("JWKS requests = %d, want 1", got)
	}
}

func TestRemoteJWKSDuplicateKidTriesAllKeys(t *testing.T) {
	oldKey := newTestECKey(t)
	newKey := newTestECKey(t)
	unrelatedKey := newTestECKey(t)
	server, handler := newJWKSTestServer(t)
	handler.setKeys(t,
		publicTestJWK(oldKey, "duplicate-key"),
		publicTestJWK(newKey, "duplicate-key"),
	)

	provider, err := NewRemoteJWKS(RemoteJWKSConfig{
		Endpoint:   server.URL + "/jwks",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	newToken := signTestJWT(t, newKey, "duplicate-key", "issuer-duplicate")
	if _, err := verifyTestJWT(newToken, provider); err != nil {
		t.Fatalf("second duplicate key was not tried: %v", err)
	}

	badToken := signTestJWT(t, unrelatedKey, "duplicate-key", "issuer-duplicate")
	_, err = verifyTestJWT(badToken, provider)
	var verificationErr *jose.JWKSVerificationError
	if !errors.As(err, &verificationErr) {
		t.Fatalf("error = %v, want *jose.JWKSVerificationError", err)
	}
	if !errors.Is(err, jose.ErrCryptoFailure) {
		t.Fatalf("error %v does not wrap jose.ErrCryptoFailure", err)
	}
	if verificationErr.Attempted != 2 {
		t.Fatalf("attempted keys = %d, want 2", verificationErr.Attempted)
	}
	if !strings.Contains(err.Error(), "trying 2 key(s)") {
		t.Fatalf("error %q does not report the attempted key count", err)
	}
}

func TestJSONWebKeySetDuplicateKidTriesAllKeys(t *testing.T) {
	oldKey := newTestECKey(t)
	newKey := newTestECKey(t)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		publicTestJWK(oldKey, "local-duplicate"),
		publicTestJWK(newKey, "local-duplicate"),
	}}

	token := signTestJWT(t, newKey, "local-duplicate", "issuer-local")
	if _, err := verifyTestJWT(token, set); err != nil {
		t.Fatalf("second duplicate local JWK was not tried: %v", err)
	}
}

func TestRemoteJWKSCacheExpiryAndStaleFallback(t *testing.T) {
	key := newTestECKey(t)
	server, handler := newJWKSTestServer(t)
	handler.setKeys(t, publicTestJWK(key, "stale-key"))
	handler.setResponse(http.StatusOK, mustMarshalJWKS(t, publicTestJWK(key, "stale-key")), "max-age=1")

	clock := &mutableClock{now: time.Unix(1_700_000_000, 0)}
	rejectProvider, err := NewRemoteJWKS(RemoteJWKSConfig{
		Endpoint:   server.URL + "/jwks",
		HTTPClient: server.Client(),
		Now:        clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	token := signTestJWT(t, key, "stale-key", "issuer-stale")
	if _, err := verifyTestJWT(token, rejectProvider); err != nil {
		t.Fatal(err)
	}

	// While the cache is fresh, endpoint failures do not interrupt validation.
	handler.setResponse(http.StatusServiceUnavailable, []byte("down"), "")
	if _, err := verifyTestJWT(token, rejectProvider); err != nil {
		t.Fatalf("fresh cache should survive endpoint failure: %v", err)
	}
	t.Logf("endpoint unavailable with fresh cache: validation continued; requests=%d", handler.requestCount())
	if got := handler.requestCount(); got != 1 {
		t.Fatalf("JWKS requests = %d, want 1", got)
	}

	clock.Advance(2 * time.Second)
	_, err = verifyTestJWT(token, rejectProvider)
	if !errors.Is(err, ErrJWKSHTTPStatus) {
		t.Fatalf("expired cache error = %v, want ErrJWKSHTTPStatus", err)
	}
	if stats := rejectProvider.Stats(); stats.RefreshFailures != 1 {
		t.Fatalf("refresh failures = %d, want 1", stats.RefreshFailures)
	}
	t.Logf("expired cache + HTTP 503: token rejected by default; refreshFailures=%d",
		rejectProvider.Stats().RefreshFailures)

	staleProvider, err := NewRemoteJWKS(RemoteJWKSConfig{
		Endpoint:     server.URL + "/jwks",
		HTTPClient:   server.Client(),
		Now:          clock.Now,
		StaleIfError: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Prime this provider with the healthy response, then expire it.
	handler.setResponse(http.StatusOK, mustMarshalJWKS(t, publicTestJWK(key, "stale-key")), "max-age=1")
	if _, err := verifyTestJWT(token, staleProvider); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Second)
	handler.setResponse(http.StatusServiceUnavailable, []byte("down"), "")
	if _, err := verifyTestJWT(token, staleProvider); err != nil {
		t.Fatalf("stale fallback should verify token: %v", err)
	}
	stats := staleProvider.Stats()
	if stats.StaleServed != 1 || stats.RefreshFailures != 1 {
		t.Fatalf("stats = %+v, want one stale serve and one refresh failure", stats)
	}
	t.Logf("expired cache + HTTP 503: stale fallback verified token; staleServed=%d refreshFailures=%d",
		stats.StaleServed, stats.RefreshFailures)
}

func TestRemoteJWKSEndpointSwitchDoesNotReuseCache(t *testing.T) {
	keyA := newTestECKey(t)
	keyB := newTestECKey(t)
	serverA, handlerA := newJWKSTestServer(t)
	serverB, handlerB := newJWKSTestServer(t)
	handlerA.setKeys(t, publicTestJWK(keyA, "switched-key"))
	handlerB.setKeys(t, publicTestJWK(keyB, "switched-key"))

	provider, err := NewRemoteJWKS(RemoteJWKSConfig{
		Endpoint:   serverA.URL + "/jwks",
		HTTPClient: serverA.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	provider.client = serverB.Client() // both test servers trust only their own TLS certificate

	tokenA := signTestJWT(t, keyA, "switched-key", "issuer-switch")
	if _, err := verifyTestJWT(tokenA, provider); err != nil {
		t.Fatal(err)
	}
	if err := provider.SetEndpoint(serverB.URL + "/jwks"); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyTestJWT(tokenA, provider); !errors.Is(err, jose.ErrCryptoFailure) {
		t.Fatalf("old key was reused after endpoint switch: %v", err)
	}

	tokenB := signTestJWT(t, keyB, "switched-key", "issuer-switch")
	if _, err := verifyTestJWT(tokenB, provider); err != nil {
		t.Fatalf("new endpoint key failed: %v", err)
	}
	if handlerA.requestCount() != 1 || handlerB.requestCount() != 1 {
		t.Fatalf("requests A=%d B=%d, want 1 each", handlerA.requestCount(), handlerB.requestCount())
	}
}

func TestJWKSResolverIsolatesIssuers(t *testing.T) {
	keyA := newTestECKey(t)
	keyB := newTestECKey(t)
	serverA, handlerA := newJWKSTestServer(t)
	serverB, handlerB := newJWKSTestServer(t)
	handlerA.setResponse(http.StatusOK, mustMarshalJWKS(t, publicTestJWK(keyA, "issuer-a-key")), "max-age=1")
	handlerB.setResponse(http.StatusOK, mustMarshalJWKS(t, publicTestJWK(keyB, "issuer-b-key")), "max-age=60")

	clock := &mutableClock{now: time.Unix(1_700_000_000, 0)}
	resolver, err := NewJWKSResolver(JWKSResolverConfig{
		Issuers: []IssuerJWKSConfig{
			{Issuer: "issuer-a", Endpoint: serverA.URL + "/jwks"},
			{Issuer: "issuer-b", Endpoint: serverB.URL + "/jwks"},
		},
		HTTPClient: serverA.Client(),
		Now:        clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The resolver has one shared client, so trust both local test certificates.
	roots := x509.NewCertPool()
	roots.AddCert(serverA.Certificate())
	roots.AddCert(serverB.Certificate())
	transport := serverA.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.RootCAs = roots
	for _, provider := range resolver.providers {
		provider.client.Transport = transport
	}

	tokenA := signTestJWT(t, keyA, "issuer-a-key", "issuer-a")
	tokenB := signTestJWT(t, keyB, "issuer-b-key", "issuer-b")
	unknownIssuerToken := signTestJWT(t, keyA, "issuer-a-key", "issuer-missing")
	if _, err := verifyTestJWT(unknownIssuerToken, resolver); !errors.Is(err, ErrUnknownIssuer) {
		t.Fatalf("unknown issuer error = %v, want ErrUnknownIssuer", err)
	}
	if _, err := verifyTestJWT(tokenA, resolver); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyTestJWT(tokenB, resolver); err != nil {
		t.Fatal(err)
	}

	clock.Advance(2 * time.Second)
	handlerA.setResponse(http.StatusServiceUnavailable, []byte("issuer A down"), "")
	if _, err := verifyTestJWT(tokenA, resolver); !errors.Is(err, ErrJWKSHTTPStatus) {
		t.Fatalf("issuer A error = %v, want ErrJWKSHTTPStatus", err)
	}
	if _, err := verifyTestJWT(tokenB, resolver); err != nil {
		t.Fatalf("issuer B was affected by issuer A failure: %v", err)
	}

	statsA, ok := resolver.Stats("issuer-a")
	if !ok || statsA.RefreshFailures != 1 {
		t.Fatalf("issuer A stats = %+v, ok=%v", statsA, ok)
	}
	statsB, ok := resolver.Stats("issuer-b")
	if !ok || statsB.RefreshFailures != 0 {
		t.Fatalf("issuer B stats = %+v, ok=%v", statsB, ok)
	}
	t.Logf("issuer A unavailable: A rejected; issuer B verified; failures A=%d B=%d",
		statsA.RefreshFailures, statsB.RefreshFailures)
}

func TestRemoteJWKSRejectsInvalidResponses(t *testing.T) {
	key := newTestECKey(t)
	token := signTestJWT(t, key, "invalid-key", "issuer-invalid")

	t.Run("insecure endpoint", func(t *testing.T) {
		_, err := NewRemoteJWKS(RemoteJWKSConfig{Endpoint: "http://example.com/jwks"})
		if !errors.Is(err, ErrJWKSInsecureEndpoint) {
			t.Fatalf("error = %v, want ErrJWKSInsecureEndpoint", err)
		}
	})

	tests := []struct {
		name       string
		status     int
		body       []byte
		maxBytes   int64
		wantErr    error
		wantStatus int
	}{
		{
			name:       "unexpected status",
			status:     http.StatusBadGateway,
			body:       []byte(`{"keys":[]}`),
			wantErr:    ErrJWKSHTTPStatus,
			wantStatus: http.StatusBadGateway,
		},
		{
			name:    "invalid JWKS",
			status:  http.StatusOK,
			body:    []byte(`{"keys":{}}`),
			wantErr: ErrJWKSInvalidResponse,
		},
		{
			name:     "response too large",
			status:   http.StatusOK,
			body:     []byte(`{"keys":[]} padding padding padding`),
			maxBytes: 16,
			wantErr:  ErrJWKSResponseTooLarge,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, handler := newJWKSTestServer(t)
			handler.setResponse(test.status, test.body, "")
			provider, err := NewRemoteJWKS(RemoteJWKSConfig{
				Endpoint:         server.URL + "/jwks",
				HTTPClient:       server.Client(),
				MaxResponseBytes: test.maxBytes,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifyTestJWT(token, provider)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if test.wantStatus != 0 {
				var statusErr *JWKSHTTPStatusError
				if !errors.As(err, &statusErr) || statusErr.StatusCode != test.wantStatus {
					t.Fatalf("status error = %#v, want status %d", statusErr, test.wantStatus)
				}
			}
		})
	}
}

func TestRemoteJWKSTimeout(t *testing.T) {
	key := newTestECKey(t)
	tests := []struct {
		name    string
		handler http.Handler
	}{
		{
			name: "before headers",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				<-r.Context().Done()
			}),
		},
		{
			name: "during body",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				<-r.Context().Done()
			}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(test.handler)
			t.Cleanup(server.Close)

			provider, err := NewRemoteJWKS(RemoteJWKSConfig{
				Endpoint:   server.URL + "/jwks",
				HTTPClient: server.Client(),
				Timeout:    40 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			token := signTestJWT(t, key, "slow-key", "issuer-slow")

			start := time.Now()
			_, err = verifyTestJWT(token, provider)
			elapsed := time.Since(start)
			if !errors.Is(err, ErrJWKSFetchFailed) || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("error = %v, want fetch failure caused by deadline", err)
			}
			if elapsed > 500*time.Millisecond {
				t.Fatalf("verification blocked for %s, want no more than 500ms", elapsed)
			}
		})
	}
}

func TestJWKSCacheTTL(t *testing.T) {
	fallback := 3 * time.Minute
	tests := []struct {
		name  string
		cache string
		want  time.Duration
	}{
		{name: "fallback", want: fallback},
		{name: "max age", cache: "public, max-age=45", want: 45 * time.Second},
		{name: "quoted max age", cache: `max-age="12"`, want: 12 * time.Second},
		{name: "no cache", cache: "no-cache, max-age=60", want: 0},
		{name: "no store", cache: "no-store", want: 0},
		{name: "invalid max age", cache: "max-age=oops", want: fallback},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := make(http.Header)
			if test.cache != "" {
				header.Set("Cache-Control", test.cache)
			}
			if got := cacheTTL(header, fallback); got != test.want {
				t.Fatalf("cacheTTL() = %s, want %s", got, test.want)
			}
		})
	}
}

func mustMarshalJWKS(t *testing.T, keys ...jose.JSONWebKey) []byte {
	t.Helper()
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
