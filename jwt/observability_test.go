package jwt

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/testutils/assert"
	"github.com/go-jose/go-jose/v4/testutils/require"
)

// TestClassifyErrorJWT verifies that the three verification failure
// categories (signature mismatch, expiry, disallowed algorithm) plus
// cancellation are classified distinctly.
func TestClassifyErrorJWT(t *testing.T) {
	require.Equal(t, ClassifyError(nil), jose.ErrKindNone)
	require.Equal(t, ClassifyError(ErrExpired), ErrKindExpired)
	require.Equal(t, ClassifyError(ErrNotValidYet), ErrKindNotYetValid)
	require.Equal(t, ClassifyError(ErrIssuedInTheFuture), ErrKindIssuedInFuture)
	require.Equal(t, ClassifyError(ErrInvalidAudience), ErrKindClaimsValidation)
	require.Equal(t, ClassifyError(ErrInvalidIssuer), ErrKindClaimsValidation)
	require.Equal(t, ClassifyError(jose.ErrCryptoFailure), jose.ErrKindSignatureMismatch)
	require.Equal(t, ClassifyError(context.Canceled), jose.ErrKindCancelled)
	require.Equal(t, ClassifyError(errors.New("boom")), jose.ErrKindOther)

	_, err := jose.ParseSignedCompact(rsaSignedToken, []jose.SignatureAlgorithm{jose.HS256})
	assert.Error(t, err)
	require.Equal(t, ClassifyError(err), jose.ErrKindAlgorithmNotAllowed)
}

func mustSignJWT(t *testing.T, claims Claims) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: sharedKey}, nil)
	require.NoError(t, err)
	raw, err := Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return raw
}

// TestClaimsWithOptionsSignatureMismatch verifies the signature-mismatch
// category surfaces as a structured error with context.
func TestClaimsWithOptionsSignatureMismatch(t *testing.T) {
	raw := mustSignJWT(t, Claims{Issuer: "issuer"})
	tok, err := ParseSigned(raw, []jose.SignatureAlgorithm{jose.HS256})
	require.NoError(t, err)

	wrongKey := []byte("ffffffffffffffffffffffffffffffff")
	obs := &jose.Observer{OnProgress: func(jose.ProgressEvent) {}}
	err = tok.ClaimsWithOptions(context.Background(), obs, wrongKey, &Claims{})
	assert.Error(t, err)
	require.Equal(t, ClassifyError(err), jose.ErrKindSignatureMismatch)
	assert.ErrorIs(t, err, jose.ErrCryptoFailure)

	var opErr *jose.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("expected *jose.OpError, got %T", err)
	}
	require.Equal(t, opErr.Context["alg"], "HS256")
}

// TestClaimsWithOptionsExpired verifies the expiry category is
// distinguishable after a successful signature verification.
func TestClaimsWithOptionsExpired(t *testing.T) {
	expired := mustSignJWT(t, Claims{
		Issuer: "issuer",
		Expiry: NewNumericDate(time.Now().Add(-2 * time.Hour)),
	})
	tok, err := ParseSigned(expired, []jose.SignatureAlgorithm{jose.HS256})
	require.NoError(t, err)

	// Signature itself verifies fine.
	cl := Claims{}
	err = tok.ClaimsWithOptions(context.Background(), nil, sharedKey, &cl)
	require.NoError(t, err)

	// Claims validation then reports the expiry category.
	err = cl.Validate(Expected{Issuer: "issuer"})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrExpired)
	require.Equal(t, ClassifyError(err), ErrKindExpired)
}

// TestClaimsWithOptionsProgress verifies progress events flow through JWT
// verification and that cancellation is honored.
func TestClaimsWithOptionsProgress(t *testing.T) {
	raw := mustSignJWT(t, Claims{Issuer: "issuer"})
	tok, err := ParseSigned(raw, []jose.SignatureAlgorithm{jose.HS256})
	require.NoError(t, err)

	var mu sync.Mutex
	var events []jose.ProgressEvent
	obs := &jose.Observer{
		OnProgress: func(evt jose.ProgressEvent) {
			mu.Lock()
			events = append(events, evt)
			mu.Unlock()
		},
	}
	cl := Claims{}
	err = tok.ClaimsWithOptions(context.Background(), obs, sharedKey, &cl)
	require.NoError(t, err)
	require.Equal(t, cl.Issuer, "issuer")

	mu.Lock()
	if len(events) == 0 {
		mu.Unlock()
		t.Fatal("expected progress events")
	}
	require.Equal(t, events[len(events)-1].Stage, "done")
	mu.Unlock()

	// Cancelled context yields "cancelled", not "failed".
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = tok.ClaimsWithOptions(ctx, obs, sharedKey, &Claims{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	require.Equal(t, ClassifyError(err), jose.ErrKindCancelled)
}

// TestClaimsWithOptionsEncryptedUnknownTotal verifies that encrypted tokens
// report progress with an unknown total (-1).
func TestClaimsWithOptionsEncryptedUnknownTotal(t *testing.T) {
	enc, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{Algorithm: jose.DIRECT, Key: sharedEncryptionKey},
		nil,
	)
	require.NoError(t, err)
	raw, err := Encrypted(enc).Claims(Claims{Issuer: "issuer"}).Serialize()
	require.NoError(t, err)
	tok, err := ParseEncrypted(raw, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A128GCM})
	require.NoError(t, err)

	var events []jose.ProgressEvent
	obs := &jose.Observer{
		OnProgress: func(evt jose.ProgressEvent) { events = append(events, evt) },
	}
	cl := Claims{}
	err = tok.ClaimsWithOptions(context.Background(), obs, sharedEncryptionKey, &cl)
	require.NoError(t, err)
	require.Equal(t, cl.Issuer, "issuer")

	if len(events) == 0 {
		t.Fatal("expected progress events")
	}
	for _, evt := range events {
		require.Equal(t, evt.Total, int64(-1))
	}
	require.Equal(t, events[len(events)-1].Stage, "done")
}

// TestClaimsDefaultPathUnchanged verifies the default Claims path is
// unaffected by the new capability.
func TestClaimsDefaultPathUnchanged(t *testing.T) {
	raw := mustSignJWT(t, Claims{Issuer: "issuer"})
	tok, err := ParseSigned(raw, []jose.SignatureAlgorithm{jose.HS256})
	require.NoError(t, err)

	cl := Claims{}
	require.NoError(t, tok.Claims(sharedKey, &cl))
	require.Equal(t, cl.Issuer, "issuer")

	// Default failure path returns the raw sentinel, not *jose.OpError.
	err = tok.Claims([]byte("ffffffffffffffffffffffffffffffff"), &Claims{})
	assert.Error(t, err)
	require.Equal(t, err, jose.ErrCryptoFailure)
}
