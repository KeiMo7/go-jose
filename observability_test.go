package jose

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/testutils/assert"
	"github.com/go-jose/go-jose/v4/testutils/require"
)

type progressRecorder struct {
	mu     sync.Mutex
	events []ProgressEvent
}

func (r *progressRecorder) record(evt ProgressEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, evt)
}

func (r *progressRecorder) snapshot() []ProgressEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ProgressEvent, len(r.events))
	copy(out, r.events)
	return out
}

func makeObservedHMACSigner(t *testing.T, recipients int, obs *Observer) Signer {
	t.Helper()
	keys := make([]SigningKey, recipients)
	for i := range keys {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)
		keys[i] = SigningKey{Algorithm: HS256, Key: key}
	}
	var opts *SignerOptions
	if obs != nil {
		opts = &SignerOptions{Observer: obs}
	}
	signer, err := NewMultiSigner(keys, opts)
	require.NoError(t, err)
	return signer
}

// TestSignProgressCallbacks verifies that a long-running multi-recipient
// signing operation reports progress at least three times with monotonically
// increasing Completed values.
func TestSignProgressCallbacks(t *testing.T) {
	rec := &progressRecorder{}
	obs := &Observer{
		OnProgress:       rec.record,
		ProgressInterval: time.Millisecond,
	}
	// RSA signatures are slow enough that the operation runs for a
	// measurable amount of time, so interval-based throttling still
	// produces several samples.
	keys := make([]SigningKey, 16)
	for i := range keys {
		keys[i] = SigningKey{Algorithm: RS256, Key: rsaTestKey}
	}
	signer, err := NewMultiSigner(keys, &SignerOptions{Observer: obs})
	require.NoError(t, err)

	payload := bytes.Repeat([]byte("payload"), 1024)
	obj, err := signer.Sign(payload)
	require.NoError(t, err)
	require.Equal(t, len(obj.Signatures), 16)

	events := rec.snapshot()
	if len(events) < 3 {
		t.Fatalf("expected at least 3 progress callbacks, got %d", len(events))
	}
	var prev int64 = -1
	for _, evt := range events {
		if evt.Completed < prev {
			t.Fatalf("Completed is not monotonically increasing: %d after %d", evt.Completed, prev)
		}
		prev = evt.Completed
		require.Equal(t, evt.Operation, "jws.sign")
		require.Equal(t, evt.Total, int64(16))
	}
	last := events[len(events)-1]
	require.Equal(t, last.Stage, "done")
	require.Equal(t, last.Completed, int64(16))
}

// TestProgressIntervalThrottling verifies that a large ProgressInterval
// suppresses intermediate samples but always delivers start and done.
func TestProgressIntervalThrottling(t *testing.T) {
	rec := &progressRecorder{}
	obs := &Observer{
		OnProgress:       rec.record,
		ProgressInterval: time.Hour,
	}
	signer := makeObservedHMACSigner(t, 16, obs)
	_, err := signer.Sign([]byte("payload"))
	require.NoError(t, err)

	events := rec.snapshot()
	require.Equal(t, len(events), 2)
	require.Equal(t, events[0].Stage, "start")
	require.Equal(t, events[1].Stage, "done")
	require.Equal(t, events[1].Completed, int64(16))
}

// TestVerifyStructuredError verifies that a failing verification returns a
// structured *OpError carrying a classification and redacted context.
func TestVerifyStructuredError(t *testing.T) {
	signingKey := make([]byte, 32)
	wrongKey := make([]byte, 32)
	_, err := rand.Read(signingKey)
	require.NoError(t, err)
	_, err = rand.Read(wrongKey)
	require.NoError(t, err)

	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: signingKey}, nil)
	require.NoError(t, err)
	obj, err := signer.Sign([]byte("payload"))
	require.NoError(t, err)

	rec := &progressRecorder{}
	obs := &Observer{OnProgress: rec.record}
	_, err = obj.VerifyWithOptions(context.Background(), wrongKey, obs)
	assert.Error(t, err)

	var opErr *OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("expected *OpError, got %T", err)
	}
	require.Equal(t, opErr.Kind, ErrKindSignatureMismatch)
	require.Equal(t, opErr.Op, "jws.verify")
	require.Equal(t, opErr.Context["alg"], "HS256")
	// The original error stays reachable for errors.Is/As.
	assert.ErrorIs(t, err, ErrCryptoFailure)
	require.Equal(t, ClassifyError(err), ErrKindSignatureMismatch)
}

// TestAlgorithmNotAllowedClassification verifies that a disallowed "alg"
// header is classified distinctly from a signature mismatch.
func TestAlgorithmNotAllowedClassification(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: key}, nil)
	require.NoError(t, err)
	obj, err := signer.Sign([]byte("payload"))
	require.NoError(t, err)
	serialized, err := obj.CompactSerialize()
	require.NoError(t, err)

	_, err = ParseSignedCompact(serialized, []SignatureAlgorithm{RS256})
	assert.Error(t, err)
	var algErr *ErrUnexpectedSignatureAlgorithm
	if !errors.As(err, &algErr) {
		t.Fatalf("expected *ErrUnexpectedSignatureAlgorithm, got %T", err)
	}
	require.Equal(t, ClassifyError(err), ErrKindAlgorithmNotAllowed)
}

// TestSignCancellation verifies that a cancelled context aborts a
// multi-recipient signing promptly and reports "cancelled", not "failed".
func TestSignCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	rec := &progressRecorder{}
	obs := &Observer{
		OnProgress: func(evt ProgressEvent) {
			rec.record(evt)
			// Cancel mid-operation: the next recipient loop iteration must
			// observe the cancellation.
			cancel()
		},
	}
	signer := makeObservedHMACSigner(t, 64, obs)
	ctxSigner, ok := signer.(ContextSigner)
	if !ok {
		t.Fatal("signer does not implement ContextSigner")
	}

	_, err := ctxSigner.SignWithContext(ctx, []byte("payload"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	require.Equal(t, ClassifyError(err), ErrKindCancelled)

	var opErr *OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("expected *OpError, got %T", err)
	}
	require.Equal(t, opErr.Kind, ErrKindCancelled)

	// The operation aborted promptly instead of signing all 64 recipients.
	if n := len(rec.snapshot()); n >= 64 {
		t.Fatalf("cancellation was not prompt: %d progress events", n)
	}
}

// TestVerifyMultiCancellation verifies cancellation on the multi-signature
// verification path.
func TestVerifyMultiCancellation(t *testing.T) {
	signer := makeObservedHMACSigner(t, 8, nil)
	obj, err := signer.Sign([]byte("payload"))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err = obj.VerifyMultiWithOptions(ctx, make([]byte, 32), nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	require.Equal(t, ClassifyError(err), ErrKindCancelled)
}

// TestCallbackPanicDoesNotBreakOperation verifies that a panicking progress
// callback is logged and swallowed without affecting the operation.
func TestCallbackPanicDoesNotBreakOperation(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	obs := &Observer{
		OnProgress: func(ProgressEvent) { panic("boom") },
		Logger:     logger,
	}
	signer := makeObservedHMACSigner(t, 4, obs)
	obj, err := signer.Sign([]byte("payload"))
	require.NoError(t, err)
	require.Equal(t, len(obj.Signatures), 4)

	if !strings.Contains(logBuf.String(), "progress callback panicked") {
		t.Fatalf("expected panic to be logged, got: %s", logBuf.String())
	}
}

// TestObservedLoggingRedacted verifies entry/exit/failure log lines exist and
// contain no key material or payloads.
func TestObservedLoggingRedacted(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	obs := &Observer{Logger: logger}

	secret := []byte("super-secret-hmac-key-material!!")
	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: secret}, &SignerOptions{Observer: obs})
	require.NoError(t, err)
	payload := []byte("confidential-payload-contents")
	obj, err := signer.Sign(payload)
	require.NoError(t, err)

	_, err = obj.VerifyWithOptions(context.Background(), []byte("wrong-key-wrong-key-wrong-key!"), obs)
	assert.Error(t, err)

	out := logBuf.String()
	if !strings.Contains(out, "operation started") {
		t.Error("missing entry log line")
	}
	if !strings.Contains(out, "operation finished") {
		t.Error("missing exit log line")
	}
	if !strings.Contains(out, "operation failed") {
		t.Error("missing failure log line")
	}
	if !strings.Contains(out, string(ErrKindSignatureMismatch)) {
		t.Error("failure log line missing error kind")
	}
	if strings.Contains(out, string(secret)) || strings.Contains(out, string(payload)) {
		t.Error("log output leaks key material or payload")
	}
}

// TestDefaultPathUnchanged verifies that enabling observability does not
// change the produced signatures, and that the default (observer-less) path
// returns unwrapped errors exactly as before.
func TestDefaultPathUnchanged(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	payload := []byte("deterministic payload")

	plain, err := NewSigner(SigningKey{Algorithm: EdDSA, Key: priv}, nil)
	require.NoError(t, err)
	observed, err := NewSigner(SigningKey{Algorithm: EdDSA, Key: priv}, &SignerOptions{
		Observer: &Observer{OnProgress: func(ProgressEvent) {}},
	})
	require.NoError(t, err)

	objPlain, err := plain.Sign(payload)
	require.NoError(t, err)
	objObserved, err := observed.Sign(payload)
	require.NoError(t, err)

	serPlain, err := objPlain.CompactSerialize()
	require.NoError(t, err)
	serObserved, err := objObserved.CompactSerialize()
	require.NoError(t, err)
	require.Equal(t, serObserved, serPlain)

	// VerifyWithOptions with nil observer behaves like Verify.
	got, err := objPlain.VerifyWithOptions(context.Background(), priv.Public(), nil)
	require.NoError(t, err)
	require.Equal(t, string(got), string(payload))

	// Default path keeps returning the raw sentinel error, not *OpError.
	_, err = objPlain.Verify([]byte("wrong-key"))
	assert.Error(t, err)
	require.Equal(t, err, ErrCryptoFailure)
	var opErr *OpError
	if errors.As(err, &opErr) {
		t.Fatal("default path must not return *OpError")
	}
}

// TestObserveUnknownTotal verifies that progress works when the total amount
// of work is unknown up front (streaming-style), with Total reported as -1.
func TestObserveUnknownTotal(t *testing.T) {
	rec := &progressRecorder{}
	obs := &Observer{OnProgress: rec.record}

	ran := false
	err := Observe(context.Background(), "stream.op", -1, obs, func() error {
		ran = true
		return nil
	})
	require.NoError(t, err)
	if !ran {
		t.Fatal("observed function did not run")
	}

	events := rec.snapshot()
	require.Equal(t, len(events), 3)
	require.Equal(t, events[0].Stage, "start")
	require.Equal(t, events[0].Total, int64(-1))
	require.Equal(t, events[2].Stage, "done")
	require.Equal(t, events[2].Total, int64(-1))

	// Nil observer: fn runs directly, no callbacks.
	err = Observe(context.Background(), "stream.op", -1, nil, func() error { return nil })
	require.NoError(t, err)

	// Cancelled context surfaces as cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = Observe(ctx, "stream.op", -1, obs, func() error { return nil })
	assert.ErrorIs(t, err, context.Canceled)
	require.Equal(t, ClassifyError(err), ErrKindCancelled)
}

// TestConcurrentObservedVerify verifies that concurrent observed operations
// each get an independent, consistent progress stream.
func TestConcurrentObservedVerify(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: key}, nil)
	require.NoError(t, err)
	obj, err := signer.Sign([]byte("payload"))
	require.NoError(t, err)

	const workers = 8
	recs := make([]*progressRecorder, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		recs[i] = &progressRecorder{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			obs := &Observer{OnProgress: recs[i].record}
			_, err := obj.VerifyWithOptions(context.Background(), key, obs)
			if err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()

	for i, rec := range recs {
		events := rec.snapshot()
		if len(events) == 0 {
			t.Fatalf("worker %d saw no progress events", i)
		}
		last := events[len(events)-1]
		require.Equal(t, last.Stage, "done")
		require.Equal(t, last.Completed, int64(1))
	}
}
