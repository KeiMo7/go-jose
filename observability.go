package jose

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// ErrorKind classifies failures surfaced by go-jose operations so callers can
// react programmatically instead of parsing error strings.
type ErrorKind string

const (
	// ErrKindNone indicates no error.
	ErrKindNone ErrorKind = ""
	// ErrKindSignatureMismatch indicates that signature or MAC verification
	// failed (ErrCryptoFailure on the JWS path). On JWE decryption paths the
	// same kind covers authentication-tag failures.
	ErrKindSignatureMismatch ErrorKind = "signature_mismatch"
	// ErrKindAlgorithmNotAllowed indicates that the algorithm in the message
	// header is not in the caller-provided allow list.
	ErrKindAlgorithmNotAllowed ErrorKind = "algorithm_not_allowed"
	// ErrKindUnsupported indicates an algorithm, key type, or serialization
	// that this build of go-jose does not support (for example ML-DSA on a
	// Go toolchain older than 1.27).
	ErrKindUnsupported ErrorKind = "unsupported"
	// ErrKindCancelled indicates the operation was cancelled via its context
	// or hit the context deadline. It is distinct from a failure.
	ErrKindCancelled ErrorKind = "cancelled"
	// ErrKindMalformed indicates the input could not be parsed.
	ErrKindMalformed ErrorKind = "malformed_input"
	// ErrKindOther covers everything else.
	ErrKindOther ErrorKind = "other"
)

// ClassifyError maps an error returned by go-jose to an ErrorKind. It never
// returns ErrKindNone for a non-nil error; unrecognized errors map to
// ErrKindOther. Cancellation is detected via context.Canceled and
// context.DeadlineExceeded, so callers can distinguish "cancelled" from
// "failed".
func ClassifyError(err error) ErrorKind {
	if err == nil {
		return ErrKindNone
	}
	var algErr *ErrUnexpectedSignatureAlgorithm
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return ErrKindCancelled
	case errors.Is(err, ErrCryptoFailure):
		return ErrKindSignatureMismatch
	case errors.As(err, &algErr):
		return ErrKindAlgorithmNotAllowed
	case errors.Is(err, ErrUnsupportedAlgorithm),
		errors.Is(err, ErrUnsupportedKeyType),
		errors.Is(err, ErrUnsupportedCriticalHeader),
		errors.Is(err, ErrNotSupported):
		return ErrKindUnsupported
	case errors.Is(err, errEmptyInput):
		return ErrKindMalformed
	default:
		return ErrKindOther
	}
}

// OpError is the structured error returned by observability-enabled
// operations. It wraps the original error (Unwrap is supported, so errors.Is
// and errors.As keep working) and adds a classification plus redacted
// context. Context never contains key material, payloads, tokens, or file
// paths; it is limited to algorithm names, counters, and stage labels.
type OpError struct {
	// Op is the operation that failed, e.g. "jws.sign" or "jws.verify".
	Op string
	// Kind classifies the failure.
	Kind ErrorKind
	// Stage is the pipeline stage in which the failure occurred.
	Stage string
	// Context holds redacted key/value pairs describing the failure.
	Context map[string]string
	// Err is the underlying error.
	Err error
}

func (e *OpError) Error() string {
	return fmt.Sprintf("go-jose/go-jose: %s failed at %s (%s): %v", e.Op, e.Stage, e.Kind, e.Err)
}

// Unwrap returns the underlying error.
func (e *OpError) Unwrap() error {
	return e.Err
}

// ProgressEvent describes one progress sample of a running operation.
type ProgressEvent struct {
	// Operation is the operation name, e.g. "jws.sign", "jws.verify",
	// "jws.verify_multi", or "jwt.decrypt".
	Operation string
	// Stage is the pipeline stage the event belongs to, e.g. "start",
	// "sign-recipient", "verify-signature", or "done".
	Stage string
	// Completed is the number of units finished so far. It increases
	// monotonically within one operation.
	Completed int64
	// Total is the expected number of units, or -1 when the total is not
	// known up front (for example streaming or opaque external operations).
	Total int64
	// Elapsed is the wall-clock time since the operation started.
	Elapsed time.Duration
}

// Observer enables optional runtime observability for signing and
// verification. It is nil-safe: a nil Observer disables all observability
// and the default code paths behave exactly as before.
//
// OnProgress must be safe for concurrent use: independent operations may
// report progress from multiple goroutines. A panic inside OnProgress is
// recovered, logged via Logger (if set), and never aborts the operation.
type Observer struct {
	// OnProgress is invoked with progress samples. Nil disables progress
	// callbacks.
	OnProgress func(ProgressEvent)
	// ProgressInterval is the minimum wall-clock interval between two
	// OnProgress invocations within one operation. Intermediate samples are
	// dropped (the counters keep advancing, so no information is lost other
	// than sampling density). The first and the final "done" sample are
	// always delivered. Zero means every step is reported.
	ProgressInterval time.Duration
	// Logger receives one structured log line on operation entry, exit, and
	// failure. Nil disables logging. Entry and exit are logged at Debug
	// level, failures at Warn level. Logged attributes are redacted: they
	// contain operation names, stages, counters, durations, and error kinds,
	// never key material, payloads, or tokens.
	Logger *slog.Logger
}

// progressTracker is the per-operation engine behind Observer. It carries no
// global state and does not accumulate samples, so long-running processes do
// not grow memory. A nil *progressTracker is valid and every method is a
// no-op on it, which keeps the default (unobserved) path allocation-free.
type progressTracker struct {
	op        string
	obs       *Observer
	total     int64
	completed int64
	started   time.Time
	last      time.Time
}

// newTracker returns a tracker for op, or nil when obs is nil or carries
// neither a callback nor a logger. total may be -1 to signal an unknown
// total.
func newTracker(op string, obs *Observer, total int64) *progressTracker {
	if obs == nil || (obs.OnProgress == nil && obs.Logger == nil) {
		return nil
	}
	t := &progressTracker{
		op:      op,
		obs:     obs,
		total:   total,
		started: time.Now(),
	}
	t.log(slog.LevelDebug, "operation started")
	t.report("start", true)
	return t
}

// step advances the completed counter by one and reports a throttled sample.
func (t *progressTracker) step(stage string) {
	if t == nil {
		return
	}
	t.completed++
	t.report(stage, false)
}

// report emits a progress sample, honoring Observer.ProgressInterval unless
// force is set.
func (t *progressTracker) report(stage string, force bool) {
	if t == nil || t.obs.OnProgress == nil {
		return
	}
	now := time.Now()
	if !force && t.obs.ProgressInterval > 0 && now.Sub(t.last) < t.obs.ProgressInterval {
		return
	}
	t.last = now
	t.safeCall(ProgressEvent{
		Operation: t.op,
		Stage:     stage,
		Completed: t.completed,
		Total:     t.total,
		Elapsed:   now.Sub(t.started),
	})
}

// safeCall invokes the user callback and isolates panics: a panicking
// callback is logged and swallowed so it cannot take down the operation.
func (t *progressTracker) safeCall(evt ProgressEvent) {
	defer func() {
		if r := recover(); r != nil {
			t.log(slog.LevelWarn, "progress callback panicked; continuing", "panic", fmt.Sprint(r))
		}
	}()
	t.obs.OnProgress(evt)
}

// finish marks the operation as successfully completed: it forces a final
// "done" sample and logs the exit line.
func (t *progressTracker) finish(stage string) {
	if t == nil {
		return
	}
	t.report(stage, true)
	t.log(slog.LevelDebug, "operation finished",
		"completed", t.completed, "total", t.total)
}

// fail logs the failure line with the classified error kind. It does not
// emit a progress sample.
func (t *progressTracker) fail(stage string, err error) {
	if t == nil {
		return
	}
	t.log(slog.LevelWarn, "operation failed",
		"stage", stage,
		"kind", string(ClassifyError(err)),
		"error", err.Error())
}

// log writes one structured line with redacted attributes.
func (t *progressTracker) log(level slog.Level, msg string, attrs ...interface{}) {
	if t == nil || t.obs.Logger == nil {
		return
	}
	args := make([]interface{}, 0, len(attrs)+4)
	args = append(args, "op", t.op, "elapsed", time.Since(t.started).String())
	args = append(args, attrs...)
	t.obs.Logger.Log(context.Background(), level, msg, args...)
}

// cancelled returns a structured cancellation error for the operation, or
// nil when the context is still alive.
func (t *progressTracker) cancelled(ctx context.Context, stage string) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		t.fail(stage, err)
		return &OpError{
			Op:    t.opName(),
			Kind:  ErrKindCancelled,
			Stage: stage,
			Err:   err,
		}
	}
	return nil
}

func (t *progressTracker) opName() string {
	if t == nil {
		return ""
	}
	return t.op
}

// wrapError builds a structured error for observability-enabled operations.
// When the tracker is nil (default path) the original error is returned
// unchanged so existing behavior is preserved byte-for-byte.
func (t *progressTracker) wrapError(stage string, err error, ctx map[string]string) error {
	if err == nil || t == nil {
		return err
	}
	t.fail(stage, err)
	return &OpError{
		Op:      t.op,
		Kind:    ClassifyError(err),
		Stage:   stage,
		Context: ctx,
		Err:     err,
	}
}

// ContextSigner is implemented by signers created with NewSigner and
// NewMultiSigner. It allows callers to cancel an in-flight Sign operation
// via the context. Cancellation is checked between recipients; a cancelled
// operation returns an *OpError with Kind ErrKindCancelled wrapping
// ctx.Err(), so errors.Is(err, context.Canceled) holds.
type ContextSigner interface {
	Signer
	SignWithContext(ctx context.Context, payload []byte) (*JSONWebSignature, error)
}

// Observe runs fn inside an observation scope named op, emitting start and
// done progress events plus entry, exit, and failure log lines through obs.
// total may be -1 when the amount of work is not known up front, for example
// for streaming input or opaque external operations; progress is still
// reported, only Total stays unknown. Cancellation of ctx is checked before
// and after fn. When obs is nil, fn is invoked directly and no observability
// overhead is incurred.
func Observe(ctx context.Context, op string, total int64, obs *Observer, fn func() error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	tr := newTracker(op, obs, total)
	if tr == nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fn()
	}
	if err := tr.cancelled(ctx, "start"); err != nil {
		return err
	}
	if err := fn(); err != nil {
		return tr.wrapError("run", err, nil)
	}
	if err := tr.cancelled(ctx, "done"); err != nil {
		return err
	}
	tr.step("run")
	tr.finish("done")
	return nil
}
