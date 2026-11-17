package jwt

import (
	"context"
	"errors"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/json"
)

// JWT-specific error kinds, reusing the jose.ErrorKind type so callers can
// classify JWS and JWT failures uniformly via ClassifyError.
const (
	// ErrKindExpired indicates the token is used after its exp claim.
	ErrKindExpired = jose.ErrorKind("expired")
	// ErrKindNotYetValid indicates the token is used before its nbf claim.
	ErrKindNotYetValid = jose.ErrorKind("not_valid_yet")
	// ErrKindIssuedInFuture indicates the iat claim is in the future.
	ErrKindIssuedInFuture = jose.ErrorKind("issued_in_future")
	// ErrKindClaimsValidation indicates a claims mismatch (iss, sub, aud, jti).
	ErrKindClaimsValidation = jose.ErrorKind("claims_validation")
)

// ClassifyError maps an error returned by this package (claims validation,
// parsing, or the underlying JWS verification) to a jose.ErrorKind. It
// distinguishes the three verification failure categories explicitly:
// signature mismatch (jose.ErrKindSignatureMismatch), expiry
// (ErrKindExpired), and disallowed algorithms
// (jose.ErrKindAlgorithmNotAllowed). Unknown errors fall back to
// jose.ClassifyError.
func ClassifyError(err error) jose.ErrorKind {
	if err == nil {
		return jose.ErrKindNone
	}
	switch {
	case errors.Is(err, ErrExpired):
		return ErrKindExpired
	case errors.Is(err, ErrNotValidYet):
		return ErrKindNotYetValid
	case errors.Is(err, ErrIssuedInTheFuture):
		return ErrKindIssuedInFuture
	case errors.Is(err, ErrInvalidIssuer),
		errors.Is(err, ErrInvalidSubject),
		errors.Is(err, ErrInvalidAudience),
		errors.Is(err, ErrInvalidID):
		return ErrKindClaimsValidation
	default:
		return jose.ClassifyError(err)
	}
}

// ClaimsWithOptions deserializes the token's claims like Claims, but accepts
// a context for cancellation and an optional jose.Observer for runtime
// observability. Both may be nil, in which case it behaves exactly like
// Claims.
//
// For signed tokens (ParseSigned) the underlying JWS verification reports
// progress and supports cancellation. For encrypted tokens (ParseEncrypted)
// the total amount of work is not known up front, so progress events carry
// Total == -1; cancellation is checked before and after decryption.
func (t *JSONWebToken) ClaimsWithOptions(ctx context.Context, obs *jose.Observer, key interface{}, dest ...interface{}) error {
	if ctx == nil {
		ctx = context.Background()
	}

	var b []byte
	var err error
	if t.sig != nil {
		b, err = t.sig.VerifyWithOptions(ctx, key, obs)
	} else {
		err = jose.Observe(ctx, "jwt.decrypt", -1, obs, func() error {
			var perr error
			b, perr = t.payload(key)
			return perr
		})
	}
	if err != nil {
		return err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}

	for _, d := range dest {
		if err := json.Unmarshal(b, d); err != nil {
			return err
		}
	}

	return nil
}
