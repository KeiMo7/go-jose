/*-
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jose

import (
	"errors"
	"fmt"
)

// This file implements detailed multi-signature verification. Unlike
// DetachedVerifyMulti, which stops at the first signature that verifies and
// silently skips the rest, the entry points here evaluate every signature on
// the object and report a per-signature verdict with a closed set of failure
// categories. The overall conclusion is derived from the per-signature
// verdicts, never reconstructed from error text.
//
// The existing single-signature entry points (Verify, DetachedVerify) are
// intentionally left untouched: messages with exactly one signature should
// continue to use them, and their conclusions, error types and return timing
// are unchanged.

var (
	// ErrUnprotectedCriticalHeader is returned (as part of a per-signature
	// verdict) when a "crit" header parameter appears in the unprotected
	// header of a signature. Per RFC 7515 Section 4.1.11, "crit" MUST be
	// integrity protected.
	ErrUnprotectedCriticalHeader = errors.New("go-jose/go-jose: crit header parameter must be integrity protected")

	// ErrMissingProtectedHeader indicates a signature in a multi-signature
	// JWS has no protected header and therefore cannot be evaluated by the
	// detailed verification path.
	ErrMissingProtectedHeader = errors.New("go-jose/go-jose: signature is missing a protected header")

	// ErrInvalidCriticalHeader indicates a structurally invalid "crit"
	// declaration: not a list of strings, an empty list, or a name that
	// does not occur in the signature's headers.
	ErrInvalidCriticalHeader = errors.New("go-jose/go-jose: invalid crit header parameter")
)

// SignatureFailureCategory classifies why a single signature failed
// verification. The set of values is closed: any failure that does not map
// to one of the specific categories is reported as
// SignatureFailureUnknown.
type SignatureFailureCategory int

const (
	// SignatureFailureNone indicates the signature verified; used only for
	// valid verdicts.
	SignatureFailureNone SignatureFailureCategory = iota

	// SignatureFailureCriticalUnsupported indicates the signature declares
	// a critical extension header that this library does not understand,
	// or the "crit" declaration itself is structurally invalid (not a
	// string list, empty, or naming a header that is not present).
	SignatureFailureCriticalUnsupported

	// SignatureFailureCriticalInvalidPosition indicates a "crit" header
	// parameter appeared outside the integrity-protected header.
	SignatureFailureCriticalInvalidPosition

	// SignatureFailureSignatureMismatch indicates the signature value did
	// not verify against the payload and key.
	SignatureFailureSignatureMismatch

	// SignatureFailureKeyUnavailable indicates no usable verification key
	// was available for this signature (e.g. no matching key in a JWK Set,
	// or an unsupported key type).
	SignatureFailureKeyUnavailable

	// SignatureFailureAlgorithmNotAllowed indicates the signature's "alg"
	// header is not in the caller-provided set of allowed algorithms.
	SignatureFailureAlgorithmNotAllowed

	// SignatureFailureUnknown is the fallback for any failure that does
	// not map to one of the categories above.
	SignatureFailureUnknown
)

// String returns a short human-readable name for the category.
func (c SignatureFailureCategory) String() string {
	switch c {
	case SignatureFailureNone:
		return "none"
	case SignatureFailureCriticalUnsupported:
		return "critical-header-unsupported"
	case SignatureFailureCriticalInvalidPosition:
		return "critical-header-invalid-position"
	case SignatureFailureSignatureMismatch:
		return "signature-mismatch"
	case SignatureFailureKeyUnavailable:
		return "key-unavailable"
	case SignatureFailureAlgorithmNotAllowed:
		return "algorithm-not-allowed"
	default:
		return "unknown"
	}
}

// SignatureVerdict is the verification outcome for a single signature of a
// multi-signature JWS.
type SignatureVerdict struct {
	// Index is the position of the signature in JSONWebSignature.Signatures.
	Index int

	// Algorithm is the "alg" header value of this signature.
	Algorithm SignatureAlgorithm

	// Valid reports whether this signature verified.
	Valid bool

	// Category classifies the failure. It is SignatureFailureNone when
	// Valid is true.
	Category SignatureFailureCategory

	// Err is the underlying error for a failed signature, nil when Valid.
	Err error
}

// String returns a one-line human-readable summary of the verdict.
func (v SignatureVerdict) String() string {
	if v.Valid {
		return fmt.Sprintf("signature #%d (%s): valid", v.Index, v.Algorithm)
	}
	if v.Err != nil {
		return fmt.Sprintf("signature #%d (%s): invalid [%s]: %v", v.Index, v.Algorithm, v.Category, v.Err)
	}
	return fmt.Sprintf("signature #%d (%s): invalid [%s]", v.Index, v.Algorithm, v.Category)
}

// MultiSignatureVerification is the result of evaluating every signature on
// a JWS object. The overall conclusion (Valid, Passed) is aggregated from
// the per-signature Verdicts.
type MultiSignatureVerification struct {
	// Valid is true only if every signature on the object verified.
	Valid bool

	// Passed is the number of signatures that verified.
	Passed int

	// Total is the number of signatures evaluated.
	Total int

	// Verdicts holds one verdict per signature, in signature order. For a
	// given input the order and content of Verdicts is deterministic.
	Verdicts []SignatureVerdict
}

// String returns a multi-line human-readable summary of the result.
func (r MultiSignatureVerification) String() string {
	out := fmt.Sprintf("valid=%t passed=%d/%d", r.Valid, r.Passed, r.Total)
	for _, v := range r.Verdicts {
		out += "\n  " + v.String()
	}
	return out
}

// VerifyMultiDetailed verifies every signature on the object and returns a
// per-signature breakdown of the outcome. Unlike VerifyMulti, it does not
// stop at the first valid signature: a signature that declares an
// unsupported critical extension header, or that fails for any other reason,
// is reported explicitly and makes the overall result invalid.
//
// The signatureAlgorithms parameter, when non-empty, restricts the "alg"
// header values that are acceptable for each signature; signatures using any
// other algorithm are reported with
// SignatureFailureAlgorithmNotAllowed. It may be nil to skip this check
// (e.g. when the object was produced by ParseSignedJSON, which already
// enforced an algorithm set at parse time).
//
// Messages with exactly one signature should generally be verified with
// Verify instead; this entry point accepts them but its verdict semantics
// differ (e.g. a missing protected header is rejected here).
//
// The verificationKey argument must have one of the types allowed for the
// verificationKey argument of JSONWebSignature.Verify().
func (obj JSONWebSignature) VerifyMultiDetailed(verificationKey any, signatureAlgorithms []SignatureAlgorithm) (MultiSignatureVerification, error) {
	return obj.DetachedVerifyMultiDetailed(obj.payload, verificationKey, signatureAlgorithms)
}

// DetachedVerifyMultiDetailed is like VerifyMultiDetailed but verifies a
// detached payload instead of the payload embedded in the object.
func (obj JSONWebSignature) DetachedVerifyMultiDetailed(payload []byte, verificationKey any, signatureAlgorithms []SignatureAlgorithm) (MultiSignatureVerification, error) {
	if len(obj.Signatures) == 0 {
		return MultiSignatureVerification{}, errors.New("go-jose/go-jose: no signatures in JWS")
	}
	if len(obj.Signatures) > MaxSignatures {
		return MultiSignatureVerification{}, fmt.Errorf("go-jose/go-jose: too many signatures in JWS; maximum is %d", MaxSignatures)
	}

	result := MultiSignatureVerification{
		Valid:    true,
		Total:    len(obj.Signatures),
		Verdicts: make([]SignatureVerdict, 0, len(obj.Signatures)),
	}

	// Each signature is evaluated independently and exactly once, so the
	// total work is linear in the number of signatures and the per-signature
	// verdicts are deterministic for a given input.
	for i := range obj.Signatures {
		verdict := obj.verifySignatureDetailed(i, payload, verificationKey, signatureAlgorithms)
		if verdict.Valid {
			result.Passed++
		} else {
			result.Valid = false
		}
		result.Verdicts = append(result.Verdicts, verdict)
	}

	return result, nil
}

// verifySignatureDetailed evaluates a single signature and classifies the
// failure, if any, at the point where it occurs.
func (obj JSONWebSignature) verifySignatureDetailed(index int, payload []byte, verificationKey any, signatureAlgorithms []SignatureAlgorithm) SignatureVerdict {
	signature := obj.Signatures[index]

	verdict := SignatureVerdict{
		Index:    index,
		Category: SignatureFailureNone,
	}
	verdict.Algorithm = signature.mergedHeaders().getSignatureAlgorithm()

	fail := func(category SignatureFailureCategory, err error) SignatureVerdict {
		verdict.Valid = false
		verdict.Category = category
		verdict.Err = err
		return verdict
	}

	// Per RFC 7515 Section 4.1.11, "crit" MUST be integrity protected and
	// therefore MUST NOT appear in the unprotected header. This is rejected
	// regardless of whether the signature value itself would verify.
	if signature.header != nil && signature.header.isSet(headerCritical) {
		return fail(SignatureFailureCriticalInvalidPosition, ErrUnprotectedCriticalHeader)
	}

	// Without a protected header the integrity of the signature's
	// parameters (including any critical extensions) cannot be established,
	// so this signature cannot be used. Other signatures are still
	// evaluated; the overall result is invalid.
	if signature.protected == nil {
		return fail(SignatureFailureUnknown, ErrMissingProtectedHeader)
	}

	// Validate the "crit" declaration structurally before consulting the
	// set of supported extensions: it must be a non-empty list of strings,
	// and every name it declares must occur in this signature's headers.
	// A declaration that fails these checks is a structural problem and is
	// never treated as recognized.
	if signature.protected.isSet(headerCritical) {
		crit, err := signature.protected.getCritical()
		if err != nil {
			return fail(SignatureFailureCriticalUnsupported, fmt.Errorf("%w: %v", ErrInvalidCriticalHeader, err))
		}
		if len(crit) == 0 {
			return fail(SignatureFailureCriticalUnsupported, fmt.Errorf("%w: empty list", ErrInvalidCriticalHeader))
		}
		merged := signature.mergedHeaders()
		for _, name := range crit {
			if !merged.isSet(HeaderKey(name)) {
				return fail(SignatureFailureCriticalUnsupported, fmt.Errorf("%w: %q does not occur in the signature's headers", ErrInvalidCriticalHeader, name))
			}
			if _, ok := supportedCritical[name]; !ok {
				return fail(SignatureFailureCriticalUnsupported, fmt.Errorf("%w: %q", ErrUnsupportedCriticalHeader, name))
			}
		}
	}

	if len(signatureAlgorithms) > 0 && !containsSignatureAlgorithm(signatureAlgorithms, verdict.Algorithm) {
		return fail(SignatureFailureAlgorithmNotAllowed, newErrUnexpectedSignatureAlgorithm(verdict.Algorithm, signatureAlgorithms))
	}

	// If the verification key is a JWK Set, pick a key based on this
	// signature's "kid" header; a single key is used as-is. At most one key
	// is tried per signature.
	key, err := tryJWKS(verificationKey, signature.Header)
	if err != nil {
		return fail(SignatureFailureKeyUnavailable, err)
	}
	verifier, err := newVerifier(key)
	if err != nil {
		return fail(SignatureFailureKeyUnavailable, err)
	}

	input, err := obj.computeAuthData(payload, &signature)
	if err != nil {
		return fail(SignatureFailureSignatureMismatch, ErrCryptoFailure)
	}

	if err := verifier.verifyPayload(input, signature.Signature, verdict.Algorithm); err != nil {
		return fail(SignatureFailureSignatureMismatch, ErrCryptoFailure)
	}

	verdict.Valid = true
	return verdict
}
