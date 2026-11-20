/*-
 * Copyright 2026 The go-jose Authors
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
	"bytes"
	"errors"
	"fmt"
)

// maxPBES2Iterations is the per-message upper bound on the PBES2 iteration
// count. It applies to every entry point, including the legacy Decrypt and
// DecryptMulti APIs.
const maxPBES2Iterations = 1000000

// MaxKeyCandidates is the maximum number of candidate keys accepted by a
// single [JSONWebEncryption.DecryptEnvelope] call. Together with
// [MaxRecipients] it bounds the amount of work an untrusted message can cause.
// A JSON Web Key Set passed as a single candidate is expanded, and every key
// in it counts toward this limit.
//
// If modifying MaxKeyCandidates, do it before any decryption occurs.
var MaxKeyCandidates = 32

// MaxEnvelopePBES2Iterations bounds the total PBKDF2 work performed by one
// [JSONWebEncryption.DecryptEnvelope] call. The "p2c" iteration count of every
// PBES2 key unwrap attempted during the call is charged against this budget.
// Attempts that would exceed it are rejected with [FailurePBES2Iterations]
// before any derivation is performed.
//
// It is a variable so that applications can raise or lower the limit before
// calling DecryptEnvelope. Per-call limits in [EnvelopeOptions] can only lower
// it.
var MaxEnvelopePBES2Iterations = 10_000_000

// FailureKind classifies why an attempt to decrypt one recipient of a JWE
// failed. The zero value, [FailureNone], means the recipient was decrypted
// successfully.
type FailureKind int

const (
	// FailureNone indicates success.
	FailureNone FailureKind = iota

	// FailureNoKeys indicates that no candidate keys were supplied at all.
	FailureNoKeys

	// FailureNoUsableKeys indicates that none of the supplied candidate keys
	// could be used to decrypt anything, for example because they were nil or
	// of an unsupported type.
	FailureNoUsableKeys

	// FailureNoMatchingKey indicates that the recipient declares a key ID and
	// no candidate key carries that ID (and no candidate is unlabelled).
	FailureNoMatchingKey

	// FailureKeyUnwrap indicates that key management failed: the candidate key
	// did not match the recipient, or the wrapped content encryption key could
	// not be unwrapped.
	FailureKeyUnwrap

	// FailureKeyAlgorithm indicates that the recipient declared a key
	// management algorithm, or used parameters, that cannot be processed.
	FailureKeyAlgorithm

	// FailureWrongKeySize indicates that the key management algorithm declared
	// one strength but was supplied key material of a different size. Both
	// sides of the mismatch are recorded.
	FailureWrongKeySize

	// FailurePBES2Iterations indicates that the password-based key derivation
	// iteration count was out of the accepted range, or would exceed the
	// envelope's total derivation budget.
	FailurePBES2Iterations

	// FailurePBES2Salt indicates that the password-based key derivation was
	// missing a salt.
	FailurePBES2Salt

	// FailurePBES2Derive indicates that the password-based key derivation
	// itself failed.
	FailurePBES2Derive

	// FailureContentKeySize indicates that the content encryption key derived
	// for this recipient had the wrong length for the declared "enc"
	// algorithm. The recipient is rejected rather than continuing with the
	// wrong key.
	FailureContentKeySize

	// FailureCEKMismatch indicates that this recipient derived a content
	// encryption key that differs from the one the other recipients derived.
	// All recipients of a message must agree on the content key.
	FailureCEKMismatch

	// FailureContentDecrypt indicates that a correctly sized content
	// encryption key was obtained but the content itself failed
	// authentication. The key matched the recipient, but the ciphertext, IV,
	// tag, or authenticated data was modified.
	FailureContentDecrypt

	// FailureDecompress indicates that decryption succeeded but the plaintext
	// could not be decompressed.
	FailureDecompress

	// FailureInternal indicates an error that does not fit any other category.
	FailureInternal
)

func (k FailureKind) String() string {
	switch k {
	case FailureNone:
		return "none"
	case FailureNoKeys:
		return "no-keys"
	case FailureNoUsableKeys:
		return "no-usable-keys"
	case FailureNoMatchingKey:
		return "no-matching-key"
	case FailureKeyUnwrap:
		return "key-unwrap"
	case FailureKeyAlgorithm:
		return "key-algorithm"
	case FailureWrongKeySize:
		return "wrong-key-size"
	case FailurePBES2Iterations:
		return "pbes2-iterations"
	case FailurePBES2Salt:
		return "pbes2-salt"
	case FailurePBES2Derive:
		return "pbes2-derive"
	case FailureContentKeySize:
		return "content-key-size"
	case FailureCEKMismatch:
		return "content-key-mismatch"
	case FailureContentDecrypt:
		return "content-decrypt"
	case FailureDecompress:
		return "decompress"
	case FailureInternal:
		return "internal"
	default:
		return fmt.Sprintf("FailureKind(%d)", int(k))
	}
}

// EnvelopeFailure describes why an attempt on a recipient failed.
type EnvelopeFailure struct {
	// Kind is the category of the failure.
	Kind FailureKind
	// Err is the underlying error, if any. It can be inspected with
	// [errors.Is].
	Err error
	// Detail is a human-readable explanation. It is informational only;
	// callers should branch on Kind rather than parse it.
	Detail string
	// Expected and Actual report the two sides of a size mismatch, in bits.
	// They are zero for other kinds.
	Expected int
	Actual   int
}

func (f *EnvelopeFailure) Error() string {
	if f == nil {
		return "<nil>"
	}
	msg := "go-jose/go-jose: " + f.Kind.String()
	if f.Detail != "" {
		msg += ": " + f.Detail
	}
	return msg
}

// Unwrap returns the underlying cause, if any.
func (f *EnvelopeFailure) Unwrap() error {
	if f == nil {
		return nil
	}
	return f.Err
}

// KeyCandidate is one decryption key that DecryptEnvelope may try, paired with
// the identifier used to match it against recipient headers.
//
// A candidate whose Key is a [JSONWebKeySet] is expanded into one candidate per
// key in the set, preserving each key's own KeyID. This makes it possible to
// hold a rotation-era key ring where several keys share one key ID: all of them
// are tried, in set order.
type KeyCandidate struct {
	// Key is a decryption key of a type accepted by
	// [JSONWebEncryption.Decrypt], or a [JSONWebKeySet].
	Key any
	// KeyID is the identifier of this key. When non-empty it is matched
	// against the "kid" header of each recipient. If Key is a [JSONWebKey], an
	// empty KeyID inherits the JWK's own KeyID. A candidate with no key ID at
	// all is tried against every recipient.
	KeyID string
}

// EnvelopeOptions tunes a [JSONWebEncryption.DecryptEnvelope] call. The zero
// value applies the package defaults.
type EnvelopeOptions struct {
	// MaxCandidates, when positive, is the maximum number of candidate keys
	// tried per recipient. Values above [MaxKeyCandidates] are clamped to it.
	MaxCandidates int
	// MaxPBES2Iterations, when positive, lowers the PBES2 derivation budget
	// for this call. Values above [MaxEnvelopePBES2Iterations] are clamped to
	// it.
	MaxPBES2Iterations int
}

// CandidateAttempt records the outcome of trying one candidate key against one
// recipient. Attempts are recorded in the order they were made.
type CandidateAttempt struct {
	// KeyIndex is the position, in the slice supplied to DecryptEnvelope, of
	// the candidate that was tried. When a [JSONWebKeySet] was supplied as a
	// single candidate, every key expanded from it shares that position.
	KeyIndex int
	// KeyPosition is the position of the key in the flattened candidate list:
	// all keys of a key set, followed by later candidates. It identifies the
	// individual key when several were supplied, or expanded, as one ring.
	KeyPosition int
	// KeyID is the candidate's key ID.
	KeyID string
	// Failure is nil when this attempt succeeded.
	Failure *EnvelopeFailure
}

// RecipientOutcome reports the result of decrypting one recipient.
type RecipientOutcome struct {
	// Index is the position of the recipient in the message.
	Index int
	// KeyID is the "kid" declared in this recipient's merged headers. It may
	// come from the protected, unprotected, or per-recipient header.
	KeyID string
	// Algorithm is the "alg" declared in this recipient's merged headers.
	Algorithm KeyAlgorithm
	// OK reports whether this recipient was fully decrypted and, if the
	// message was compressed, decompressed.
	OK bool
	// KeyUnwrapped reports whether a content encryption key was derived for
	// this recipient, independently of whether the content or decompression
	// stage succeeded. This keeps the key-stage conclusion when a later stage
	// fails.
	KeyUnwrapped bool
	// Failure is nil when OK is true, and describes the failure otherwise.
	Failure *EnvelopeFailure
	// Plaintext is this recipient's decrypted plaintext. It is set only when
	// OK is true.
	Plaintext []byte
	// UsedKeyID is the key ID of the candidate that decrypted this recipient.
	// It is set only when OK is true. Comparing UsedKeyID across messages is
	// how callers tell which key of a rotation decrypted a message.
	UsedKeyID string
	// UsedKeyIndex is the position, in the candidate slice, of the key that
	// decrypted this recipient. It is -1 when OK is false. When the successful
	// candidate was a key set, this is the position of the set.
	UsedKeyIndex int
	// UsedKeyPosition is the position of the successful key in the flattened
	// candidate list (all key-set keys first, then later candidates). It
	// distinguishes the individual keys of a rotation-era ring, including keys
	// that share one key ID. It is -1 when OK is false.
	UsedKeyPosition int
	// Attempts records every candidate key tried for this recipient.
	Attempts []CandidateAttempt

	// cek is the content encryption key accepted for this recipient. It is
	// kept to verify that all recipients agree.
	cek []byte
}

// EnvelopeResult is the result of [JSONWebEncryption.DecryptEnvelope]. It
// reports the outcome of every recipient independently.
type EnvelopeResult struct {
	// Recipients holds one outcome per recipient, in message order. Every
	// recipient is attempted; decryption does not stop at the first success.
	Recipients []RecipientOutcome
	// Plaintext is the shared plaintext, set when at least one recipient
	// succeeded. Successful recipients all derived the same content
	// encryption key, so one plaintext represents them all.
	Plaintext []byte
	// Plaintexts holds the plaintext produced by each successful recipient, in
	// message order. The entries are always equal; they are exposed so callers
	// can verify that themselves.
	Plaintexts [][]byte
	// KeyIDs holds the [RecipientOutcome.UsedKeyID] of every successful
	// recipient, in message order.
	KeyIDs []string
	// Err is non-nil when no recipient could be decrypted. When every
	// recipient failed it wraps [ErrAllRecipientsFailed], and additionally
	// wraps [ErrNoKeyCandidates] or [ErrNoUsableKeyCandidates] if those were
	// the reason.
	Err error
}

// Failed reports whether the envelope as a whole failed. It is true exactly
// when no recipient produced plaintext.
func (r *EnvelopeResult) Failed() bool {
	return r == nil || len(r.Plaintexts) == 0
}

// Successful returns the outcomes of recipients that were decrypted.
func (r *EnvelopeResult) Successful() []RecipientOutcome {
	var out []RecipientOutcome
	if r == nil {
		return out
	}
	for _, ro := range r.Recipients {
		if ro.OK {
			out = append(out, ro)
		}
	}
	return out
}

var (
	// ErrAllRecipientsFailed is wrapped by the envelope result error when every
	// recipient failed. The per-recipient reasons remain available in
	// [EnvelopeResult.Recipients].
	ErrAllRecipientsFailed = errors.New("go-jose/go-jose: no recipient could be decrypted")

	// ErrNoKeyCandidates is returned when the candidate set is empty.
	ErrNoKeyCandidates = errors.New("go-jose/go-jose: no key candidates supplied")

	// ErrNoUsableKeyCandidates is returned when no supplied candidate can be
	// used to decrypt anything at all, as opposed to candidates that were
	// usable but did not match any recipient.
	ErrNoUsableKeyCandidates = errors.New("go-jose/go-jose: no usable key candidates")

	// ErrNoMatchingKeyCandidate is returned when a recipient declares a key ID
	// that no candidate carries.
	ErrNoMatchingKeyCandidate = errors.New("go-jose/go-jose: no candidate key matches the recipient key ID")

	// ErrTooManyKeyCandidates is returned when more candidates are supplied
	// than [MaxKeyCandidates] allows.
	ErrTooManyKeyCandidates = errors.New("go-jose/go-jose: too many key candidates")

	// ErrInvalidPBES2Iterations indicates a "p2c" value outside the accepted
	// range.
	ErrInvalidPBES2Iterations = errors.New("go-jose/go-jose: invalid PBES2 iteration count")

	// ErrMissingPBES2Salt indicates a PBES2 recipient without a "p2s" salt.
	ErrMissingPBES2Salt = errors.New("go-jose/go-jose: missing PBES2 salt")

	// ErrPBES2Derivation indicates that PBKDF2 key derivation failed.
	ErrPBES2Derivation = errors.New("go-jose/go-jose: PBES2 key derivation failed")

	// ErrKeyStrengthMismatch indicates that the strength implied by a key
	// management algorithm does not match the supplied key material.
	ErrKeyStrengthMismatch = errors.New("go-jose/go-jose: key strength does not match algorithm")

	// ErrContentKeySizeMismatch indicates that a derived content encryption
	// key has the wrong length for the declared content encryption algorithm.
	ErrContentKeySizeMismatch = errors.New("go-jose/go-jose: content encryption key size does not match algorithm")

	// ErrContentKeyMismatch indicates that recipients of a single message
	// derived different content encryption keys.
	ErrContentKeyMismatch = errors.New("go-jose/go-jose: recipients derived different content encryption keys")
)

// resolvedCandidate is a KeyCandidate after its decrypter has been built.
type resolvedCandidate struct {
	// keyIndex is the position in the caller-supplied candidate slice;
	// keyPosition is the position in the flattened key list.
	keyIndex    int
	keyPosition int
	keyID       string
	decrypter   keyDecrypter
	err         error // non-nil if the candidate cannot be used
	symmetricIn int   // symmetric key size in bits; -1 if unknown
}

// DecryptEnvelope decrypts a JWE with one or more recipients, trying a set of
// candidate keys and reporting the outcome for every recipient.
//
// Unlike [JSONWebEncryption.DecryptMulti], it does not stop at the first
// successful recipient: every recipient is attempted and its outcome is
// reported in [EnvelopeResult.Recipients]. Candidate keys are matched against
// each recipient's own merged headers, so a "kid" that appears only in a
// per-recipient header is honored. Every candidate sharing a matching key ID is
// tried, in the order supplied.
//
// Key management failures are categorized in [EnvelopeFailure.Kind] instead of
// being collapsed into [ErrCryptoFailure]. Content authentication failures
// ([FailureContentDecrypt]) are distinguishable from key mismatch
// ([FailureKeyUnwrap]). PBES2 iteration-range faults, missing salts, and
// derivation failures each have their own category.
//
// The content encryption key for a recipient is always derived through the
// path selected by that recipient's declared "alg"; a failure in that path is
// never retried through another one. A derived key whose length does not match
// the declared "enc" is rejected ([FailureContentKeySize]), as is a derived
// key that disagrees with the other recipients' keys ([FailureCEKMismatch]).
//
// Work is bounded: the number of recipients by [MaxRecipients], the number of
// candidate keys by [MaxKeyCandidates] (and [EnvelopeOptions.MaxCandidates]),
// and the total PBES2 iterations by [MaxEnvelopePBES2Iterations] (and
// [EnvelopeOptions.MaxPBES2Iterations]).
//
// The returned result is always non-nil. The returned error equals
// result.Err, which is nil when at least one recipient was decrypted and
// otherwise wraps [ErrAllRecipientsFailed].
func (obj JSONWebEncryption) DecryptEnvelope(candidates []KeyCandidate, opts *EnvelopeOptions) (*EnvelopeResult, error) {
	result := &EnvelopeResult{}
	fail := func(err error) (*EnvelopeResult, error) {
		result.Err = err
		return result, err
	}

	if len(obj.recipients) == 0 {
		return fail(errors.New("go-jose/go-jose: no recipients"))
	}
	if len(obj.recipients) > MaxRecipients {
		return fail(fmt.Errorf("go-jose/go-jose: too many recipients in JWE; maximum is %d", MaxRecipients))
	}

	var o EnvelopeOptions
	if opts != nil {
		o = *opts
	}
	maxAttempts := MaxKeyCandidates
	if maxAttempts < 0 {
		maxAttempts = 0
	}
	if o.MaxCandidates > 0 && o.MaxCandidates < maxAttempts {
		maxAttempts = o.MaxCandidates
	}
	pbes2Budget := MaxEnvelopePBES2Iterations
	if pbes2Budget < 0 {
		pbes2Budget = 0
	}
	if o.MaxPBES2Iterations > 0 && o.MaxPBES2Iterations < pbes2Budget {
		pbes2Budget = o.MaxPBES2Iterations
	}

	globalHeaders := obj.mergedHeaders(nil)
	if err := globalHeaders.checkNoCritical(); err != nil {
		return fail(err)
	}
	messageEnc := obj.envelopeEncryption(globalHeaders)
	cipher := getContentCipher(messageEnc)
	if cipher == nil {
		return fail(fmt.Errorf("go-jose/go-jose: unsupported enc value '%s'", string(messageEnc)))
	}
	authData, err := obj.computeAuthData()
	if err != nil {
		return fail(err)
	}
	parts := &aeadParts{
		iv:         obj.iv,
		ciphertext: obj.ciphertext,
		tag:        obj.tag,
	}
	generator := randomKeyGenerator{
		size: cipher.keySize(),
	}

	resolved, err := resolveCandidates(candidates)
	if err != nil {
		return fail(err)
	}
	result.Recipients = make([]RecipientOutcome, len(obj.recipients))
	for i := range obj.recipients {
		result.Recipients[i].Index = i
		result.Recipients[i].UsedKeyIndex = -1
		result.Recipients[i].UsedKeyPosition = -1
	}

	// No candidate keys at all: state that conclusion per recipient instead
	// of reporting a generic authentication failure.
	if len(resolved) == 0 {
		for i := range obj.recipients {
			ro := &result.Recipients[i]
			merged := obj.mergedHeaders(&obj.recipients[i])
			ro.KeyID = merged.getString(headerKeyID)
			ro.Algorithm = merged.getAlgorithm()
			ro.Failure = &EnvelopeFailure{
				Kind:   FailureNoKeys,
				Err:    ErrNoKeyCandidates,
				Detail: "no candidate keys were supplied",
			}
		}
		return fail(fmt.Errorf("%w: %w", ErrAllRecipientsFailed, ErrNoKeyCandidates))
	}

	usable := 0
	for i := range resolved {
		if resolved[i].err == nil {
			usable++
		}
	}
	if usable == 0 {
		for i := range obj.recipients {
			ro := &result.Recipients[i]
			merged := obj.mergedHeaders(&obj.recipients[i])
			ro.KeyID = merged.getString(headerKeyID)
			ro.Algorithm = merged.getAlgorithm()
			ro.Failure = &EnvelopeFailure{
				Kind:   FailureNoUsableKeys,
				Err:    ErrNoUsableKeyCandidates,
				Detail: "none of the candidate keys could be used for decryption",
			}
		}
		return fail(fmt.Errorf("%w: %w", ErrAllRecipientsFailed, ErrNoUsableKeyCandidates))
	}

	for i := range obj.recipients {
		attemptRecipient(&obj, &result.Recipients[i], resolved, messageEnc, cipher, parts, authData, generator, maxAttempts, &pbes2Budget)
	}

	// Every recipient that derived a content encryption key must agree on it.
	// A disagreement means the message is inconsistent, so it is rejected as a
	// whole rather than returning whichever recipient happened to succeed.
	if enforceCEKAgreement(result.Recipients) {
		return fail(fmt.Errorf("%w: %w", ErrAllRecipientsFailed, ErrContentKeyMismatch))
	}

	var successes []*RecipientOutcome
	for i := range result.Recipients {
		if result.Recipients[i].OK {
			successes = append(successes, &result.Recipients[i])
		}
	}
	if len(successes) == 0 {
		return fail(envelopeTotalFailure(result.Recipients))
	}

	plaintext, err := obj.decompress(successes[0].Plaintext)
	if err != nil {
		// Keep the key-stage conclusion and localize the failure to the
		// decompression stage.
		for _, ro := range successes {
			ro.OK = false
			ro.Plaintext = nil
			ro.Failure = &EnvelopeFailure{
				Kind:   FailureDecompress,
				Err:    err,
				Detail: err.Error(),
			}
		}
		// The failure is localized to decompression; the error is returned
		// as-is rather than as a total recipient failure, because the key
		// stage succeeded for these recipients.
		return fail(err)
	}

	result.Plaintext = plaintext
	for _, ro := range successes {
		ro.Plaintext = bytes.Clone(plaintext)
		result.Plaintexts = append(result.Plaintexts, ro.Plaintext)
		result.KeyIDs = append(result.KeyIDs, ro.UsedKeyID)
	}
	return result, nil
}

// envelopeEncryption picks the content encryption algorithm for the message.
// It normally comes from the protected header; if it appears only in the
// unprotected or per-recipient headers, the first recipient's merged value is
// used, since every recipient must declare the same "enc".
func (obj JSONWebEncryption) envelopeEncryption(global rawHeader) ContentEncryption {
	if enc := global.getEncryption(); enc != "" {
		return enc
	}
	if len(obj.recipients) > 0 {
		merged := obj.mergedHeaders(&obj.recipients[0])
		return merged.getEncryption()
	}
	return ""
}

// attemptRecipient tries every eligible candidate against one recipient and
// fills in its outcome.
func attemptRecipient(
	obj *JSONWebEncryption,
	ro *RecipientOutcome,
	resolved []resolvedCandidate,
	messageEnc ContentEncryption,
	cipher contentCipher,
	parts *aeadParts,
	authData []byte,
	generator keyGenerator,
	maxAttempts int,
	pbes2Budget *int,
) {
	recipient := &obj.recipients[ro.Index]
	merged := obj.mergedHeaders(recipient)
	ro.KeyID = merged.getString(headerKeyID)
	ro.Algorithm = merged.getAlgorithm()
	ro.UsedKeyIndex = -1
	ro.UsedKeyPosition = -1

	if ro.Algorithm == "" {
		ro.Failure = &EnvelopeFailure{
			Kind:   FailureKeyAlgorithm,
			Err:    ErrUnsupportedAlgorithm,
			Detail: "recipient has no key management algorithm",
		}
		return
	}
	if enc := merged.getEncryption(); enc != "" && enc != messageEnc {
		ro.Failure = &EnvelopeFailure{
			Kind:   FailureKeyAlgorithm,
			Err:    ErrUnsupportedAlgorithm,
			Detail: fmt.Sprintf("recipient declares enc %q but the message uses %q", enc, messageEnc),
		}
		return
	}

	// Select candidates by key ID using the recipient's own merged headers, so
	// a kid present only in the per-recipient header is honored. A recipient
	// or candidate with no key ID is unlabelled and matches anything. Every
	// candidate with a matching ID is kept: two keys sharing one identifier are
	// both tried.
	var eligible []*resolvedCandidate
	for i := range resolved {
		c := &resolved[i]
		if ro.KeyID != "" && c.keyID != "" && c.keyID != ro.KeyID {
			continue
		}
		eligible = append(eligible, c)
	}
	if len(eligible) == 0 {
		ro.Failure = &EnvelopeFailure{
			Kind:   FailureNoMatchingKey,
			Err:    ErrNoMatchingKeyCandidate,
			Detail: fmt.Sprintf("no candidate key has key ID %q", ro.KeyID),
		}
		return
	}
	if len(eligible) > maxAttempts {
		eligible = eligible[:maxAttempts]
	}

	for _, c := range eligible {
		if c.err != nil {
			ro.Attempts = append(ro.Attempts, CandidateAttempt{
				KeyIndex:    c.keyIndex,
				KeyPosition: c.keyPosition,
				KeyID:       c.keyID,
				Failure: &EnvelopeFailure{
					Kind:   FailureNoUsableKeys,
					Err:    c.err,
					Detail: c.err.Error(),
				},
			})
			continue
		}

		cek, plaintext, failure := attemptCandidate(ro.Algorithm, c, merged, recipient, cipher, parts, authData, generator, pbes2Budget)
		attempt := CandidateAttempt{KeyIndex: c.keyIndex, KeyPosition: c.keyPosition, KeyID: c.keyID}
		if failure != nil {
			attempt.Failure = failure
			ro.Attempts = append(ro.Attempts, attempt)
			// A CEK was derived; keep it so cross-recipient agreement is
			// checked against keys that were actually derived, even if this
			// recipient's content did not authenticate.
			if cek != nil {
				ro.cek = cek
			}
			continue
		}
		ro.Attempts = append(ro.Attempts, attempt)
		ro.KeyUnwrapped = true
		ro.OK = true
		ro.Plaintext = plaintext
		ro.UsedKeyID = c.keyID
		ro.UsedKeyIndex = c.keyIndex
		ro.UsedKeyPosition = c.keyPosition
		ro.cek = cek
		return
	}

	if f := summarizeAttempts(ro.Attempts); f != nil {
		ro.Failure = f
		// A content authentication failure means the key stage did succeed:
		// the key matched and a correctly sized CEK was obtained. A key size
		// mismatch likewise means a CEK was derived, just with the wrong
		// length.
		ro.KeyUnwrapped = f.Kind == FailureContentDecrypt || f.Kind == FailureContentKeySize
		return
	}
	// Every eligible candidate was unusable.
	ro.Failure = &EnvelopeFailure{
		Kind:   FailureNoUsableKeys,
		Err:    ErrNoUsableKeyCandidates,
		Detail: "none of the candidate keys for this recipient could be used",
	}
}

// attemptCandidate performs the key management and content decryption stages
// for one candidate/recipient pair. A nil failure means success, in which case
// the returned CEK was accepted and the content authenticated.
func attemptCandidate(
	alg KeyAlgorithm,
	c *resolvedCandidate,
	merged rawHeader,
	recipient *recipientInfo,
	cipher contentCipher,
	parts *aeadParts,
	authData []byte,
	generator keyGenerator,
	pbes2Budget *int,
) (cek, plaintext []byte, failure *EnvelopeFailure) {
	// An explicit key wrapping algorithm declares a strength; the supplied key
	// material must have exactly that strength.
	if expected, ok := keyWrapKeySizeBits(alg); ok && c.symmetricIn >= 0 && c.symmetricIn != expected {
		return nil, nil, &EnvelopeFailure{
			Kind:     FailureWrongKeySize,
			Err:      ErrKeyStrengthMismatch,
			Detail:   fmt.Sprintf("algorithm %s declares %d-bit key wrap, candidate supplied %d bits", alg, expected, c.symmetricIn),
			Expected: expected,
			Actual:   c.symmetricIn,
		}
	}

	// Validate and account for password-based derivation before running it.
	if isPBES2(alg) {
		if f := checkPBES2(merged, pbes2Budget); f != nil {
			return nil, nil, f
		}
	}

	cek, err := c.decrypter.decryptKey(merged, recipient, generator)
	if err != nil {
		// PBES2 derivation failures carry their own sentinel; a derivation
		// that fails inside the declared path is never retried on another
		// path.
		if isPBES2(alg) && errors.Is(err, ErrPBES2Derivation) {
			return nil, nil, &EnvelopeFailure{
				Kind:   FailurePBES2Derive,
				Err:    err,
				Detail: err.Error(),
			}
		}
		return nil, nil, classifyKeyFailure(err)
	}

	if len(cek) != cipher.keySize() {
		return nil, nil, &EnvelopeFailure{
			Kind:     FailureContentKeySize,
			Err:      ErrContentKeySizeMismatch,
			Detail:   fmt.Sprintf("algorithm %s requires a %d-bit content key, got %d bits", merged.getEncryption(), cipher.keySize()*8, len(cek)*8),
			Expected: cipher.keySize() * 8,
			Actual:   len(cek) * 8,
		}
	}

	plaintext, err = cipher.decrypt(cek, authData, parts)
	if err != nil {
		// The key matched the recipient and unwrapped to a correctly sized
		// CEK, but the content did not authenticate. This is a different
		// condition from a key that does not fit the recipient.
		return cek, nil, &EnvelopeFailure{
			Kind:   FailureContentDecrypt,
			Err:    ErrCryptoFailure,
			Detail: "content encryption key was accepted but content authentication failed; ciphertext, IV, tag, or AAD was modified (a wrong RSA1_5 key also lands here)",
		}
	}
	return cek, plaintext, nil
}

// enforceCEKAgreement verifies that every recipient that derived a content
// encryption key derived the same one. If more than one distinct key was
// derived, the message is internally inconsistent and cannot be trusted, so
// every recipient that produced a key is rejected with [FailureCEKMismatch] and
// the function reports true. Recipients that failed before the key stage keep
// their own reasons.
func enforceCEKAgreement(outcomes []RecipientOutcome) (mismatched bool) {
	var distinct [][]byte
	for i := range outcomes {
		cek := outcomes[i].cek
		if cek == nil {
			continue
		}
		seen := false
		for _, d := range distinct {
			if bytes.Equal(d, cek) {
				seen = true
				break
			}
		}
		if !seen {
			distinct = append(distinct, cek)
		}
	}
	if len(distinct) <= 1 {
		return false
	}
	for i := range outcomes {
		ro := &outcomes[i]
		if ro.cek == nil {
			continue
		}
		ro.OK = false
		ro.Plaintext = nil
		ro.Failure = &EnvelopeFailure{
			Kind:   FailureCEKMismatch,
			Err:    ErrContentKeyMismatch,
			Detail: "derived content encryption key differs from the other recipients; message rejected",
		}
	}
	return true
}

// checkPBES2 validates the password-based derivation parameters and charges
// the derivation budget. It returns nil when the derivation may proceed.
func checkPBES2(merged rawHeader, budget *int) *EnvelopeFailure {
	p2s, err := merged.getP2S()
	if err != nil {
		return &EnvelopeFailure{
			Kind:   FailurePBES2Salt,
			Err:    fmt.Errorf("%w: %v", ErrMissingPBES2Salt, err),
			Detail: "invalid salt header",
		}
	}
	if p2s == nil || len(p2s.bytes()) == 0 {
		return &EnvelopeFailure{
			Kind:   FailurePBES2Salt,
			Err:    ErrMissingPBES2Salt,
			Detail: "salt header is missing or empty",
		}
	}

	p2c, err := merged.getP2C()
	if err != nil {
		return &EnvelopeFailure{
			Kind:   FailurePBES2Iterations,
			Err:    fmt.Errorf("%w: %v", ErrInvalidPBES2Iterations, err),
			Detail: "invalid iteration count header",
		}
	}
	if p2c <= 0 {
		return &EnvelopeFailure{
			Kind:   FailurePBES2Iterations,
			Err:    ErrInvalidPBES2Iterations,
			Detail: "iteration count must be a positive integer",
		}
	}
	if p2c > maxPBES2Iterations {
		return &EnvelopeFailure{
			Kind:   FailurePBES2Iterations,
			Err:    ErrInvalidPBES2Iterations,
			Detail: fmt.Sprintf("iteration count %d exceeds the per-message maximum of %d", p2c, maxPBES2Iterations),
		}
	}
	if p2c > *budget {
		return &EnvelopeFailure{
			Kind:   FailurePBES2Iterations,
			Err:    ErrInvalidPBES2Iterations,
			Detail: fmt.Sprintf("iteration count %d would exceed the remaining derivation budget of %d", p2c, *budget),
		}
	}
	*budget -= p2c
	return nil
}

// classifyKeyFailure maps a key management error onto a failure category. The
// recipient's declared algorithm selected this path; a failure here is never
// retried through another derivation path.
func classifyKeyFailure(err error) *EnvelopeFailure {
	kind := FailureKeyUnwrap
	switch {
	case errors.Is(err, ErrInvalidPBES2Iterations):
		kind = FailurePBES2Iterations
	case errors.Is(err, ErrMissingPBES2Salt):
		kind = FailurePBES2Salt
	case errors.Is(err, ErrPBES2Derivation):
		kind = FailurePBES2Derive
	case errors.Is(err, ErrUnsupportedAlgorithm):
		kind = FailureKeyAlgorithm
	case errors.Is(err, ErrKeyStrengthMismatch):
		kind = FailureWrongKeySize
	}
	return &EnvelopeFailure{
		Kind:   kind,
		Err:    err,
		Detail: err.Error(),
	}
}

// summarizeAttempts picks the most informative failure from a recipient's
// attempts. Results are derived from the attempt records themselves, not from
// error strings.
func summarizeAttempts(attempts []CandidateAttempt) *EnvelopeFailure {
	best := -1
	bestRank := -1
	for i, a := range attempts {
		if a.Failure == nil {
			continue
		}
		rank := failureRank(a.Failure.Kind)
		if rank > bestRank {
			best = i
			bestRank = rank
		}
	}
	if best < 0 {
		return nil
	}
	return attempts[best].Failure
}

func failureRank(k FailureKind) int {
	switch k {
	case FailureContentDecrypt:
		return 100
	case FailureCEKMismatch:
		return 95
	case FailureContentKeySize:
		return 90
	case FailureDecompress:
		return 85
	case FailurePBES2Iterations, FailurePBES2Salt, FailurePBES2Derive:
		return 80
	case FailureWrongKeySize:
		return 70
	case FailureKeyAlgorithm:
		return 60
	case FailureNoMatchingKey:
		return 50
	case FailureKeyUnwrap:
		return 40
	case FailureNoUsableKeys:
		return 30
	default:
		return 10
	}
}

// envelopeTotalFailure builds the overall error once every recipient failed.
func envelopeTotalFailure(outcomes []RecipientOutcome) error {
	allNoKeys, allUnusable := len(outcomes) > 0, len(outcomes) > 0
	for _, ro := range outcomes {
		if ro.Failure == nil || ro.Failure.Kind != FailureNoKeys {
			allNoKeys = false
		}
		if ro.Failure == nil || ro.Failure.Kind != FailureNoUsableKeys {
			allUnusable = false
		}
	}
	switch {
	case allNoKeys:
		return fmt.Errorf("%w: %w", ErrAllRecipientsFailed, ErrNoKeyCandidates)
	case allUnusable:
		return fmt.Errorf("%w: %w", ErrAllRecipientsFailed, ErrNoUsableKeyCandidates)
	default:
		return fmt.Errorf("%w: %d recipients", ErrAllRecipientsFailed, len(outcomes))
	}
}

// resolveCandidates builds decrypters for all candidates up front, recording
// the ones that cannot be used rather than failing the whole call. Key sets are
// expanded, and the total is bounded by [MaxKeyCandidates].
func resolveCandidates(candidates []KeyCandidate) ([]resolvedCandidate, error) {
	maxCandidates := MaxKeyCandidates
	if maxCandidates < 0 {
		maxCandidates = 0
	}
	out := make([]resolvedCandidate, 0, len(candidates))
	add := func(index int, keyID string, key any) error {
		if len(out) >= maxCandidates {
			return fmt.Errorf("%w: key sets expand beyond the maximum of %d", ErrTooManyKeyCandidates, maxCandidates)
		}
		dec, err := newDecrypter(key)
		bits := -1
		if n, ok := symmetricKeyBits(key); ok {
			bits = n
		}
		out = append(out, resolvedCandidate{
			keyIndex:    index,
			keyPosition: len(out),
			keyID:       keyID,
			decrypter:   dec,
			err:         err,
			symmetricIn: bits,
		})
		return nil
	}

	totalSupplied := 0
	for i, c := range candidates {
		switch jwks := c.Key.(type) {
		case JSONWebKeySet:
			totalSupplied += len(jwks.Keys)
			for _, k := range jwks.Keys {
				if err := add(i, k.KeyID, k); err != nil {
					return nil, err
				}
			}
			continue
		case *JSONWebKeySet:
			if jwks == nil {
				totalSupplied++
				_ = add(i, "", nil)
				continue
			}
			totalSupplied += len(jwks.Keys)
			for _, k := range jwks.Keys {
				if err := add(i, k.KeyID, k); err != nil {
					return nil, err
				}
			}
			continue
		}
		totalSupplied++
		keyID := c.KeyID
		if keyID == "" {
			switch jwk := c.Key.(type) {
			case JSONWebKey:
				keyID = jwk.KeyID
			case *JSONWebKey:
				if jwk != nil {
					keyID = jwk.KeyID
				}
			}
		}
		if err := add(i, keyID, c.Key); err != nil {
			return nil, err
		}
	}
	if totalSupplied > maxCandidates {
		return nil, fmt.Errorf("%w: %d supplied, maximum is %d", ErrTooManyKeyCandidates, totalSupplied, maxCandidates)
	}
	return out, nil
}

// keyWrapKeySizeBits returns the key-encryption-key strength in bits declared
// by an explicit symmetric key wrapping algorithm.
func keyWrapKeySizeBits(alg KeyAlgorithm) (int, bool) {
	switch alg {
	case A128KW, A128GCMKW:
		return 128, true
	case A192KW, A192GCMKW:
		return 192, true
	case A256KW, A256GCMKW:
		return 256, true
	default:
		return 0, false
	}
}

// symmetricKeyBits returns the size in bits of a symmetric key, if the key
// value is one.
func symmetricKeyBits(key any) (int, bool) {
	switch k := key.(type) {
	case []byte:
		return len(k) * 8, true
	case string:
		return len(k) * 8, true
	case JSONWebKey:
		return symmetricKeyBits(k.Key)
	case *JSONWebKey:
		if k != nil {
			return symmetricKeyBits(k.Key)
		}
	}
	return 0, false
}

func isPBES2(alg KeyAlgorithm) bool {
	switch alg {
	case PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW:
		return true
	default:
		return false
	}
}
