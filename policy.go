/*-
 * Copyright 2026 go-jose Authors
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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
)

// Hardened JWE policy layer.
//
// The policy-based entry points in this file enforce, in addition to the
// parsing checks performed by the legacy ParseEncrypted* entry points:
//
//   - allow lists constrain both the key management ("alg") and the content
//     encryption ("enc") algorithms, and each must be present in the
//     integrity-protected header;
//   - declarations that appear only in unprotected (non-integrity-protected)
//     header positions can never authorize a message;
//   - unauthenticated encryption (no integrity tag) is rejected;
//   - the strength claimed by a key management algorithm is checked against
//     the actual key length;
//   - keys marked for signature use are rejected for key management;
//   - algorithm/key type mismatches are reported in their own category;
//   - algorithms below the configured minimum strength floors are rejected
//     even when listed in the allow set;
//   - certificate chains carried in "x5c" headers are validated against the
//     key class required by the declared cipher suite.
//
// Every failure is reported through a typed sentinel error (see the Err*
// declarations below). Rejection messages contain algorithm names and key
// lengths only; they never contain key material, plaintext fragments or
// plaintext digests.

// Minimum strength floors applied by [JWEPolicy] unless overridden.
const (
	// MinimumKeyLengthBits is the minimum acceptable key length, in bits.
	MinimumKeyLengthBits = 128
	// MinimumDigestLengthBits is the minimum acceptable digest length, in bits.
	MinimumDigestLengthBits = 256
)

// Hardened-policy error categories. These are distinct from one another and
// from the legacy errors (ErrCryptoFailure, ErrUnsupportedKeyType, ...) so
// that callers can branch on the reason a message was rejected instead of
// collapsing every failure into a decryption/verification error.
var (
	// ErrInvalidPolicy is returned when an allow set itself is malformed:
	// containing empty/duplicated entries, or containing entries whose
	// casing does not match the registered JOSE name. It is a configuration
	// error and is detected when the policy is constructed, never at runtime.
	ErrInvalidPolicy = errors.New("go-jose/go-jose: invalid algorithm policy")

	// ErrEmptyPolicy is returned when an allow set is empty. An empty allow
	// set is a configuration error and must never be interpreted as
	// "allow everything".
	ErrEmptyPolicy = errors.New("go-jose/go-jose: empty algorithm policy")

	// ErrUnprotectedAlgorithm is returned when the "alg" or "enc" parameter
	// that authorizes a message is declared in an unprotected (not
	// integrity-protected) header position, or when a parameter required in
	// the protected header is missing from it.
	ErrUnprotectedAlgorithm = errors.New("go-jose/go-jose: algorithm declared outside the integrity-protected header")

	// ErrUnknownAlgorithm is returned when an algorithm name is not
	// recognized. It is deliberately separate from key errors: an
	// unrecognized name is not a key problem.
	ErrUnknownAlgorithm = errors.New("go-jose/go-jose: unknown algorithm")

	// ErrAlgorithmNotAllowed is returned when a recognized, sufficiently
	// strong algorithm is not a member of the configured allow set.
	ErrAlgorithmNotAllowed = errors.New("go-jose/go-jose: algorithm not permitted by policy")

	// ErrWeakAlgorithm is returned when an algorithm falls below the
	// configured key/digest length floors, or is deprecated, even though it
	// appears in the allow set.
	ErrWeakAlgorithm = errors.New("go-jose/go-jose: weak or deprecated algorithm")

	// ErrUnauthenticatedEncryption is returned when the message does not
	// carry an integrity protection tag, i.e. an unauthenticated encryption
	// mode. Being able to recover plaintext is never sufficient to pass.
	ErrUnauthenticatedEncryption = errors.New("go-jose/go-jose: encryption mode has no integrity tag")

	// ErrKeyStrengthMismatch is returned when the strength claimed by the
	// key management algorithm does not match the length of the supplied key.
	ErrKeyStrengthMismatch = errors.New("go-jose/go-jose: key length does not match declared algorithm strength")

	// ErrKeyUseConflict is returned when the same key is marked for
	// signature use but is presented for key management (or vice versa).
	ErrKeyUseConflict = errors.New("go-jose/go-jose: key use conflicts with its declared purpose")

	// ErrKeyTypeMismatch is returned when the algorithm/key pairing is
	// wrong at the class level, e.g. an asymmetric key paired with a
	// symmetric algorithm or a symmetric key paired with an asymmetric one.
	// It is distinct from key material errors.
	ErrKeyTypeMismatch = errors.New("go-jose/go-jose: key type does not match algorithm")

	// ErrCertificateChain is returned for failures parsing or validating an
	// x5c certificate chain. It is separate from algorithm policy failures.
	ErrCertificateChain = errors.New("go-jose/go-jose: invalid certificate chain")

	// ErrUnsupportedMultiRecipient is returned by the hardened entry points
	// for multi-recipient messages, whose per-recipient headers cannot all
	// be integrity protected in a single authorization decision.
	ErrUnsupportedMultiRecipient = errors.New("go-jose/go-jose: multi-recipient JWE not supported by policy")
)

// JWEPolicy is a validated, immutable allow list for JWE processing.
//
// Construct one with [NewJWEPolicy]. A zero-value or nil policy rejects
// everything: an empty allow set is a configuration error, never an implicit
// "allow all".
type JWEPolicy struct {
	keyAlgs     map[KeyAlgorithm]struct{}
	contentAlgs map[ContentEncryption]struct{}
	minKeyBits  int
	minHashBits int
}

// NewJWEPolicy constructs a [JWEPolicy] from the given allow lists.
//
// Both lists must be non-empty. Empty entries, duplicate entries and entries
// whose casing does not match the registered JOSE algorithm name are rejected
// at construction time (wrapping [ErrInvalidPolicy] or [ErrEmptyPolicy]), so
// that an invalid configuration can never run.
//
// Recognized algorithms below [MinimumKeyLengthBits]/[MinimumDigestLengthBits],
// or deprecated algorithms (e.g. RSA1_5), are still rejected at message
// processing time even when included in the allow list.
func NewJWEPolicy(keyAlgorithms []KeyAlgorithm, contentEncryption []ContentEncryption) (*JWEPolicy, error) {
	if len(keyAlgorithms) == 0 || len(contentEncryption) == 0 {
		return nil, ErrEmptyPolicy
	}

	policy := &JWEPolicy{
		keyAlgs:     make(map[KeyAlgorithm]struct{}, len(keyAlgorithms)),
		contentAlgs: make(map[ContentEncryption]struct{}, len(contentEncryption)),
		minKeyBits:  MinimumKeyLengthBits,
		minHashBits: MinimumDigestLengthBits,
	}

	for _, alg := range keyAlgorithms {
		if alg == "" {
			return nil, fmt.Errorf("%w: empty key algorithm entry", ErrInvalidPolicy)
		}
		canonical, ok := canonicalKeyAlgorithm(alg)
		if !ok {
			return nil, fmt.Errorf("%w: unregistered key algorithm %q", ErrInvalidPolicy, alg)
		}
		if canonical != alg {
			return nil, fmt.Errorf("%w: key algorithm %q must be written as %q", ErrInvalidPolicy, alg, canonical)
		}
		if _, dup := policy.keyAlgs[alg]; dup {
			return nil, fmt.Errorf("%w: duplicate key algorithm %q", ErrInvalidPolicy, alg)
		}
		policy.keyAlgs[alg] = struct{}{}
	}

	for _, enc := range contentEncryption {
		if enc == "" {
			return nil, fmt.Errorf("%w: empty content encryption entry", ErrInvalidPolicy)
		}
		canonical, ok := canonicalContentEncryption(enc)
		if !ok {
			return nil, fmt.Errorf("%w: unregistered content encryption algorithm %q", ErrInvalidPolicy, enc)
		}
		if canonical != enc {
			return nil, fmt.Errorf("%w: content encryption algorithm %q must be written as %q", ErrInvalidPolicy, enc, canonical)
		}
		if _, dup := policy.contentAlgs[enc]; dup {
			return nil, fmt.Errorf("%w: duplicate content encryption algorithm %q", ErrInvalidPolicy, enc)
		}
		policy.contentAlgs[enc] = struct{}{}
	}

	return policy, nil
}

// normalizedName strips the separators allowed in JOSE algorithm names and
// lower-cases the result, yielding a casing/separator-insensitive key for
// the registered-name lookup used to detect casing inconsistencies at load
// time.
func normalizedName(name string) string {
	return strings.ToLower(strings.NewReplacer("-", "", "_", "", "+", "", " ", "").Replace(name))
}

// keyClass identifies the family of key an algorithm requires.
type keyClass int

const (
	classSymmetric keyClass = iota
	classRSA
	classEC
)

// keyAlgorithmInfo describes the security properties of a registered key
// management algorithm.
type keyAlgorithmInfo struct {
	canonical     KeyAlgorithm
	class         keyClass
	minDigestBits int // digest length required by the algorithm, 0 if none
	minKeyBits    int // minimum key length required by the algorithm, 0 if N/A
	deprecated    bool
	symmetricBits int // required key length in bits for symmetric key management, 0 if N/A
}

// registeredKeyAlgorithms is the registry of key management algorithms
// understood by this library, keyed by [normalizedName], together with their
// strength metadata.
var registeredKeyAlgorithms = map[string]keyAlgorithmInfo{
	normalizedName(string(RSA1_5)):             {canonical: RSA1_5, class: classRSA, minKeyBits: 2048, deprecated: true},
	normalizedName(string(RSA_OAEP)):           {canonical: RSA_OAEP, class: classRSA, minDigestBits: 160, minKeyBits: 2048},
	normalizedName(string(RSA_OAEP_256)):       {canonical: RSA_OAEP_256, class: classRSA, minDigestBits: 256, minKeyBits: 2048},
	normalizedName(string(A128KW)):             {canonical: A128KW, class: classSymmetric, minKeyBits: 128, symmetricBits: 128},
	normalizedName(string(A192KW)):             {canonical: A192KW, class: classSymmetric, minKeyBits: 192, symmetricBits: 192},
	normalizedName(string(A256KW)):             {canonical: A256KW, class: classSymmetric, minKeyBits: 256, symmetricBits: 256},
	normalizedName(string(DIRECT)):             {canonical: DIRECT, class: classSymmetric, minKeyBits: 128},
	normalizedName(string(ECDH_ES)):            {canonical: ECDH_ES, class: classEC, minKeyBits: 128},
	normalizedName(string(ECDH_ES_A128KW)):     {canonical: ECDH_ES_A128KW, class: classEC, minKeyBits: 128},
	normalizedName(string(ECDH_ES_A192KW)):     {canonical: ECDH_ES_A192KW, class: classEC, minKeyBits: 192},
	normalizedName(string(ECDH_ES_A256KW)):     {canonical: ECDH_ES_A256KW, class: classEC, minKeyBits: 256},
	normalizedName(string(A128GCMKW)):          {canonical: A128GCMKW, class: classSymmetric, minKeyBits: 128, symmetricBits: 128},
	normalizedName(string(A192GCMKW)):          {canonical: A192GCMKW, class: classSymmetric, minKeyBits: 192, symmetricBits: 192},
	normalizedName(string(A256GCMKW)):          {canonical: A256GCMKW, class: classSymmetric, minKeyBits: 256, symmetricBits: 256},
	normalizedName(string(PBES2_HS256_A128KW)): {canonical: PBES2_HS256_A128KW, class: classSymmetric, minDigestBits: 256, minKeyBits: 128, symmetricBits: 128},
	normalizedName(string(PBES2_HS384_A192KW)): {canonical: PBES2_HS384_A192KW, class: classSymmetric, minDigestBits: 384, minKeyBits: 192, symmetricBits: 192},
	normalizedName(string(PBES2_HS512_A256KW)): {canonical: PBES2_HS512_A256KW, class: classSymmetric, minDigestBits: 512, minKeyBits: 256, symmetricBits: 256},
}

// contentEncryptionInfo describes the security properties of a registered
// content encryption algorithm.
type contentEncryptionInfo struct {
	canonical  ContentEncryption
	minKeyBits int
	tagBytes   int
}

// registeredContentEncryption is the registry of content encryption
// algorithms understood by this library, keyed by [normalizedName]. Every
// registered algorithm is an authenticated AEAD/AEAD-like construction;
// unauthenticated modes are not registered and therefore cannot pass.
var registeredContentEncryption = map[string]contentEncryptionInfo{
	normalizedName(string(A128GCM)):       {canonical: A128GCM, minKeyBits: 128, tagBytes: 16},
	normalizedName(string(A192GCM)):       {canonical: A192GCM, minKeyBits: 192, tagBytes: 16},
	normalizedName(string(A256GCM)):       {canonical: A256GCM, minKeyBits: 256, tagBytes: 16},
	normalizedName(string(A128CBC_HS256)): {canonical: A128CBC_HS256, minKeyBits: 128, tagBytes: 16},
	normalizedName(string(A192CBC_HS384)): {canonical: A192CBC_HS384, minKeyBits: 192, tagBytes: 24},
	normalizedName(string(A256CBC_HS512)): {canonical: A256CBC_HS512, minKeyBits: 256, tagBytes: 32},
}

// canonicalKeyAlgorithm returns the registered name for alg using a
// casing/separator-insensitive comparison. The boolean reports whether any
// registered algorithm matches.
func canonicalKeyAlgorithm(alg KeyAlgorithm) (KeyAlgorithm, bool) {
	info, ok := registeredKeyAlgorithms[normalizedName(string(alg))]
	if !ok {
		return "", false
	}
	return info.canonical, true
}

// canonicalContentEncryption returns the registered name for enc using a
// casing/separator-insensitive comparison. The boolean reports whether any
// registered algorithm matches.
func canonicalContentEncryption(enc ContentEncryption) (ContentEncryption, bool) {
	info, ok := registeredContentEncryption[normalizedName(string(enc))]
	if !ok {
		return "", false
	}
	return info.canonical, true
}

// validateAgainstPolicy applies every message-level policy check to a parsed
// JWE. It is shared by the compact and JSON entry points so that both
// serializations reach identical decisions for the same logical message.
func (policy *JWEPolicy) validateAgainstPolicy(obj *JSONWebEncryption) error {
	if policy == nil || len(policy.keyAlgs) == 0 || len(policy.contentAlgs) == 0 {
		return ErrEmptyPolicy
	}

	if len(obj.recipients) > 1 {
		return ErrUnsupportedMultiRecipient
	}

	// RFC 7516: "enc" and (single-recipient) "alg" are integrity-protected
	// header parameters. Any occurrence in an unprotected position is
	// rejected outright: unprotected declarations can neither authorize the
	// message nor override a protected value.
	if obj.unprotected != nil {
		if value, present := (*obj.unprotected)[headerEncryption]; present && value != nil {
			return fmt.Errorf("%w: %q must not appear in an unprotected header", ErrUnprotectedAlgorithm, headerEncryption)
		}
		if value, present := (*obj.unprotected)[headerAlgorithm]; present && value != nil {
			return fmt.Errorf("%w: %q must not appear in an unprotected header", ErrUnprotectedAlgorithm, headerAlgorithm)
		}
	}
	if len(obj.recipients) == 1 && obj.recipients[0].header != nil {
		perRecipient := obj.recipients[0].header
		if value, present := (*perRecipient)[headerAlgorithm]; present && value != nil {
			return fmt.Errorf("%w: %q must not appear in an unprotected per-recipient header", ErrUnprotectedAlgorithm, headerAlgorithm)
		}
		if value, present := (*perRecipient)[headerEncryption]; present && value != nil {
			return fmt.Errorf("%w: %q must not appear in an unprotected per-recipient header", ErrUnprotectedAlgorithm, headerEncryption)
		}
	}

	// The authorization decision is taken exclusively on the protected
	// header. Missing, empty or non-string values are reported as
	// unprotected-algorithm failures rather than silently falling back to an
	// unprotected position.
	if obj.protected == nil {
		return fmt.Errorf("%w: message has no integrity-protected header", ErrUnprotectedAlgorithm)
	}

	enc := obj.protected.getEncryption()
	if enc == "" {
		return fmt.Errorf("%w: missing or empty %q in protected header", ErrUnprotectedAlgorithm, headerEncryption)
	}
	alg := obj.protected.getAlgorithm()
	if alg == "" {
		return fmt.Errorf("%w: missing or empty %q in protected header", ErrUnprotectedAlgorithm, headerAlgorithm)
	}

	if err := policy.classifyAlgorithms(alg, enc, obj.tag); err != nil {
		return err
	}
	return nil
}

// preValidateRaw runs the full message-level policy decision directly against
// the raw, unsanitized message, before any legacy parsing error can be
// returned. This guarantees that policy failures are always reported through
// their typed categories instead of being collapsed into generic legacy
// parse errors. The same checks are repeated on the sanitized object by
// [JWEPolicy.validateAgainstPolicy] as defense in depth.
func (policy *JWEPolicy) preValidateRaw(raw *rawJSONWebEncryption) error {
	if policy == nil || len(policy.keyAlgs) == 0 || len(policy.contentAlgs) == 0 {
		return ErrEmptyPolicy
	}

	recipientCount := len(raw.Recipients)
	if recipientCount == 0 {
		recipientCount = 1
	}
	if recipientCount > 1 {
		return ErrUnsupportedMultiRecipient
	}

	// Reject any "alg"/"enc" declaration sitting in a non-integrity-
	// protected position, in every location such a header can occur.
	checkUnprotected := func(header *rawHeader, position string) error {
		if header == nil {
			return nil
		}
		if value, present := (*header)[headerAlgorithm]; present && value != nil {
			return fmt.Errorf("%w: %q must not appear in the %s header", ErrUnprotectedAlgorithm, headerAlgorithm, position)
		}
		if value, present := (*header)[headerEncryption]; present && value != nil {
			return fmt.Errorf("%w: %q must not appear in the %s header", ErrUnprotectedAlgorithm, headerEncryption, position)
		}
		return nil
	}
	if err := checkUnprotected(raw.Unprotected, "unprotected"); err != nil {
		return err
	}
	if err := checkUnprotected(raw.Header, "per-recipient"); err != nil {
		return err
	}
	for i := range raw.Recipients {
		if err := checkUnprotected(raw.Recipients[i].Header, "per-recipient"); err != nil {
			return err
		}
	}

	protected, err := parseProtectedHeader(raw.Protected)
	if err != nil {
		return err
	}
	if protected == nil {
		return fmt.Errorf("%w: message has no integrity-protected header", ErrUnprotectedAlgorithm)
	}
	enc := protected.getEncryption()
	if enc == "" {
		return fmt.Errorf("%w: missing or empty %q in protected header", ErrUnprotectedAlgorithm, headerEncryption)
	}
	alg := protected.getAlgorithm()
	if alg == "" {
		return fmt.Errorf("%w: missing or empty %q in protected header", ErrUnprotectedAlgorithm, headerAlgorithm)
	}

	return policy.classifyAlgorithms(alg, enc, raw.Tag.bytes())
}

// classifyAlgorithms applies the recognition, allow-list, strength-floor and
// integrity-tag checks to the protected algorithm declarations.
func (policy *JWEPolicy) classifyAlgorithms(alg KeyAlgorithm, enc ContentEncryption, tag []byte) error {
	// An unauthenticated mode (empty tag) can never be accepted, regardless
	// of whether plaintext could be recovered.
	if len(tag) == 0 {
		return fmt.Errorf("%w: message has no integrity tag", ErrUnauthenticatedEncryption)
	}

	encInfo, encKnown := registeredContentEncryption[normalizedName(string(enc))]
	if !encKnown {
		return fmt.Errorf("%w: content encryption %q", ErrUnknownAlgorithm, enc)
	}
	if len(tag) < encInfo.tagBytes {
		return fmt.Errorf("%w: integrity tag shorter than the %d bytes required by %q",
			ErrUnauthenticatedEncryption, encInfo.tagBytes, enc)
	}
	if _, allowed := policy.contentAlgs[enc]; !allowed {
		return fmt.Errorf("%w: content encryption %q", ErrAlgorithmNotAllowed, enc)
	}
	if encInfo.minKeyBits < policy.minKeyBits {
		return fmt.Errorf("%w: content encryption %q provides only %d-bit keys",
			ErrWeakAlgorithm, enc, encInfo.minKeyBits)
	}

	algInfo, algKnown := registeredKeyAlgorithms[normalizedName(string(alg))]
	if !algKnown {
		return fmt.Errorf("%w: key management algorithm %q", ErrUnknownAlgorithm, alg)
	}
	if _, allowed := policy.keyAlgs[alg]; !allowed {
		return fmt.Errorf("%w: key management algorithm %q", ErrAlgorithmNotAllowed, alg)
	}
	if algInfo.deprecated {
		return fmt.Errorf("%w: key management algorithm %q is deprecated", ErrWeakAlgorithm, alg)
	}
	if algInfo.minDigestBits != 0 && algInfo.minDigestBits < policy.minHashBits {
		return fmt.Errorf("%w: key management algorithm %q uses a %d-bit digest",
			ErrWeakAlgorithm, alg, algInfo.minDigestBits)
	}
	if algInfo.minKeyBits != 0 && algInfo.minKeyBits < policy.minKeyBits {
		return fmt.Errorf("%w: key management algorithm %q requires only %d-bit keys",
			ErrWeakAlgorithm, alg, algInfo.minKeyBits)
	}
	return nil
}

// allRegisteredKeyAlgorithms returns every registered key management
// algorithm. It is the permissive allow set handed to the shared legacy
// sanitizer on the hardened path, so that allow-list enforcement remains
// exclusively the policy's responsibility.
func allRegisteredKeyAlgorithms() []KeyAlgorithm {
	out := make([]KeyAlgorithm, 0, len(registeredKeyAlgorithms))
	for _, info := range registeredKeyAlgorithms {
		out = append(out, info.canonical)
	}
	return out
}

// allRegisteredContentEncryption returns every registered content encryption
// algorithm. See [allRegisteredKeyAlgorithms].
func allRegisteredContentEncryption() []ContentEncryption {
	out := make([]ContentEncryption, 0, len(registeredContentEncryption))
	for _, info := range registeredContentEncryption {
		out = append(out, info.canonical)
	}
	return out
}

// validateCertificateChains parses every x5c header in the message and checks
// that each chain's key is capable of the declared key management algorithm.
// Chain parse failures wrap [ErrCertificateChain] and are never conflated
// with algorithm policy failures.
func (policy *JWEPolicy) validateCertificateChains(raw rawJSONWebEncryption, alg KeyAlgorithm) error {
	algInfo, ok := registeredKeyAlgorithms[normalizedName(string(alg))]
	if !ok {
		// Unknown algorithms are reported through their own category by the
		// policy check; nothing useful can be derived for the chain here.
		return nil
	}

	var chains [][]string
	collect := func(header *rawHeader) {
		if header == nil {
			return
		}
		value, present := (*header)[headerX5c]
		if !present || value == nil {
			return
		}
		var entries []string
		if err := json.Unmarshal(*value, &entries); err != nil {
			chains = append(chains, nil)
			return
		}
		chains = append(chains, entries)
	}
	collect(raw.Unprotected)
	collect(raw.Header)
	if objProtected, err := parseProtectedHeader(raw.Protected); err == nil {
		collect(objProtected)
	}
	for _, recipient := range raw.Recipients {
		collect(recipient.Header)
	}

	for _, chain := range chains {
		certs, err := parseCertificateChain(chain)
		if err != nil {
			return fmt.Errorf("%w: failed to parse x5c chain: %w", ErrCertificateChain, err)
		}
		for _, cert := range certs {
			if err := checkCertificateKeyClass(cert.PublicKey, algInfo.class, alg); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkCertificateKeyClass verifies that a public key carried in a certificate
// belongs to the key class required by the declared cipher suite.
func checkCertificateKeyClass(publicKey any, expected keyClass, alg KeyAlgorithm) error {
	switch expected {
	case classRSA:
		if _, ok := publicKey.(*rsa.PublicKey); !ok {
			return fmt.Errorf("%w: algorithm %q requires an RSA key but x5c carries %T",
				ErrKeyTypeMismatch, alg, publicKey)
		}
	case classEC:
		if _, ok := publicKey.(*ecdsa.PublicKey); !ok {
			return fmt.Errorf("%w: algorithm %q requires an EC key but x5c carries %T",
				ErrKeyTypeMismatch, alg, publicKey)
		}
	case classSymmetric:
		// Symmetric keys are never distributed through certificate chains.
		return fmt.Errorf("%w: symmetric algorithm %q cannot use an x5c key", ErrKeyTypeMismatch, alg)
	default:
		return fmt.Errorf("%w: unhandled key class for algorithm %q", ErrKeyTypeMismatch, alg)
	}
	return nil
}

// validateDecryptionKey applies the key-level policy checks that can only be
// performed once the decryption key is known: class pairing, claimed strength
// versus actual key length, and signature/key-management use conflicts.
func (policy *JWEPolicy) validateDecryptionKey(alg KeyAlgorithm, enc ContentEncryption, decryptionKey any) error {
	algInfo, ok := registeredKeyAlgorithms[normalizedName(string(alg))]
	if !ok {
		return fmt.Errorf("%w: key management algorithm %q", ErrUnknownAlgorithm, alg)
	}

	// A JWK carries metadata (notably "use"); unwrap it while remembering
	// the metadata, but keep resolving JWKS through the existing path.
	switch key := decryptionKey.(type) {
	case JSONWebKey:
		if isSignatureUse(key.Use) {
			return fmt.Errorf("%w: key %q is marked for signature use", ErrKeyUseConflict, key.KeyID)
		}
		return policy.validateKeyMaterial(alg, enc, algInfo, key.Key)
	case *JSONWebKey:
		if isSignatureUse(key.Use) {
			return fmt.Errorf("%w: key %q is marked for signature use", ErrKeyUseConflict, key.KeyID)
		}
		return policy.validateKeyMaterial(alg, enc, algInfo, key.Key)
	default:
		return policy.validateKeyMaterial(alg, enc, algInfo, decryptionKey)
	}
}

// validateKeyMaterial checks the key class and length against the declared
// algorithm. Opaque decrypters are application-managed and out of scope for
// the library-side pairing checks.
func (policy *JWEPolicy) validateKeyMaterial(alg KeyAlgorithm, enc ContentEncryption, algInfo keyAlgorithmInfo, key any) error {
	if _, ok := key.(OpaqueKeyDecrypter); ok {
		return nil
	}

	switch algInfo.class {
	case classSymmetric:
		raw, ok := key.([]byte)
		if !ok {
			return fmt.Errorf("%w: algorithm %q requires a symmetric key but got %T", ErrKeyTypeMismatch, alg, key)
		}
		// "dir" uses the key directly as the content encryption key, so its
		// required length follows the content encryption algorithm.
		expectedBits := algInfo.symmetricBits
		if alg == DIRECT {
			cipher := getContentCipher(enc)
			if cipher == nil {
				return fmt.Errorf("%w: content encryption %q", ErrUnknownAlgorithm, enc)
			}
			expectedBits = cipher.keySize() * 8
		}
		if expectedBits != 0 && len(raw)*8 != expectedBits {
			return fmt.Errorf("%w: algorithm %q declares %d-bit strength but key is %d bits",
				ErrKeyStrengthMismatch, alg, expectedBits, len(raw)*8)
		}
	case classRSA:
		switch key.(type) {
		case *rsa.PrivateKey, *rsa.PublicKey:
		default:
			return fmt.Errorf("%w: algorithm %q requires an RSA key but got %T", ErrKeyTypeMismatch, alg, key)
		}
	case classEC:
		switch key.(type) {
		case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		default:
			return fmt.Errorf("%w: algorithm %q requires an EC key but got %T", ErrKeyTypeMismatch, alg, key)
		}
	}

	// Ed25519 keys only exist for signatures; pairing one with any key
	// management algorithm is a class-level mismatch.
	switch key.(type) {
	case ed25519.PrivateKey, ed25519.PublicKey:
		return fmt.Errorf("%w: algorithm %q cannot use an Ed25519 key", ErrKeyTypeMismatch, alg)
	}

	return nil
}

// isSignatureUse reports whether a JWK "use" value marks the key for
// signature operations, which forbids its use for key management.
func isSignatureUse(use string) bool {
	return use == "sig"
}
