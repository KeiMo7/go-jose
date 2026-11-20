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
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
)

// Policy-based, hardened JWE entry points.
//
// These functions accept an explicitly constructed [JWEPolicy] instead of
// raw algorithm slices. A nil policy, or one whose allow sets are empty,
// rejects every message. The legacy ParseEncrypted* functions keep their
// historical behavior unchanged.

// ParseEncryptedWithPolicy parses an encrypted JWE message in compact or JSON
// serialization and applies the hardened checks of [JWEPolicy].
//
// The serialization is selected from the input, but both paths run the exact
// same policy validation, so the same logical message always reaches the same
// decision regardless of serialization.
func ParseEncryptedWithPolicy(input string, policy *JWEPolicy) (*JSONWebEncryption, error) {
	if policy == nil {
		return nil, ErrEmptyPolicy
	}
	input = stripWhitespace(input)
	if strings.HasPrefix(input, "{") {
		return ParseEncryptedJSONWithPolicy(input, policy)
	}
	return ParseEncryptedCompactWithPolicy(input, policy)
}

// ParseEncryptedJSONWithPolicy parses a JWE JSON Serialization message and
// applies the hardened checks of [JWEPolicy].
func ParseEncryptedJSONWithPolicy(input string, policy *JWEPolicy) (*JSONWebEncryption, error) {
	if policy == nil {
		return nil, ErrEmptyPolicy
	}
	if len(input) == 0 {
		return nil, errEmptyInput
	}

	var parsed rawJSONWebEncryption
	if err := json.Unmarshal([]byte(input), &parsed); err != nil {
		return nil, err
	}
	return policy.validateAndSanitize(&parsed, parsed.protectedKeyAlgorithm())
}

// ParseEncryptedCompactWithPolicy parses a JWE Compact Serialization message
// and applies the hardened checks of [JWEPolicy].
func ParseEncryptedCompactWithPolicy(input string, policy *JWEPolicy) (*JSONWebEncryption, error) {
	if policy == nil {
		return nil, ErrEmptyPolicy
	}
	if len(input) == 0 {
		return nil, errEmptyInput
	}

	var parts [5]string
	var ok bool
	remaining := input
	for i := range 4 {
		parts[i], remaining, ok = strings.Cut(remaining, ".")
		if !ok {
			return nil, errors.New("go-jose/go-jose: compact JWE format must have five parts")
		}
	}
	if strings.ContainsRune(remaining, '.') {
		return nil, errors.New("go-jose/go-jose: compact JWE format must have five parts")
	}
	parts[4] = remaining

	rawProtected, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	encryptedKey, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, err
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, err
	}

	raw := &rawJSONWebEncryption{
		Protected:    newBuffer(rawProtected),
		EncryptedKey: newBuffer(encryptedKey),
		Iv:           newBuffer(iv),
		Ciphertext:   newBuffer(ciphertext),
		Tag:          newBuffer(tag),
	}

	// The compact form can only carry an algorithm in the protected header,
	// which is exactly the position the policy decision is taken from.
	protected, err := parseProtectedHeader(raw.Protected)
	if err != nil {
		return nil, err
	}
	var alg KeyAlgorithm
	if protected != nil {
		alg = protected.getAlgorithm()
	}
	return policy.validateAndSanitize(raw, alg)
}

// validateAndSanitize runs, in order:
//  1. the raw policy decision, so every policy failure is reported through
//     its typed category before any generic legacy parse error;
//  2. certificate chain validation (a category of its own);
//  3. the shared legacy sanitization with the full registered algorithm set,
//     so parsing behavior on legitimate messages is unchanged and allow-list
//     enforcement stays exclusively the policy's job;
//  4. the policy decision again on the sanitized object, as defense in depth.
func (policy *JWEPolicy) validateAndSanitize(raw *rawJSONWebEncryption, declaredKeyAlg KeyAlgorithm) (*JSONWebEncryption, error) {
	if err := policy.preValidateRaw(raw); err != nil {
		return nil, err
	}

	if err := policy.validateCertificateChains(*raw, declaredKeyAlg); err != nil {
		return nil, err
	}

	obj, err := sanitizeJSONWebEncryption(raw, allRegisteredKeyAlgorithms(), allRegisteredContentEncryption())
	if err != nil {
		return nil, err
	}

	if err := policy.validateAgainstPolicy(obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// protectedKeyAlgorithm extracts the "alg" value carried in the protected
// header of a raw JSON-serialized JWE. It returns "" when absent so the
// certificate checks can skip algorithm-specific pairing in that case; the
// missing value is then rejected by the policy validation.
func (parsed rawJSONWebEncryption) protectedKeyAlgorithm() KeyAlgorithm {
	protected, err := parseProtectedHeader(parsed.Protected)
	if err != nil || protected == nil {
		return ""
	}
	return protected.getAlgorithm()
}

// HardenedDecrypt validates the object against policy-level key checks and
// decrypts it. It is the policy counterpart of [JSONWebEncryption.Decrypt]:
// key class mismatches, declared-strength/key-length mismatches and
// signature/key-management use conflicts are reported through their typed
// sentinel errors before any cryptographic operation is attempted, so no
// fallback to another algorithm ever happens.
//
// Multi-recipient objects are rejected; use the legacy DecryptMulti path for
// those (the hardened policy rejects them at parse time regardless).
func (obj JSONWebEncryption) HardenedDecrypt(policy *JWEPolicy, decryptionKey any) ([]byte, error) {
	if policy == nil {
		return nil, ErrEmptyPolicy
	}
	if len(obj.recipients) > 1 {
		return nil, ErrUnsupportedMultiRecipient
	}
	if obj.protected == nil {
		return nil, fmt.Errorf("%w: message has no integrity-protected header", ErrUnprotectedAlgorithm)
	}

	alg := obj.protected.getAlgorithm()
	enc := obj.protected.getEncryption()
	if alg == "" {
		return nil, fmt.Errorf("%w: missing or empty %q in protected header", ErrUnprotectedAlgorithm, headerAlgorithm)
	}
	if enc == "" {
		return nil, fmt.Errorf("%w: missing or empty %q in protected header", ErrUnprotectedAlgorithm, headerEncryption)
	}

	// Re-assert the message-level policy in case the object was obtained
	// through a legacy entry point rather than a policy one.
	if err := policy.validateAgainstPolicy(&obj); err != nil {
		return nil, err
	}

	if err := policy.validateDecryptionKey(alg, enc, decryptionKey); err != nil {
		return nil, err
	}

	plaintext, err := obj.Decrypt(decryptionKey)
	if err != nil {
		// Do not leak underlying primitive details beyond the existing
		// category; no key material, plaintext or digest is included.
		return nil, err
	}
	return plaintext, nil
}
