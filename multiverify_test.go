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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

var multiTestHMACKey = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}

// signMultiJSON signs payload with one HS256 signature per entry in count and
// returns the full JSON serialization as a mutable map.
func signMultiJSON(t *testing.T, payload []byte, count int) map[string]any {
	t.Helper()
	keys := make([]SigningKey, count)
	for i := range keys {
		keys[i] = SigningKey{Algorithm: HS256, Key: multiTestHMACKey}
	}
	signer, err := NewMultiSigner(keys, nil)
	if err != nil {
		t.Fatalf("NewMultiSigner: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(obj.FullSerialize()), &m); err != nil {
		t.Fatalf("unmarshal serialized JWS: %v", err)
	}
	return m
}

func mustMarshal(t *testing.T, m map[string]any) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal mutated JWS: %v", err)
	}
	return string(b)
}

func signatureEntry(t *testing.T, m map[string]any, i int) map[string]any {
	t.Helper()
	sigs, ok := m["signatures"].([]any)
	if !ok || i >= len(sigs) {
		t.Fatalf("no signature entry %d in %v", i, m)
	}
	return sigs[i].(map[string]any)
}

// mutateProtected decodes the protected header of signature i, applies fn,
// and re-encodes it. The signature value is left stale on purpose.
func mutateProtected(t *testing.T, m map[string]any, i int, fn func(map[string]any)) {
	t.Helper()
	sig := signatureEntry(t, m, i)
	raw, err := base64.RawURLEncoding.DecodeString(sig["protected"].(string))
	if err != nil {
		t.Fatalf("decode protected header: %v", err)
	}
	var ph map[string]any
	if err := json.Unmarshal(raw, &ph); err != nil {
		t.Fatalf("unmarshal protected header: %v", err)
	}
	fn(ph)
	newRaw, err := json.Marshal(ph)
	if err != nil {
		t.Fatalf("marshal protected header: %v", err)
	}
	sig["protected"] = base64.RawURLEncoding.EncodeToString(newRaw)
}

// tamperSignature flips the first character of signature i's value, keeping
// it valid base64url but changing the decoded bytes.
func tamperSignature(t *testing.T, m map[string]any, i int) {
	t.Helper()
	sig := signatureEntry(t, m, i)
	s := sig["signature"].(string)
	if s == "" {
		t.Fatalf("empty signature value")
	}
	if s[0] == 'A' {
		s = "B" + s[1:]
	} else {
		s = "A" + s[1:]
	}
	sig["signature"] = s
}

func parseMulti(t *testing.T, m map[string]any, algs ...SignatureAlgorithm) *JSONWebSignature {
	t.Helper()
	obj, err := ParseSignedJSON(mustMarshal(t, m), algs)
	if err != nil {
		t.Fatalf("ParseSignedJSON: %v", err)
	}
	return obj
}

// Three signatures: one declares an unknown critical extension header, one
// has a tampered signature value, one is fully valid. The overall result
// must be invalid with a verdict for each signature.
func TestVerifyMultiDetailedThreeSignatures(t *testing.T) {
	m := signMultiJSON(t, []byte("payload"), 3)
	mutateProtected(t, m, 0, func(ph map[string]any) {
		ph["crit"] = []any{"unknown-ext"}
		ph["unknown-ext"] = true
	})
	tamperSignature(t, m, 1)

	obj := parseMulti(t, m, HS256)
	result, err := obj.VerifyMultiDetailed(multiTestHMACKey, nil)
	if err != nil {
		t.Fatalf("VerifyMultiDetailed: %v", err)
	}

	t.Logf("detailed multi-signature verification result:\n%s", result.String())

	if result.Valid {
		t.Errorf("overall result should be invalid")
	}
	if result.Total != 3 || result.Passed != 1 {
		t.Errorf("expected passed=1/3, got passed=%d/%d", result.Passed, result.Total)
	}
	if len(result.Verdicts) != 3 {
		t.Fatalf("expected 3 verdicts, got %d", len(result.Verdicts))
	}

	if result.Verdicts[0].Valid || result.Verdicts[0].Category != SignatureFailureCriticalUnsupported {
		t.Errorf("verdict 0: want invalid/critical-header-unsupported, got %s", result.Verdicts[0])
	}
	if !errors.Is(result.Verdicts[0].Err, ErrUnsupportedCriticalHeader) {
		t.Errorf("verdict 0: want ErrUnsupportedCriticalHeader, got %v", result.Verdicts[0].Err)
	}
	if result.Verdicts[1].Valid || result.Verdicts[1].Category != SignatureFailureSignatureMismatch {
		t.Errorf("verdict 1: want invalid/signature-mismatch, got %s", result.Verdicts[1])
	}
	if !result.Verdicts[2].Valid || result.Verdicts[2].Category != SignatureFailureNone {
		t.Errorf("verdict 2: want valid, got %s", result.Verdicts[2])
	}
	for i, v := range result.Verdicts {
		if v.Index != i {
			t.Errorf("verdict %d has index %d", i, v.Index)
		}
	}
}

// Two fully valid signatures: overall valid, per-signature valid, passed=2.
func TestVerifyMultiDetailedAllValid(t *testing.T) {
	m := signMultiJSON(t, []byte("payload"), 2)
	obj := parseMulti(t, m, HS256)

	result, err := obj.VerifyMultiDetailed(multiTestHMACKey, nil)
	if err != nil {
		t.Fatalf("VerifyMultiDetailed: %v", err)
	}
	if !result.Valid {
		t.Errorf("overall result should be valid: %s", result.String())
	}
	if result.Passed != 2 || result.Total != 2 {
		t.Errorf("expected passed=2/2, got passed=%d/%d", result.Passed, result.Total)
	}
	for i, v := range result.Verdicts {
		if !v.Valid || v.Category != SignatureFailureNone || v.Err != nil {
			t.Errorf("verdict %d should be valid: %s", i, v)
		}
	}
}

// A "crit" parameter in the unprotected header must be rejected with the
// invalid-position category even if the signature value verifies.
func TestVerifyMultiDetailedCritInUnprotectedHeader(t *testing.T) {
	m := signMultiJSON(t, []byte("payload"), 2)
	signatureEntry(t, m, 0)["header"] = map[string]any{"crit": []any{"b64"}}

	obj := parseMulti(t, m, HS256)
	result, err := obj.VerifyMultiDetailed(multiTestHMACKey, nil)
	if err != nil {
		t.Fatalf("VerifyMultiDetailed: %v", err)
	}

	if result.Valid {
		t.Errorf("overall result should be invalid")
	}
	v := result.Verdicts[0]
	if v.Valid || v.Category != SignatureFailureCriticalInvalidPosition {
		t.Errorf("verdict 0: want invalid/critical-header-invalid-position, got %s", v)
	}
	if !errors.Is(v.Err, ErrUnprotectedCriticalHeader) {
		t.Errorf("verdict 0: want ErrUnprotectedCriticalHeader, got %v", v.Err)
	}
	if !result.Verdicts[1].Valid {
		t.Errorf("verdict 1 should be valid: %s", result.Verdicts[1])
	}
}

// Structural problems in the "crit" declaration: naming a header that does
// not exist, an empty list, or a value that is not a list of strings.
func TestVerifyMultiDetailedCritStructural(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(ph map[string]any)
	}{
		{"name not present", func(ph map[string]any) { ph["crit"] = []any{"no-such-header"} }},
		{"empty list", func(ph map[string]any) { ph["crit"] = []any{} }},
		{"not a string list", func(ph map[string]any) { ph["crit"] = "b64" }},
		{"null", func(ph map[string]any) { ph["crit"] = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := signMultiJSON(t, []byte("payload"), 2)
			mutateProtected(t, m, 0, tc.mutate)

			obj := parseMulti(t, m, HS256)
			result, err := obj.VerifyMultiDetailed(multiTestHMACKey, nil)
			if err != nil {
				t.Fatalf("VerifyMultiDetailed: %v", err)
			}
			if result.Valid {
				t.Errorf("overall result should be invalid")
			}
			v := result.Verdicts[0]
			if v.Valid || v.Category != SignatureFailureCriticalUnsupported {
				t.Errorf("verdict 0: want invalid/critical-header-unsupported, got %s", v)
			}
			if !errors.Is(v.Err, ErrInvalidCriticalHeader) {
				t.Errorf("verdict 0: want ErrInvalidCriticalHeader, got %v", v.Err)
			}
			if !result.Verdicts[1].Valid {
				t.Errorf("verdict 1 should be valid: %s", result.Verdicts[1])
			}
		})
	}
}

// Two signatures using different algorithms (one symmetric, one asymmetric)
// are evaluated independently; one failing does not affect the other's
// recorded verdict.
func TestVerifyMultiDetailedMixedAlgorithms(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	payload := []byte("payload")

	sign := func(alg SignatureAlgorithm, key any, kid string) map[string]any {
		signer, err := NewSigner(SigningKey{Algorithm: alg, Key: key},
			(&SignerOptions{}).WithHeader(headerKeyID, kid))
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		obj, err := signer.Sign(payload)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(obj.FullSerialize()), &m); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return m
	}

	hs := sign(HS256, multiTestHMACKey, "k1")
	ed := sign(EdDSA, edPriv, "k2")

	combined := map[string]any{
		"payload": hs["payload"],
		"signatures": []any{
			map[string]any{"protected": hs["protected"], "signature": hs["signature"]},
			map[string]any{"protected": ed["protected"], "signature": ed["signature"]},
		},
	}

	jwks := JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: "k1", Key: multiTestHMACKey},
		{KeyID: "k2", Key: edPub},
	}}

	obj := parseMulti(t, combined, HS256, EdDSA)

	result, err := obj.VerifyMultiDetailed(jwks, nil)
	if err != nil {
		t.Fatalf("VerifyMultiDetailed: %v", err)
	}
	if !result.Valid || result.Passed != 2 {
		t.Errorf("expected both signatures valid: %s", result.String())
	}
	if result.Verdicts[0].Algorithm != HS256 || result.Verdicts[1].Algorithm != EdDSA {
		t.Errorf("unexpected algorithms: %s, %s", result.Verdicts[0].Algorithm, result.Verdicts[1].Algorithm)
	}

	// Tamper only the EdDSA signature; the HS256 verdict must be unaffected.
	tamperSignature(t, combined, 1)
	obj = parseMulti(t, combined, HS256, EdDSA)
	result, err = obj.VerifyMultiDetailed(jwks, nil)
	if err != nil {
		t.Fatalf("VerifyMultiDetailed: %v", err)
	}
	if result.Valid {
		t.Errorf("overall result should be invalid")
	}
	if !result.Verdicts[0].Valid {
		t.Errorf("verdict 0 (HS256) should still be valid: %s", result.Verdicts[0])
	}
	if result.Verdicts[1].Valid || result.Verdicts[1].Category != SignatureFailureSignatureMismatch {
		t.Errorf("verdict 1 (EdDSA): want invalid/signature-mismatch, got %s", result.Verdicts[1])
	}
}

// Messages with more than MaxSignatures signatures are rejected, at parse
// time and at detailed-verification time, with the limit in the error.
func TestVerifyMultiDetailedTooManySignatures(t *testing.T) {
	m := signMultiJSON(t, []byte("payload"), 3)
	serialized := mustMarshal(t, m)

	defer func() { MaxSignatures = 32 }()

	MaxSignatures = 2
	_, err := ParseSignedJSON(serialized, []SignatureAlgorithm{HS256})
	if err == nil || !strings.Contains(err.Error(), "maximum is 2") {
		t.Errorf("parse should reject with limit in error, got %v", err)
	}

	MaxSignatures = 3
	obj, err := ParseSignedJSON(serialized, []SignatureAlgorithm{HS256})
	if err != nil {
		t.Fatalf("ParseSignedJSON: %v", err)
	}

	MaxSignatures = 2
	_, err = obj.VerifyMultiDetailed(multiTestHMACKey, nil)
	if err == nil || !strings.Contains(err.Error(), "maximum is 2") {
		t.Errorf("detailed verify should reject with limit in error, got %v", err)
	}
}

// A signature whose algorithm is not in the caller-provided allowed set is
// reported with the algorithm-not-allowed category.
func TestVerifyMultiDetailedAlgorithmNotAllowed(t *testing.T) {
	signer, err := NewMultiSigner([]SigningKey{
		{Algorithm: HS256, Key: multiTestHMACKey},
		{Algorithm: HS256, Key: multiTestHMACKey},
	}, nil)
	if err != nil {
		t.Fatalf("NewMultiSigner: %v", err)
	}
	obj, err := signer.Sign([]byte("payload"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	result, err := obj.VerifyMultiDetailed(multiTestHMACKey, []SignatureAlgorithm{EdDSA})
	if err != nil {
		t.Fatalf("VerifyMultiDetailed: %v", err)
	}
	if result.Valid || result.Passed != 0 {
		t.Errorf("expected overall invalid with 0 passed: %s", result.String())
	}
	for i, v := range result.Verdicts {
		if v.Valid || v.Category != SignatureFailureAlgorithmNotAllowed {
			t.Errorf("verdict %d: want invalid/algorithm-not-allowed, got %s", i, v)
		}
		var algErr *ErrUnexpectedSignatureAlgorithm
		if !errors.As(v.Err, &algErr) {
			t.Errorf("verdict %d: want ErrUnexpectedSignatureAlgorithm, got %v", i, v.Err)
		}
	}
}

// No usable key for a signature (no matching kid in the JWK Set, or an
// unsupported key type) is reported with the key-unavailable category.
func TestVerifyMultiDetailedKeyUnavailable(t *testing.T) {
	m := signMultiJSON(t, []byte("payload"), 2)
	obj := parseMulti(t, m, HS256)

	// JWK Set without a matching kid (the signatures carry no kid header).
	result, err := obj.VerifyMultiDetailed(JSONWebKeySet{Keys: []JSONWebKey{{KeyID: "other", Key: multiTestHMACKey}}}, nil)
	if err != nil {
		t.Fatalf("VerifyMultiDetailed: %v", err)
	}
	for i, v := range result.Verdicts {
		if v.Valid || v.Category != SignatureFailureKeyUnavailable {
			t.Errorf("verdict %d: want invalid/key-unavailable, got %s", i, v)
		}
		if !errors.Is(v.Err, ErrJWKSKidNotFound) {
			t.Errorf("verdict %d: want ErrJWKSKidNotFound, got %v", i, v.Err)
		}
	}

	// Unsupported key type.
	result, err = obj.VerifyMultiDetailed(42, nil)
	if err != nil {
		t.Fatalf("VerifyMultiDetailed: %v", err)
	}
	for i, v := range result.Verdicts {
		if v.Valid || v.Category != SignatureFailureKeyUnavailable {
			t.Errorf("verdict %d: want invalid/key-unavailable, got %s", i, v)
		}
	}
}

// A signature without a protected header is unusable; the remaining
// signatures are still evaluated and the overall result is invalid.
func TestVerifyMultiDetailedMissingProtectedHeader(t *testing.T) {
	m := signMultiJSON(t, []byte("payload"), 2)
	sig0 := signatureEntry(t, m, 0)
	delete(sig0, "protected")
	sig0["header"] = map[string]any{"alg": "HS256"}

	obj := parseMulti(t, m, HS256)
	result, err := obj.VerifyMultiDetailed(multiTestHMACKey, nil)
	if err != nil {
		t.Fatalf("VerifyMultiDetailed: %v", err)
	}
	if result.Valid {
		t.Errorf("overall result should be invalid")
	}
	v := result.Verdicts[0]
	if v.Valid || v.Category != SignatureFailureUnknown {
		t.Errorf("verdict 0: want invalid/unknown, got %s", v)
	}
	if !errors.Is(v.Err, ErrMissingProtectedHeader) {
		t.Errorf("verdict 0: want ErrMissingProtectedHeader, got %v", v.Err)
	}
	if !result.Verdicts[1].Valid {
		t.Errorf("verdict 1 should be valid: %s", result.Verdicts[1])
	}
}

// Verifying the same input twice must produce identical per-signature
// results, in the same order.
func TestVerifyMultiDetailedDeterministic(t *testing.T) {
	m := signMultiJSON(t, []byte("payload"), 3)
	mutateProtected(t, m, 0, func(ph map[string]any) {
		ph["crit"] = []any{"unknown-ext"}
		ph["unknown-ext"] = true
	})
	tamperSignature(t, m, 1)

	obj := parseMulti(t, m, HS256)

	first, err := obj.VerifyMultiDetailed(multiTestHMACKey, nil)
	if err != nil {
		t.Fatalf("VerifyMultiDetailed: %v", err)
	}
	second, err := obj.VerifyMultiDetailed(multiTestHMACKey, nil)
	if err != nil {
		t.Fatalf("VerifyMultiDetailed: %v", err)
	}

	if first.Valid != second.Valid || first.Passed != second.Passed || first.Total != second.Total {
		t.Fatalf("overall results differ:\n%s\n%s", first.String(), second.String())
	}
	if len(first.Verdicts) != len(second.Verdicts) {
		t.Fatalf("verdict counts differ")
	}
	for i := range first.Verdicts {
		a, b := first.Verdicts[i], second.Verdicts[i]
		if a.Index != b.Index || a.Valid != b.Valid || a.Category != b.Category || a.Algorithm != b.Algorithm {
			t.Errorf("verdict %d differs: %s vs %s", i, a, b)
		}
	}
}

func TestVerifyMultiDetailedNoSignatures(t *testing.T) {
	obj := &JSONWebSignature{}
	if _, err := obj.VerifyMultiDetailed(multiTestHMACKey, nil); err == nil {
		t.Errorf("expected error for object without signatures")
	}
}

// The existing single-signature entry points must be unaffected by the new
// one: Verify on a single-signature object behaves as before, and still
// rejects multi-signature objects.
func TestVerifyMultiDetailedLeavesSingleSignatureAlone(t *testing.T) {
	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: multiTestHMACKey}, nil)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	obj, err := signer.Sign([]byte("payload"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	payload, err := obj.Verify(multiTestHMACKey)
	if err != nil || string(payload) != "payload" {
		t.Errorf("Verify: got %q, %v", payload, err)
	}

	multi, err := NewMultiSigner([]SigningKey{
		{Algorithm: HS256, Key: multiTestHMACKey},
		{Algorithm: HS256, Key: multiTestHMACKey},
	}, nil)
	if err != nil {
		t.Fatalf("NewMultiSigner: %v", err)
	}
	multiObj, err := multi.Sign([]byte("payload"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := multiObj.Verify(multiTestHMACKey); err == nil {
		t.Errorf("Verify on multi-signature object should fail")
	}
}
