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
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
	"testing"

	josecipher "github.com/go-jose/go-jose/v5/cipher"
)

func randomKey(t *testing.T, size int) []byte {
	t.Helper()
	k := make([]byte, size)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// newAESKWMulti builds a multi-recipient A128GCM message to the given A128KW
// keys, with a key ID per recipient (empty means no kid).
func newAESKWMulti(t *testing.T, keys [][]byte, kids []string) (*JSONWebEncryption, []byte) {
	t.Helper()
	rcpts := make([]Recipient, len(keys))
	for i := range keys {
		rcpts[i] = Recipient{Algorithm: A128KW, Key: keys[i], KeyID: kids[i]}
	}
	enc, err := NewMultiEncrypter(A128GCM, rcpts, nil)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("rotation-era envelope payload")
	obj, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEncrypted(obj.FullSerialize(), []KeyAlgorithm{A128KW}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatal(err)
	}
	return parsed, plaintext
}

func outcomeFor(ro RecipientOutcome) string {
	if ro.OK {
		return "ok"
	}
	if ro.Failure == nil {
		return "failed without reason"
	}
	return ro.Failure.Kind.String()
}

// TestEnvelopeRotationWithLostKey covers the three-recipient acceptance case:
// one current key, one pre-rotation key, and one lost key.
func TestEnvelopeRotationWithLostKey(t *testing.T) {
	current := randomKey(t, 16)
	old := randomKey(t, 16)
	lost := randomKey(t, 16)

	obj, plaintext := newAESKWMulti(t, [][]byte{current, old, lost},
		[]string{"current", "old", "lost"})

	result, err := obj.DecryptEnvelope([]KeyCandidate{
		{Key: current, KeyID: "current"},
		{Key: old, KeyID: "old"},
	}, nil)
	if err != nil {
		t.Fatalf("DecryptEnvelope: %v", err)
	}
	if result.Failed() {
		t.Fatal("result reports failure but two recipients should decrypt")
	}
	if len(result.Recipients) != 3 {
		t.Fatalf("got %d outcomes, want 3", len(result.Recipients))
	}

	want := []struct {
		ok     bool
		kind   FailureKind
		usedID string
	}{
		{true, FailureNone, "current"},
		{true, FailureNone, "old"},
		{false, FailureNoMatchingKey, ""},
	}
	for i, w := range want {
		ro := result.Recipients[i]
		if ro.OK != w.ok {
			t.Errorf("recipient %d: OK = %v, want %v (outcome %s)", i, ro.OK, w.ok, outcomeFor(ro))
		}
		if w.ok {
			if ro.UsedKeyID != w.usedID {
				t.Errorf("recipient %d: UsedKeyID = %q, want %q", i, ro.UsedKeyID, w.usedID)
			}
			if !bytes.Equal(ro.Plaintext, plaintext) {
				t.Errorf("recipient %d: plaintext mismatch", i)
			}
		} else {
			if ro.Failure == nil || ro.Failure.Kind != w.kind {
				t.Errorf("recipient %d: failure = %v, want %s", i, ro.Failure, w.kind)
			}
		}
	}

	// Every successful recipient must agree.
	if len(result.Plaintexts) != 2 || !bytes.Equal(result.Plaintexts[0], result.Plaintexts[1]) {
		t.Errorf("Plaintexts = %q, want two equal entries", result.Plaintexts)
	}
	if !bytes.Equal(result.Plaintext, plaintext) {
		t.Errorf("Plaintext = %q, want %q", result.Plaintext, plaintext)
	}
	if len(result.KeyIDs) != 2 || result.KeyIDs[0] != "current" || result.KeyIDs[1] != "old" {
		t.Errorf("KeyIDs = %v, want [current old]", result.KeyIDs)
	}

	t.Logf("per-recipient outcomes: %s", describeOutcomes(result.Recipients))
}

// TestEnvelopeCandidatesSharingKeyID checks that two candidate keys with the
// same key ID are both tried and that the second can succeed.
func TestEnvelopeCandidatesSharingKeyID(t *testing.T) {
	right := randomKey(t, 16)
	wrong := randomKey(t, 16)

	obj, plaintext := newAESKWMulti(t, [][]byte{right}, []string{"ring"})

	result, err := obj.DecryptEnvelope([]KeyCandidate{
		{Key: wrong, KeyID: "ring"},
		{Key: right, KeyID: "ring"},
	}, nil)
	if err != nil {
		t.Fatalf("DecryptEnvelope: %v", err)
	}
	if len(result.Recipients) != 1 || !result.Recipients[0].OK {
		t.Fatalf("recipient did not decrypt: %s", describeOutcomes(result.Recipients))
	}
	ro := result.Recipients[0]
	if ro.UsedKeyPosition != 1 {
		t.Errorf("UsedKeyPosition = %d, want 1 (the second key in the ring)", ro.UsedKeyPosition)
	}
	if ro.UsedKeyID != "ring" {
		t.Errorf("UsedKeyID = %q, want %q", ro.UsedKeyID, "ring")
	}
	if !bytes.Equal(ro.Plaintext, plaintext) {
		t.Error("plaintext mismatch")
	}
	if len(ro.Attempts) != 2 {
		t.Fatalf("got %d attempts, want 2: %+v", len(ro.Attempts), ro.Attempts)
	}
	if ro.Attempts[0].Failure == nil || ro.Attempts[0].Failure.Kind != FailureKeyUnwrap {
		t.Errorf("first attempt = %v, want key-unwrap failure", ro.Attempts[0].Failure)
	}
	if ro.Attempts[1].Failure != nil {
		t.Errorf("second attempt failed: %v", ro.Attempts[1].Failure)
	}

	// With attempts capped at one, the second key is never reached.
	capped, err := obj.DecryptEnvelope([]KeyCandidate{
		{Key: wrong, KeyID: "ring"},
		{Key: right, KeyID: "ring"},
	}, &EnvelopeOptions{MaxCandidates: 1})
	if err == nil {
		t.Fatal("expected failure when only the first candidate may be tried")
	}
	if !errors.Is(err, ErrAllRecipientsFailed) {
		t.Errorf("error = %v, want ErrAllRecipientsFailed", err)
	}
	if got := capped.Recipients[0].Failure; got == nil || got.Kind != FailureKeyUnwrap {
		t.Errorf("capped failure = %v, want key-unwrap", got)
	}
}

// TestEnvelopeWrongKeyStrength checks the declared-128-bits/256-bit-key case.
func TestEnvelopeWrongKeyStrength(t *testing.T) {
	key128 := randomKey(t, 16)
	key256 := randomKey(t, 32)

	enc, err := NewEncrypter(A128GCM, Recipient{Algorithm: A128KW, Key: key128, KeyID: "k"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := enc.Encrypt([]byte("strength"))
	if err != nil {
		t.Fatal(err)
	}

	result, err := obj.DecryptEnvelope([]KeyCandidate{{Key: key256, KeyID: "k"}}, nil)
	if err == nil {
		t.Fatal("expected rejection of a 256-bit key for A128KW")
	}
	ro := result.Recipients[0]
	if ro.OK {
		t.Fatal("recipient unexpectedly decrypted")
	}
	if ro.Failure == nil {
		t.Fatal("no failure recorded")
	}
	if ro.Failure.Kind != FailureWrongKeySize {
		t.Fatalf("Kind = %s, want %s", ro.Failure.Kind, FailureWrongKeySize)
	}
	if ro.Failure.Expected != 128 || ro.Failure.Actual != 256 {
		t.Errorf("mismatch sides = (%d, %d), want (128, 256)", ro.Failure.Expected, ro.Failure.Actual)
	}
	if !errors.Is(ro.Failure, ErrKeyStrengthMismatch) {
		t.Errorf("failure does not wrap ErrKeyStrengthMismatch: %v", ro.Failure)
	}
	if !strings.Contains(ro.Failure.Detail, "128") || !strings.Contains(ro.Failure.Detail, "256") {
		t.Errorf("detail does not report both sides: %q", ro.Failure.Detail)
	}
}

// TestEnvelopeContentKeySizeMismatch crafts a message in which one recipient
// unwraps a content key of the wrong length. That recipient must be rejected
// while the other recipient's conclusion is preserved.
func TestEnvelopeContentKeySizeMismatch(t *testing.T) {
	kek := randomKey(t, 16)
	rsaRecipient := Recipient{Algorithm: RSA_OAEP, Key: &rsaTestKey.PublicKey, KeyID: "rsa"}

	enc, err := NewMultiEncrypter(A128GCM, []Recipient{
		rsaRecipient,
		{Algorithm: A128KW, Key: kek, KeyID: "kw"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("content-key-size")
	obj, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEncrypted(obj.FullSerialize(),
		[]KeyAlgorithm{RSA_OAEP, A128KW}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatal(err)
	}

	// Replace the A128KW recipient's wrapped key with a wrap of a 24-byte key.
	wrongCEK := randomKey(t, 24)
	block, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := josecipher.KeyWrap(block, wrongCEK)
	if err != nil {
		t.Fatal(err)
	}
	parsed.recipients[1].encryptedKey = wrapped

	result, err := parsed.DecryptEnvelope([]KeyCandidate{
		{Key: rsaTestKey, KeyID: "rsa"},
		{Key: kek, KeyID: "kw"},
	}, nil)
	if err != nil {
		t.Fatalf("one recipient should still decrypt: %v", err)
	}

	if !result.Recipients[0].OK || result.Recipients[0].UsedKeyID != "rsa" {
		t.Errorf("RSA recipient outcome = %s, want ok", outcomeFor(result.Recipients[0]))
	}
	bad := result.Recipients[1]
	if bad.OK {
		t.Fatal("short-CEK recipient unexpectedly decrypted")
	}
	if bad.Failure == nil || bad.Failure.Kind != FailureContentKeySize {
		t.Fatalf("failure = %v, want %s", bad.Failure, FailureContentKeySize)
	}
	if bad.Failure.Expected != 128 || bad.Failure.Actual != 192 {
		t.Errorf("sides = (%d, %d), want (128, 192)", bad.Failure.Expected, bad.Failure.Actual)
	}
	if !bad.KeyUnwrapped {
		t.Error("KeyUnwrapped should be true: a key was unwrapped, just the wrong size")
	}
	if !bytes.Equal(result.Plaintext, plaintext) {
		t.Errorf("Plaintext = %q, want %q", result.Plaintext, plaintext)
	}

	t.Logf("per-recipient outcomes: %s", describeOutcomes(result.Recipients))
}

// TestEnvelopePerRecipientKeyID checks that a kid present only in a
// per-recipient header still selects the right key.
func TestEnvelopePerRecipientKeyID(t *testing.T) {
	right := randomKey(t, 16)
	other := randomKey(t, 16)

	obj, plaintext := newAESKWMulti(t, [][]byte{other, right}, []string{"other", "target"})

	// The protected header must not carry the kid; it is per recipient.
	if obj.protected != nil && obj.protected.isSet(headerKeyID) {
		t.Fatal("test setup: kid unexpectedly in the protected header")
	}
	if obj.recipients[1].header == nil || obj.recipients[1].header.getString(headerKeyID) != "target" {
		t.Fatalf("test setup: recipient 1 header = %+v", obj.recipients[1].header)
	}

	result, err := obj.DecryptEnvelope([]KeyCandidate{{Key: right, KeyID: "target"}}, nil)
	if err != nil {
		t.Fatalf("DecryptEnvelope: %v", err)
	}
	if !result.Recipients[1].OK {
		t.Fatalf("recipient 1 didn't decrypt: %s", describeOutcomes(result.Recipients))
	}
	if !bytes.Equal(result.Recipients[1].Plaintext, plaintext) {
		t.Error("plaintext mismatch")
	}
}

// TestEnvelopeNoCandidates checks the explicit empty-candidate conclusion.
func TestEnvelopeNoCandidates(t *testing.T) {
	obj, _ := newAESKWMulti(t, [][]byte{randomKey(t, 16)}, []string{"k"})

	result, err := obj.DecryptEnvelope(nil, nil)
	if err == nil {
		t.Fatal("expected an error with no candidates")
	}
	if !errors.Is(err, ErrNoKeyCandidates) {
		t.Errorf("error = %v, want ErrNoKeyCandidates", err)
	}
	ro := result.Recipients[0]
	if ro.Failure == nil || ro.Failure.Kind != FailureNoKeys {
		t.Fatalf("failure = %v, want %s", ro.Failure, FailureNoKeys)
	}
	if !strings.Contains(ro.Failure.Error(), "no candidate keys") {
		t.Errorf("failure text is not explicit: %q", ro.Failure.Error())
	}
}

// TestEnvelopeUnusableCandidates checks the case where every candidate is
// unusable, as distinct from merely not matching.
func TestEnvelopeUnusableCandidates(t *testing.T) {
	obj, _ := newAESKWMulti(t, [][]byte{randomKey(t, 16)}, []string{"k"})

	result, err := obj.DecryptEnvelope([]KeyCandidate{{Key: nil}, {Key: 42, KeyID: "k"}}, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrNoUsableKeyCandidates) {
		t.Errorf("error = %v, want ErrNoUsableKeyCandidates", err)
	}
	if result.Recipients[0].Failure.Kind != FailureNoUsableKeys {
		t.Errorf("kind = %s, want %s", result.Recipients[0].Failure.Kind, FailureNoUsableKeys)
	}
}

// TestEnvelopeCandidateLimit checks the hard bound on candidate keys.
func TestEnvelopeCandidateLimit(t *testing.T) {
	key := randomKey(t, 16)
	obj, _ := newAESKWMulti(t, [][]byte{key}, []string{"k"})

	candidates := make([]KeyCandidate, MaxKeyCandidates+1)
	for i := range candidates {
		candidates[i] = KeyCandidate{Key: key, KeyID: "k"}
	}
	_, err := obj.DecryptEnvelope(candidates, nil)
	if !errors.Is(err, ErrTooManyKeyCandidates) {
		t.Fatalf("error = %v, want ErrTooManyKeyCandidates", err)
	}
}

// TestEnvelopeKeySetExpansion verifies that a JWK Set acts as a rotation ring
// and that a key later in the set can decrypt.
func TestEnvelopeKeySetExpansion(t *testing.T) {
	right := randomKey(t, 16)
	wrong := randomKey(t, 16)

	obj, plaintext := newAESKWMulti(t, [][]byte{right}, []string{"ring"})

	set := JSONWebKeySet{Keys: []JSONWebKey{
		{Key: wrong, KeyID: "ring"},
		{Key: right, KeyID: "ring"},
	}}
	result, err := obj.DecryptEnvelope([]KeyCandidate{{Key: set}}, nil)
	if err != nil {
		t.Fatalf("DecryptEnvelope: %v", err)
	}
	ro := result.Recipients[0]
	if !ro.OK {
		t.Fatalf("recipient didn't decrypt: %s", describeOutcomes(result.Recipients))
	}
	if ro.UsedKeyPosition != 1 || ro.UsedKeyID != "ring" {
		t.Errorf("used key = (pos %d, id %q), want (1, ring)", ro.UsedKeyPosition, ro.UsedKeyID)
	}
	if !bytes.Equal(ro.Plaintext, plaintext) {
		t.Error("plaintext mismatch")
	}
}

// TestEnvelopeContentDecryptVsKeyMismatch separates a modified message from a
// wrong key.
func TestEnvelopeContentDecryptVsKeyMismatch(t *testing.T) {
	key := randomKey(t, 16)
	obj, _ := newAESKWMulti(t, [][]byte{key}, []string{"k"})

	tampered := obj
	tampered.tag = bytes.Clone(obj.tag)
	tampered.tag[0] ^= 0xff

	result, err := tampered.DecryptEnvelope([]KeyCandidate{{Key: key, KeyID: "k"}}, nil)
	if err == nil {
		t.Fatal("expected tampered content to be rejected")
	}
	ro := result.Recipients[0]
	if ro.Failure == nil || ro.Failure.Kind != FailureContentDecrypt {
		t.Fatalf("failure = %v, want %s", ro.Failure, FailureContentDecrypt)
	}
	if !ro.KeyUnwrapped {
		t.Error("KeyUnwrapped should be true: the key matched")
	}
	if !errors.Is(ro.Failure, ErrCryptoFailure) {
		t.Errorf("failure should wrap ErrCryptoFailure: %v", ro.Failure)
	}
	if !strings.Contains(ro.Failure.Error(), "authentication failed") {
		t.Errorf("failure does not explain the content was modified: %q", ro.Failure.Error())
	}

	wrongKey := randomKey(t, 16)
	result, err = obj.DecryptEnvelope([]KeyCandidate{{Key: wrongKey, KeyID: "k"}}, nil)
	if err == nil {
		t.Fatal("expected a wrong key to be rejected")
	}
	ro = result.Recipients[0]
	if ro.Failure == nil || ro.Failure.Kind != FailureKeyUnwrap {
		t.Fatalf("failure = %v, want %s", ro.Failure, FailureKeyUnwrap)
	}
	if ro.KeyUnwrapped {
		t.Error("KeyUnwrapped should be false when the key did not match")
	}
}

// pbkdf2TestMessage builds a single-recipient PBES2 message with a cheap
// iteration count for tests that mutate the headers afterwards.
func pbkdf2TestMessage(t *testing.T) *JSONWebEncryption {
	t.Helper()
	enc, err := NewEncrypter(A128GCM, Recipient{
		Algorithm:  PBES2_HS256_A128KW,
		Key:        "password",
		PBES2Count: 1000,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := enc.Encrypt([]byte("pbes2"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEncrypted(obj.FullSerialize(),
		[]KeyAlgorithm{PBES2_HS256_A128KW}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestEnvelopePBES2FailureCategories(t *testing.T) {
	t.Run("iterations out of range", func(t *testing.T) {
		obj := pbkdf2TestMessage(t)
		if err := obj.protected.set(headerP2C, maxPBES2Iterations+1); err != nil {
			t.Fatal(err)
		}
		result, err := obj.DecryptEnvelope([]KeyCandidate{{Key: "password"}}, nil)
		if err == nil {
			t.Fatal("expected rejection")
		}
		ro := result.Recipients[0]
		if ro.Failure.Kind != FailurePBES2Iterations {
			t.Fatalf("kind = %s, want %s", ro.Failure.Kind, FailurePBES2Iterations)
		}
		if !errors.Is(ro.Failure, ErrInvalidPBES2Iterations) {
			t.Errorf("failure should wrap ErrInvalidPBES2Iterations: %v", ro.Failure)
		}
	})

	t.Run("non-positive iterations", func(t *testing.T) {
		obj := pbkdf2TestMessage(t)
		if err := obj.protected.set(headerP2C, 0); err != nil {
			t.Fatal(err)
		}
		result, _ := obj.DecryptEnvelope([]KeyCandidate{{Key: "password"}}, nil)
		if got := result.Recipients[0].Failure.Kind; got != FailurePBES2Iterations {
			t.Fatalf("kind = %s, want %s", got, FailurePBES2Iterations)
		}
	})

	t.Run("missing salt", func(t *testing.T) {
		obj := pbkdf2TestMessage(t)
		delete(*obj.protected, headerP2S)
		result, err := obj.DecryptEnvelope([]KeyCandidate{{Key: "password"}}, nil)
		if err == nil {
			t.Fatal("expected rejection")
		}
		ro := result.Recipients[0]
		if ro.Failure.Kind != FailurePBES2Salt {
			t.Fatalf("kind = %s, want %s", ro.Failure.Kind, FailurePBES2Salt)
		}
		if !errors.Is(ro.Failure, ErrMissingPBES2Salt) {
			t.Errorf("failure should wrap ErrMissingPBES2Salt: %v", ro.Failure)
		}
	})

	t.Run("derivation failure", func(t *testing.T) {
		obj := pbkdf2TestMessage(t)
		old := pbkdf2Key
		pbkdf2Key = func(h func() hash.Hash, password string, salt []byte, iter, keyLength int) ([]byte, error) {
			return nil, errors.New("synthetic derivation failure")
		}
		defer func() { pbkdf2Key = old }()

		result, err := obj.DecryptEnvelope([]KeyCandidate{{Key: "password"}}, nil)
		if err == nil {
			t.Fatal("expected rejection")
		}
		ro := result.Recipients[0]
		if ro.Failure.Kind != FailurePBES2Derive {
			t.Fatalf("kind = %s, want %s (%v)", ro.Failure.Kind, FailurePBES2Derive, ro.Failure)
		}
		if !errors.Is(ro.Failure, ErrPBES2Derivation) {
			t.Errorf("failure should wrap ErrPBES2Derivation: %v", ro.Failure)
		}
	})

	t.Run("iteration budget", func(t *testing.T) {
		obj := pbkdf2TestMessage(t)
		result, err := obj.DecryptEnvelope([]KeyCandidate{{Key: "password"}},
			&EnvelopeOptions{MaxPBES2Iterations: 999})
		if err == nil {
			t.Fatal("expected rejection by budget")
		}
		if got := result.Recipients[0].Failure.Kind; got != FailurePBES2Iterations {
			t.Fatalf("kind = %s, want %s", got, FailurePBES2Iterations)
		}
	})
}

// TestEnvelopeDecompressFailureKeepsKeyStage checks that a decompression
// failure is localized, leaving the key-stage conclusion intact.
func TestEnvelopeDecompressFailureKeepsKeyStage(t *testing.T) {
	testKey, err := hex.DecodeString("0c5433f844097b2e910db9b3638ff824")
	if err != nil {
		t.Fatal(err)
	}
	msg := `{
		"protected":"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0",
		"encrypted_key":"0ZJRSSVctBhIpWvT9Ke2Z-KvSby-kjmi",
		"iv":"4nuUbYF0BR0KPz1v",
		"ciphertext":"luLq8QTsJEXbZdRvEzIiHWEitTZTORZqXIk",
		"tag":"S1j6wvSGtTUCXhED91lUGQ"
	}`
	obj, err := ParseEncrypted(msg, []KeyAlgorithm{A128KW}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatal(err)
	}
	result, err := obj.DecryptEnvelope([]KeyCandidate{{Key: testKey}}, nil)
	if err == nil {
		t.Fatal("expected a decompression failure")
	}
	ro := result.Recipients[0]
	if ro.OK {
		t.Error("OK should be false after a decompression failure")
	}
	if ro.Failure == nil || ro.Failure.Kind != FailureDecompress {
		t.Fatalf("failure = %v, want %s", ro.Failure, FailureDecompress)
	}
	if !ro.KeyUnwrapped {
		t.Error("KeyUnwrapped should remain true across a decompression failure")
	}
	if !strings.Contains(err.Error(), "failed to decompress plaintext") {
		t.Errorf("error = %v, want the decompression error preserved", err)
	}
	if !strings.Contains(ro.Failure.Detail, "failed to decompress plaintext") {
		t.Errorf("detail = %q, want decompression failure", ro.Failure.Detail)
	}
}

// TestEnvelopeCEKDisagreementRejectsMessage crafts a message where two
// recipients unwrap different content keys. Even though one recipient's key is
// the real one, the message is rejected as a whole.
func TestEnvelopeCEKDisagreementRejectsMessage(t *testing.T) {
	k0 := randomKey(t, 16)
	k1 := randomKey(t, 16)
	obj, _ := newAESKWMulti(t, [][]byte{k0, k1}, []string{"a", "b"})

	block, err := aes.NewCipher(k1)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := josecipher.KeyWrap(block, randomKey(t, 16))
	if err != nil {
		t.Fatal(err)
	}
	obj.recipients[1].encryptedKey = wrong

	result, err := obj.DecryptEnvelope([]KeyCandidate{
		{Key: k0, KeyID: "a"},
		{Key: k1, KeyID: "b"},
	}, nil)
	if err == nil {
		t.Fatal("expected the inconsistent message to be rejected")
	}
	if !errors.Is(err, ErrContentKeyMismatch) {
		t.Fatalf("error = %v, want ErrContentKeyMismatch", err)
	}
	if !errors.Is(err, ErrAllRecipientsFailed) {
		t.Fatalf("error = %v, want ErrAllRecipientsFailed", err)
	}
	if result.Plaintext != nil || len(result.Plaintexts) != 0 {
		t.Fatal("rejected message must not expose plaintext")
	}
	for i, ro := range result.Recipients {
		if ro.OK {
			t.Errorf("recipient %d reports success on a rejected message", i)
		}
		if ro.Failure == nil || ro.Failure.Kind != FailureCEKMismatch {
			t.Errorf("recipient %d failure = %v, want %s", i, ro.Failure, FailureCEKMismatch)
		}
	}
}

// TestEnvelopeDecompressLimitPreserved checks that the existing decompression
// size limit still applies through the new entry point.
func TestEnvelopeDecompressLimitPreserved(t *testing.T) {
	key := randomKey(t, 16)
	enc, err := NewEncrypter(A128GCM, Recipient{Algorithm: A128KW, Key: key}, &EncrypterOptions{Compression: DEFLATE})
	if err != nil {
		t.Fatal(err)
	}
	// A highly compressible payload above the 250kB cap.
	obj, err := enc.Encrypt([]byte(strings.Repeat("a", 251_000)))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEncrypted(obj.FullSerialize(), []KeyAlgorithm{A128KW}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatal(err)
	}
	result, err := parsed.DecryptEnvelope([]KeyCandidate{{Key: key}}, nil)
	if err == nil {
		t.Fatal("expected the decompressed plaintext to be rejected as too large")
	}
	ro := result.Recipients[0]
	if ro.Failure == nil || ro.Failure.Kind != FailureDecompress {
		t.Fatalf("failure = %v, want %s", ro.Failure, FailureDecompress)
	}
	if !ro.KeyUnwrapped {
		t.Error("KeyUnwrapped should remain true: the key stage succeeded")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error = %v, want the size-limit error preserved", err)
	}
	if !strings.Contains(err.Error(), "uncompressed data would be too large") {
		t.Errorf("error = %v, want the existing decompression limit message", err)
	}
}

// TestEnvelopeCEKAgreement is a unit test of the cross-recipient invariant:
// when recipients derive different content keys the message is rejected as a
// whole rather than returning whichever recipient looked correct.
func TestEnvelopeCEKAgreement(t *testing.T) {
	outcomes := []RecipientOutcome{
		{OK: true, cek: []byte("shared")},
		{OK: true, cek: []byte("shared")},
		{OK: true, cek: []byte("other")},
	}
	if !enforceCEKAgreement(outcomes) {
		t.Fatal("expected a mismatch to be detected")
	}
	for i, ro := range outcomes {
		if ro.OK {
			t.Errorf("recipient %d still reports success", i)
		}
		if ro.Failure == nil || ro.Failure.Kind != FailureCEKMismatch {
			t.Errorf("recipient %d failure = %v, want %s", i, ro.Failure, FailureCEKMismatch)
		}
		if ro.Plaintext != nil {
			t.Errorf("recipient %d still exposes plaintext", i)
		}
	}

	// Agreement is not a failure.
	agree := []RecipientOutcome{
		{OK: true, cek: []byte("shared")},
		{OK: true, cek: []byte("shared")},
	}
	if enforceCEKAgreement(agree) {
		t.Fatal("agreeing recipients were reported as mismatched")
	}
	if !agree[0].OK || !agree[1].OK {
		t.Error("agreeing recipients should keep successful outcomes")
	}
}

// TestEnvelopeLegacyAPIsUnchanged verifies that the existing single-recipient
// entry point and its error values are unaffected by the new API.
func TestEnvelopeLegacyAPIsUnchanged(t *testing.T) {
	key := randomKey(t, 16)
	obj, _ := newAESKWMulti(t, [][]byte{key}, []string{"k"})

	enc, err := NewEncrypter(A128GCM, Recipient{Algorithm: A128KW, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	single, err := enc.Encrypt([]byte("single"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := single.Decrypt(key); err != nil || string(got) != "single" {
		t.Fatalf("Decrypt() = (%q, %v), want (single, nil)", got, err)
	}
	if _, err := single.Decrypt(randomKey(t, 16)); err != ErrCryptoFailure {
		t.Fatalf("Decrypt() with wrong key = %v, want ErrCryptoFailure", err)
	}
	if _, _, _, err := obj.DecryptMulti(key); err != nil {
		t.Fatalf("DecryptMulti() = %v, want nil", err)
	}
}

// describeOutcomes renders one line per recipient for test logs, including
// the rotation role each successful key plays.
func describeOutcomes(outcomes []RecipientOutcome) string {
	var b strings.Builder
	b.WriteString("\n")
	for _, ro := range outcomes {
		fmt.Fprintf(&b, "  recipient %d: kid=%q alg=%s", ro.Index, ro.KeyID, ro.Algorithm)
		if ro.OK {
			fmt.Fprintf(&b, " ok used=%q key=%s position=%d\n",
				ro.UsedKeyID, rotationRole(ro.UsedKeyID), ro.UsedKeyPosition)
			continue
		}
		fmt.Fprintf(&b, " failed reason=%s", ro.Failure.Kind)
		if ro.Failure.Detail != "" {
			fmt.Fprintf(&b, " (%s)", ro.Failure.Detail)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// rotationRole maps the key IDs used in these tests to the rotation role they
// model.
func rotationRole(kid string) string {
	switch kid {
	case "current":
		return "current key"
	case "old":
		return "pre-rotation key"
	case "lost":
		return "lost key"
	default:
		return "candidate " + kid
	}
}
