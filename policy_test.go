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
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// --- test helpers -----------------------------------------------------------

// defaultTestPolicy is the allow set used by tests that need a policy that
// accepts the algorithms produced by the library's own encrypters.
func defaultTestPolicy(t *testing.T) *JWEPolicy {
	t.Helper()
	policy, err := NewJWEPolicy(
		[]KeyAlgorithm{DIRECT, A128KW, A256KW, A128GCMKW, RSA_OAEP_256, ECDH_ES, ECDH_ES_A128KW, PBES2_HS512_A256KW},
		[]ContentEncryption{A128GCM, A256GCM, A128CBC_HS256},
	)
	if err != nil {
		t.Fatalf("NewJWEPolicy: %v", err)
	}
	return policy
}

// mustEncryptJSON builds a valid single-recipient JWE in JSON serialization.
func mustEncryptJSON(t *testing.T, enc ContentEncryption, alg KeyAlgorithm, key any, plaintext []byte) string {
	t.Helper()
	encrypter, err := NewEncrypter(enc, Recipient{Algorithm: alg, Key: key}, nil)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	obj, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return obj.FullSerialize()
}

// mustEncryptCompact builds a valid single-recipient JWE in compact
// serialization.
func mustEncryptCompact(t *testing.T, enc ContentEncryption, alg KeyAlgorithm, key any, plaintext []byte) string {
	t.Helper()
	encrypter, err := NewEncrypter(enc, Recipient{Algorithm: alg, Key: key}, nil)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	obj, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	serialized, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	return serialized
}

// marshalRawJWE re-serializes a modified raw JWE map.
func marshalRawJWE(t *testing.T, raw map[string]any) string {
	t.Helper()
	out, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal raw JWE: %v", err)
	}
	return string(out)
}

// parseJWEJSONToMap parses a JSON-serialized JWE into a generic map so tests
// can tamper with individual header positions.
func parseJWEJSONToMap(t *testing.T, msg string) map[string]any {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal([]byte(msg), &raw); err != nil {
		t.Fatalf("unmarshal JWE: %v", err)
	}
	return raw
}

// decodeProtected decodes the base64url protected header of a JSON JWE map
// into a generic map.
func decodeProtected(t *testing.T, raw map[string]any) map[string]any {
	t.Helper()
	encoded, _ := raw["protected"].(string)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode protected: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(decoded, &header); err != nil {
		t.Fatalf("unmarshal protected: %v", err)
	}
	return header
}

// encodeProtected writes a header map back into the JWE's protected field.
func encodeProtected(t *testing.T, raw map[string]any, header map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal protected: %v", err)
	}
	raw["protected"] = base64.RawURLEncoding.EncodeToString(encoded)
}

func assertErrorIs(t *testing.T, err error, target error, context string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: want error wrapping %v, got %v", context, target, err)
	}
}

// --- policy construction ----------------------------------------------------

func TestNewJWEPolicyRejectsEmptyAndMalformed(t *testing.T) {
	// Hard constraint: empty allow set is a configuration error, never
	// "allow everything".
	if _, err := NewJWEPolicy(nil, []ContentEncryption{A128GCM}); !errors.Is(err, ErrEmptyPolicy) {
		t.Fatalf("empty key algs: want ErrEmptyPolicy, got %v", err)
	}
	if _, err := NewJWEPolicy([]KeyAlgorithm{DIRECT}, nil); !errors.Is(err, ErrEmptyPolicy) {
		t.Fatalf("empty content algs: want ErrEmptyPolicy, got %v", err)
	}
	if _, err := NewJWEPolicy(nil, nil); !errors.Is(err, ErrEmptyPolicy) {
		t.Fatalf("both empty: want ErrEmptyPolicy, got %v", err)
	}

	cases := []struct {
		name string
		algs []KeyAlgorithm
		encs []ContentEncryption
	}{
		{"empty key entry", []KeyAlgorithm{""}, []ContentEncryption{A128GCM}},
		{"empty enc entry", []KeyAlgorithm{DIRECT}, []ContentEncryption{""}},
		{"duplicate key", []KeyAlgorithm{DIRECT, DIRECT}, []ContentEncryption{A128GCM}},
		{"duplicate enc", []KeyAlgorithm{DIRECT}, []ContentEncryption{A128GCM, A128GCM}},
		{"wrong key casing", []KeyAlgorithm{KeyAlgorithm("direct")}, []ContentEncryption{A128GCM}},
		{"wrong enc casing", []KeyAlgorithm{DIRECT}, []ContentEncryption{ContentEncryption("a128gcm")}},
		{"unknown key", []KeyAlgorithm{KeyAlgorithm("BOGUS-KW")}, []ContentEncryption{A128GCM}},
		{"unknown enc", []KeyAlgorithm{DIRECT}, []ContentEncryption{ContentEncryption("BOGUS-GCM")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewJWEPolicy(tc.algs, tc.encs); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("want ErrInvalidPolicy, got %v", err)
			}
		})
	}
}

func TestNilPolicyRejectsEverything(t *testing.T) {
	msg := mustEncryptJSON(t, A128GCM, DIRECT, []byte("0123456789abcdef"), []byte("hi"))
	if _, err := ParseEncryptedWithPolicy(msg, nil); !errors.Is(err, ErrEmptyPolicy) {
		t.Fatalf("nil policy JSON: want ErrEmptyPolicy, got %v", err)
	}
	compact := mustEncryptCompact(t, A128GCM, DIRECT, []byte("0123456789abcdef"), []byte("hi"))
	if _, err := ParseEncryptedCompactWithPolicy(compact, nil); !errors.Is(err, ErrEmptyPolicy) {
		t.Fatalf("nil policy compact: want ErrEmptyPolicy, got %v", err)
	}
}

// --- requirement: algorithm only in an unprotected position ----------------

func TestUnprotectedEncRejected(t *testing.T) {
	policy := defaultTestPolicy(t)
	key := []byte("0123456789abcdef")
	msg := mustEncryptJSON(t, A128GCM, DIRECT, key, []byte("secret payload"))

	raw := parseJWEJSONToMap(t, msg)
	header := decodeProtected(t, raw)

	// Move "enc" out of the protected header into an unprotected position.
	delete(header, "enc")
	encodeProtected(t, raw, header)
	raw["unprotected"] = map[string]any{"enc": string(A128GCM)}
	moved := marshalRawJWE(t, raw)

	_, err := ParseEncryptedJSONWithPolicy(moved, policy)
	assertErrorIs(t, err, ErrUnprotectedAlgorithm, "enc only in unprotected header")
	if !strings.Contains(err.Error(), "unprotected") {
		t.Fatalf("error should point at the unprotected position: %v", err)
	}

	// Same message via the generic dispatcher must be rejected identically.
	_, err = ParseEncryptedWithPolicy(moved, policy)
	assertErrorIs(t, err, ErrUnprotectedAlgorithm, "dispatcher path")
}

func TestUnprotectedAlgRejected(t *testing.T) {
	policy := defaultTestPolicy(t)
	key := []byte("0123456789abcdef")
	msg := mustEncryptJSON(t, A128GCM, DIRECT, key, []byte("secret payload"))

	raw := parseJWEJSONToMap(t, msg)
	header := decodeProtected(t, raw)
	delete(header, "alg")
	encodeProtected(t, raw, header)
	raw["unprotected"] = map[string]any{"alg": string(DIRECT)}
	moved := marshalRawJWE(t, raw)

	_, err := ParseEncryptedJSONWithPolicy(moved, policy)
	assertErrorIs(t, err, ErrUnprotectedAlgorithm, "alg only in unprotected header")
}

func TestUnprotectedDeclarationCannotOverrideProtected(t *testing.T) {
	policy := defaultTestPolicy(t)
	key := []byte("0123456789abcdef")
	msg := mustEncryptJSON(t, A128GCM, DIRECT, key, []byte("secret payload"))

	// A protected, disallowed "enc" must not be bypassed by placing an
	// allowed value in an unprotected position.
	raw := parseJWEJSONToMap(t, msg)
	header := decodeProtected(t, raw)
	header["enc"] = "A192GCM"
	encodeProtected(t, raw, header)
	raw["unprotected"] = map[string]any{"enc": string(A128GCM)}
	tampered := marshalRawJWE(t, raw)

	_, err := ParseEncryptedJSONWithPolicy(tampered, policy)
	if err == nil {
		t.Fatal("tampered message with disallowed protected enc was accepted")
	}
	if errors.Is(err, ErrUnprotectedAlgorithm) {
		// Acceptable: the unprotected duplicate is itself forbidden.
		return
	}
	assertErrorIs(t, err, ErrAlgorithmNotAllowed, "unprotected value must not override protected value")
}

// --- requirement: missing/empty/unrecognized content encryption -------------

func TestMissingEmptyUnknownEnc(t *testing.T) {
	policy := defaultTestPolicy(t)
	key := []byte("0123456789abcdef")
	msg := mustEncryptJSON(t, A128GCM, DIRECT, key, []byte("secret"))

	t.Run("missing enc", func(t *testing.T) {
		raw := parseJWEJSONToMap(t, msg)
		header := decodeProtected(t, raw)
		delete(header, "enc")
		encodeProtected(t, raw, header)
		_, err := ParseEncryptedJSONWithPolicy(marshalRawJWE(t, raw), policy)
		assertErrorIs(t, err, ErrUnprotectedAlgorithm, "missing enc")
	})

	t.Run("empty enc", func(t *testing.T) {
		raw := parseJWEJSONToMap(t, msg)
		header := decodeProtected(t, raw)
		header["enc"] = ""
		encodeProtected(t, raw, header)
		_, err := ParseEncryptedJSONWithPolicy(marshalRawJWE(t, raw), policy)
		assertErrorIs(t, err, ErrUnprotectedAlgorithm, "empty enc")
	})

	t.Run("unknown enc", func(t *testing.T) {
		raw := parseJWEJSONToMap(t, msg)
		header := decodeProtected(t, raw)
		header["enc"] = "NOT-A-REAL-ENC"
		encodeProtected(t, raw, header)
		_, err := ParseEncryptedJSONWithPolicy(marshalRawJWE(t, raw), policy)
		assertErrorIs(t, err, ErrUnknownAlgorithm, "unknown enc")
	})

	t.Run("unknown alg is separate category", func(t *testing.T) {
		raw := parseJWEJSONToMap(t, msg)
		header := decodeProtected(t, raw)
		header["alg"] = "NOT-A-REAL-ALG"
		encodeProtected(t, raw, header)
		_, err := ParseEncryptedJSONWithPolicy(marshalRawJWE(t, raw), policy)
		assertErrorIs(t, err, ErrUnknownAlgorithm, "unknown alg")
		if errors.Is(err, ErrUnsupportedKeyType) || errors.Is(err, ErrInvalidKeySize) {
			t.Fatalf("unknown alg must not be reported as a key error: %v", err)
		}
	})
}

// --- requirement: unauthenticated encryption rejected -----------------------

func TestMissingIntegrityTagRejected(t *testing.T) {
	policy := defaultTestPolicy(t)
	key := []byte("0123456789abcdef")
	msg := mustEncryptJSON(t, A128GCM, DIRECT, key, []byte("secret"))

	raw := parseJWEJSONToMap(t, msg)
	raw["tag"] = ""
	noTag := marshalRawJWE(t, raw)

	_, err := ParseEncryptedJSONWithPolicy(noTag, policy)
	assertErrorIs(t, err, ErrUnauthenticatedEncryption, "empty tag")
}

// --- requirement: key-wrap strength vs actual key length --------------------

func TestKeyStrengthMismatchRejected(t *testing.T) {
	policy := defaultTestPolicy(t)

	// A128KW claims 128-bit strength; hand it a 256-bit key.
	shortKey := bytes.Repeat([]byte{0x42}, 16)
	longKey := bytes.Repeat([]byte{0x43}, 32)
	msg := mustEncryptJSON(t, A128GCM, A128KW, shortKey, []byte("secret"))

	obj, err := ParseEncryptedJSONWithPolicy(msg, policy)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	_, err = obj.HardenedDecrypt(policy, longKey)
	assertErrorIs(t, err, ErrKeyStrengthMismatch, "A128KW with 256-bit key")
	if !strings.Contains(err.Error(), "128") || !strings.Contains(err.Error(), "256") {
		t.Fatalf("error should report both declared and actual strength: %v", err)
	}

	// dir mode: key length must match the content encryption key size.
	directMsg := mustEncryptJSON(t, A256GCM, DIRECT, bytes.Repeat([]byte{0x44}, 32), []byte("secret"))
	directObj, err := ParseEncryptedJSONWithPolicy(directMsg, policy)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	_, err = directObj.HardenedDecrypt(policy, bytes.Repeat([]byte{0x45}, 16))
	assertErrorIs(t, err, ErrKeyStrengthMismatch, "dir with wrong length key")
}

// --- requirement: same key used for signature and key management ------------

func TestSignatureUseKeyRejected(t *testing.T) {
	policy := defaultTestPolicy(t)
	keyBytes := bytes.Repeat([]byte{0x46}, 16)
	msg := mustEncryptJSON(t, A128GCM, A128KW, keyBytes, []byte("secret"))
	obj, err := ParseEncryptedJSONWithPolicy(msg, policy)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	signingJWK := JSONWebKey{Key: keyBytes, Use: "sig"}
	_, err = obj.HardenedDecrypt(policy, signingJWK)
	assertErrorIs(t, err, ErrKeyUseConflict, "sig-marked JWK for key management")

	// The same key material without a conflicting use still works.
	encJWK := JSONWebKey{Key: keyBytes, Use: "enc"}
	plaintext, err := obj.HardenedDecrypt(policy, encJWK)
	if err != nil {
		t.Fatalf("enc-marked JWK should be accepted: %v", err)
	}
	if string(plaintext) != "secret" {
		t.Fatalf("plaintext = %q, want %q", plaintext, "secret")
	}
}

// --- requirement: algorithm/key type mismatch, separate category ------------

func TestKeyTypeMismatchRejected(t *testing.T) {
	policy := defaultTestPolicy(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	symKey := bytes.Repeat([]byte{0x47}, 16)

	// Asymmetric RSA-OAEP-256 message, decrypt with a symmetric key.
	rsaMsg := mustEncryptJSON(t, A128GCM, RSA_OAEP_256, &rsaKey.PublicKey, []byte("secret"))
	rsaObj, err := ParseEncryptedJSONWithPolicy(rsaMsg, policy)
	if err != nil {
		t.Fatalf("parse rsa: %v", err)
	}
	_, err = rsaObj.HardenedDecrypt(policy, symKey)
	assertErrorIs(t, err, ErrKeyTypeMismatch, "symmetric key for RSA alg")
	if errors.Is(err, ErrUnsupportedKeyType) || errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("type mismatch must not collapse into a key error: %v", err)
	}

	// Symmetric A128KW message, decrypt with an asymmetric EC key.
	symMsg := mustEncryptJSON(t, A128GCM, A128KW, symKey, []byte("secret"))
	symObj, err := ParseEncryptedJSONWithPolicy(symMsg, policy)
	if err != nil {
		t.Fatalf("parse sym: %v", err)
	}
	_, err = symObj.HardenedDecrypt(policy, ecKey)
	assertErrorIs(t, err, ErrKeyTypeMismatch, "EC key for symmetric alg")

	// Ed25519 keys are signature-only; pairing is a type mismatch.
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = symObj.HardenedDecrypt(policy, edPriv)
	assertErrorIs(t, err, ErrKeyTypeMismatch, "ed25519 private key for JWE")
	_ = edPub
}

// --- requirement: weak algorithms blocked even when allowed -----------------

func TestWeakAlgorithmsBlockedEvenWhenAllowed(t *testing.T) {
	// RSA1_5 is deprecated; a policy can name it, but it must still be
	// rejected at message time.
	policy, err := NewJWEPolicy([]KeyAlgorithm{RSA1_5, RSA_OAEP}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatalf("NewJWEPolicy: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	msg := mustEncryptJSON(t, A128GCM, RSA1_5, &rsaKey.PublicKey, []byte("secret"))
	_, err = ParseEncryptedJSONWithPolicy(msg, policy)
	assertErrorIs(t, err, ErrWeakAlgorithm, "deprecated RSA1_5")

	// RSA-OAEP uses a 160-bit digest, below the 256-bit floor.
	oaepMsg := mustEncryptJSON(t, A128GCM, RSA_OAEP, &rsaKey.PublicKey, []byte("secret"))
	_, err = ParseEncryptedJSONWithPolicy(oaepMsg, policy)
	assertErrorIs(t, err, ErrWeakAlgorithm, "RSA-OAEP SHA-1 digest")
}

// --- requirement: x5c chain key capability vs cipher suite ------------------

func TestCertificateChainMismatchRejected(t *testing.T) {
	policy, err := NewJWEPolicy([]KeyAlgorithm{ECDH_ES}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatalf("NewJWEPolicy: %v", err)
	}

	// Build a chain whose leaf carries an RSA key, while ECDH-ES needs EC.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rsa-leaf"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	x5c := base64.StdEncoding.EncodeToString(der)

	msg := mustEncryptJSON(t, A128GCM, ECDH_ES, mustECPublicKey(t), []byte("secret"))
	raw := parseJWEJSONToMap(t, msg)
	raw["unprotected"] = map[string]any{"x5c": []string{x5c}}
	withChain := marshalRawJWE(t, raw)

	_, err = ParseEncryptedJSONWithPolicy(withChain, policy)
	assertErrorIs(t, err, ErrKeyTypeMismatch, "RSA x5c key for ECDH-ES")
}

func TestMalformedCertificateChainIsOwnCategory(t *testing.T) {
	policy := defaultTestPolicy(t)
	msg := mustEncryptJSON(t, A128GCM, DIRECT, bytes.Repeat([]byte{0x48}, 16), []byte("secret"))
	raw := parseJWEJSONToMap(t, msg)
	raw["unprotected"] = map[string]any{"x5c": []string{"not-a-certificate!!"}}
	withBadChain := marshalRawJWE(t, raw)

	_, err := ParseEncryptedJSONWithPolicy(withBadChain, policy)
	assertErrorIs(t, err, ErrCertificateChain, "malformed x5c chain")
	if errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("chain parse failure must not be conflated with an algorithm failure: %v", err)
	}
}

// --- requirement: identical decision across serializations ------------------

func TestCompactAndJSONReachSameDecision(t *testing.T) {
	policy := defaultTestPolicy(t)
	key := bytes.Repeat([]byte{0x49}, 16)
	plaintext := []byte("serialization parity")

	compact := mustEncryptCompact(t, A128GCM, DIRECT, key, plaintext)
	jsonMsg := mustEncryptJSON(t, A128GCM, DIRECT, key, plaintext)

	// Both accepted, both decrypt to the same plaintext.
	compactObj, err := ParseEncryptedCompactWithPolicy(compact, policy)
	if err != nil {
		t.Fatalf("compact parse: %v", err)
	}
	jsonObj, err := ParseEncryptedJSONWithPolicy(jsonMsg, policy)
	if err != nil {
		t.Fatalf("json parse: %v", err)
	}
	compactPlain, err := compactObj.HardenedDecrypt(policy, key)
	if err != nil {
		t.Fatalf("compact decrypt: %v", err)
	}
	jsonPlain, err := jsonObj.HardenedDecrypt(policy, key)
	if err != nil {
		t.Fatalf("json decrypt: %v", err)
	}
	if !bytes.Equal(compactPlain, jsonPlain) || !bytes.Equal(compactPlain, plaintext) {
		t.Fatalf("plaintext mismatch: %q vs %q", compactPlain, jsonPlain)
	}

	// The unprotected-enc attack is representable only in JSON; compact has
	// no unprotected position, and an enc-less compact message must fail
	// with the same category.
	raw := parseJWEJSONToMap(t, jsonMsg)
	header := decodeProtected(t, raw)
	delete(header, "enc")
	encodeProtected(t, raw, header)
	raw["unprotected"] = map[string]any{"enc": string(A128GCM)}
	movedJSON := marshalRawJWE(t, raw)
	_, jsonErr := ParseEncryptedJSONWithPolicy(movedJSON, policy)
	assertErrorIs(t, jsonErr, ErrUnprotectedAlgorithm, "json unprotected enc")

	parts := strings.Split(compact, ".")
	protectedDecoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var protected map[string]any
	if err := json.Unmarshal(protectedDecoded, &protected); err != nil {
		t.Fatal(err)
	}
	delete(protected, "enc")
	parts[0] = base64.RawURLEncoding.EncodeToString(mustJSONBytes(t, protected))
	brokenCompact := strings.Join(parts, ".")
	_, compactErr := ParseEncryptedCompactWithPolicy(brokenCompact, policy)
	assertErrorIs(t, compactErr, ErrUnprotectedAlgorithm, "compact missing enc")
}

// --- requirement: allow list constrains both alg and enc --------------------

func TestAllowListConstrainsAlgAndEnc(t *testing.T) {
	policy, err := NewJWEPolicy([]KeyAlgorithm{DIRECT}, []ContentEncryption{A256GCM})
	if err != nil {
		t.Fatalf("NewJWEPolicy: %v", err)
	}

	// Allowed enc but alg not in the key-management set.
	key16 := bytes.Repeat([]byte{0x4a}, 16)
	msg := mustEncryptJSON(t, A128GCM, A128KW, key16, []byte("secret"))
	_, err = ParseEncryptedJSONWithPolicy(msg, policy)
	assertErrorIs(t, err, ErrAlgorithmNotAllowed, "alg outside allow set")

	// Allowed alg but enc not in the content set.
	key32 := bytes.Repeat([]byte{0x4b}, 32)
	msg = mustEncryptJSON(t, A128GCM, DIRECT, key16, []byte("secret"))
	_, err = ParseEncryptedJSONWithPolicy(msg, policy)
	assertErrorIs(t, err, ErrAlgorithmNotAllowed, "enc outside allow set")

	// Both in set passes.
	okMsg := mustEncryptJSON(t, A256GCM, DIRECT, key32, []byte("secret"))
	if _, err := ParseEncryptedJSONWithPolicy(okMsg, policy); err != nil {
		t.Fatalf("fully allowed message rejected: %v", err)
	}
}

// --- hard constraint: no algorithm fallback/downgrade -----------------------

func TestNoDowngradeOnRejectedAlgorithm(t *testing.T) {
	policy := defaultTestPolicy(t)
	key := bytes.Repeat([]byte{0x4c}, 16)
	msg := mustEncryptJSON(t, A128GCM, DIRECT, key, []byte("secret"))

	// Tamper the protected alg from "dir" to "ECDH-ES+A128KW". Both are in
	// the allow set, so this is not an allow-list failure. If the library
	// ever fell back to another allow-listed algorithm (here, "dir", which
	// matches the symmetric key), the message could decrypt; the typed
	// key-class check on the *declared* alg must fire instead.
	raw := parseJWEJSONToMap(t, msg)
	header := decodeProtected(t, raw)
	header["alg"] = "ECDH-ES+A128KW"
	encodeProtected(t, raw, header)

	obj, err := ParseEncryptedJSONWithPolicy(marshalRawJWE(t, raw), policy)
	if err != nil {
		t.Fatalf("message should parse; the declared alg is allow-listed: %v", err)
	}
	_, err = obj.HardenedDecrypt(policy, key)
	assertErrorIs(t, err, ErrKeyTypeMismatch, "declared alg must be evaluated as-is, never replaced by another allow-listed alg")
}

func TestNoDowngradeUnknownAlgNeverRetried(t *testing.T) {
	policy := defaultTestPolicy(t)
	key := bytes.Repeat([]byte{0x4c}, 16)
	msg := mustEncryptJSON(t, A128GCM, DIRECT, key, []byte("secret"))

	raw := parseJWEJSONToMap(t, msg)
	header := decodeProtected(t, raw)
	header["alg"] = "MYSTERY-ALG"
	encodeProtected(t, raw, header)

	_, err := ParseEncryptedJSONWithPolicy(marshalRawJWE(t, raw), policy)
	assertErrorIs(t, err, ErrUnknownAlgorithm, "unknown alg rejected outright, no retries")
}

// --- hard constraint: rejection output leaks nothing ------------------------

func TestRejectionErrorsDoNotLeakSensitiveMaterial(t *testing.T) {
	policy := defaultTestPolicy(t)
	secretPlaintext := []byte("TOP-SECRET-PLAINTEXT")
	key := bytes.Repeat([]byte{0x4d}, 16)
	msg := mustEncryptJSON(t, A128GCM, DIRECT, key, secretPlaintext)

	raw := parseJWEJSONToMap(t, msg)
	header := decodeProtected(t, raw)
	delete(header, "enc")
	encodeProtected(t, raw, header)
	raw["unprotected"] = map[string]any{"enc": string(A128GCM)}

	_, err := ParseEncryptedJSONWithPolicy(marshalRawJWE(t, raw), policy)
	if err == nil {
		t.Fatal("expected rejection")
	}
	message := err.Error()
	forbidden := []string{string(secretPlaintext), base64.RawURLEncoding.EncodeToString(key), string(key)}
	for _, leak := range forbidden {
		if strings.Contains(message, leak) {
			t.Fatalf("rejection error leaks %q: %v", leak, err)
		}
	}
}

// --- happy path through the hardened API ------------------------------------

func TestHardenedDecryptRoundTrip(t *testing.T) {
	policy := defaultTestPolicy(t)
	key := bytes.Repeat([]byte{0x4e}, 16)
	plaintext := []byte("hello hardened world")

	for _, msg := range []string{
		mustEncryptJSON(t, A128GCM, DIRECT, key, plaintext),
		mustEncryptCompact(t, A128GCM, DIRECT, key, plaintext),
	} {
		obj, err := ParseEncryptedWithPolicy(msg, policy)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		out, err := obj.HardenedDecrypt(policy, key)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(out, plaintext) {
			t.Fatalf("plaintext = %q, want %q", out, plaintext)
		}
	}
}

// --- multi-recipient rejection ----------------------------------------------

func TestMultiRecipientRejectedByPolicy(t *testing.T) {
	policy := defaultTestPolicy(t)
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encrypter, err := NewMultiEncrypter(A128GCM,
		[]Recipient{
			{Algorithm: RSA_OAEP_256, Key: &rsaKey1.PublicKey},
			{Algorithm: RSA_OAEP_256, Key: &rsaKey2.PublicKey},
		}, nil)
	if err != nil {
		t.Fatalf("NewMultiEncrypter: %v", err)
	}
	obj, err := encrypter.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, err = ParseEncryptedJSONWithPolicy(obj.FullSerialize(), policy)
	assertErrorIs(t, err, ErrUnsupportedMultiRecipient, "multi-recipient")
}

// --- small helpers ----------------------------------------------------------

func mustECPublicKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &key.PublicKey
}

func mustJSONBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
