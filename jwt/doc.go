/*-
 * Copyright 2017 Square Inc.
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

/*
Package jwt provides an implementation of the JSON Web Token standard.

# Remote JWKS

NewRemoteJWKS provides a lazy, caching JWKS provider for third-party signing
keys. It can be passed directly to JSONWebToken.Claims:

	provider, err := jwt.NewRemoteJWKS(jwt.RemoteJWKSConfig{
		Endpoint: "https://issuer.example/.well-known/jwks.json",
	})
	if err != nil {
		return err
	}
	var claims jwt.Claims
	if err := token.Claims(provider, &claims); err != nil {
		return err
	}
	if err := claims.Validate(jwt.Expected{Issuer: "https://issuer.example"}); err != nil {
		return err
	}

NewJWKSResolver configures one isolated provider per issuer. Passing the
resolver to Claims selects the provider from the token's unverified "iss"
claim; the selected key still has to verify the signature. Callers should
still validate the issuer claim with Claims.Validate.

# Cache policy

A key lookup uses a fresh cache without network I/O. A missing kid, or an
expired cache, triggers a refresh and then retries the lookup. Each provider
allows one in-flight HTTP request; concurrent callers wait for and share that
request's result.

The cache lifetime comes from Cache-Control max-age. no-cache and no-store
cause the next lookup to refresh. If max-age is absent or invalid,
RemoteJWKSConfig.DefaultTTL is used; its default is DefaultJWKSCacheTTL
(10 minutes). Successful refreshes merge keys by kid and public-key
fingerprint, retaining still-unexpired old keys during rotation instead of
replacing the complete set.

Each cache entry records its source endpoint. RemoteJWKS.SetEndpoint (or
JWKSResolver.SetEndpoint for one issuer) clears the cache, and a response from
an endpoint which has since been replaced is never installed. Issuers
configured through JWKSResolver also have separate caches, locks, and
in-flight requests.

# Fetch limits and degradation

Only HTTPS endpoints and redirects are accepted. A request must return 200 OK
and a valid public JWKS within RemoteJWKSConfig.MaxResponseBytes (default
DefaultJWKSMaxResponseBytes, 1 MiB). The complete request, including reading
the response body, is bounded by RemoteJWKSConfig.Timeout (default
DefaultJWKSTimeout, 5 seconds).

If a refresh fails while the current cache is still fresh, validation
continues from cache. If the cache is expired, validation rejects the token by
default. RemoteJWKSConfig.StaleIfError (also IssuerJWKSConfig.StaleIfError) can
opt into serving the expired cached key when refresh fails; the default is
false.

Fetch errors are distinguishable with errors.Is against
ErrJWKSInsecureEndpoint, ErrJWKSFetchFailed, ErrJWKSHTTPStatus,
ErrJWKSInvalidResponse, and ErrJWKSResponseTooLarge. A JWKSHTTPStatusError
also exposes the HTTP status code.

When several keys have the same kid, verification tries each key in order. If
all candidates fail, *JWKSVerificationError reports the kid and the number of
attempted keys, and errors.Is(err, jose.ErrCryptoFailure) remains true for
existing callers.

# Observability

RemoteJWKS.Stats and JWKSResolver.Stats expose monotonic counters:

	Fetches          real HTTP requests started
	FetchSuccesses   successful HTTP/JWKS fetches
	RefreshFailures  failed real refreshes (not waiting callers)
	CacheHits        lookups served by a fresh cache
	CacheMisses      lookups which triggered a refresh attempt
	StaleServed      validations served from expired cache via StaleIfError
	LastFetchError   most recent refresh failure text, empty before any failure
*/
package jwt
