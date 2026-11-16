package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestDiscover(t *testing.T) {
	type wantFields struct {
		UILocalesSupported bool
	}

	type args struct {
		issuer       string
		wellKnownUrl []string
	}
	tests := []struct {
		name       string
		args       args
		wantFields *wantFields
		wantErr    error
	}{
		{
			name: "spotify", // https://github.com/zitadel/oidc/issues/406
			args: args{
				issuer: "https://accounts.spotify.com",
			},
			wantFields: &wantFields{
				UILocalesSupported: true,
			},
			wantErr: nil,
		},
		{
			name: "discovery failed",
			args: args{
				issuer: "https://example.com",
			},
			wantErr: oidc.ErrDiscoveryFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Discover(context.Background(), tt.args.issuer, http.DefaultClient, tt.args.wellKnownUrl...)
			require.ErrorIs(t, err, tt.wantErr)
			if tt.wantFields == nil {
				return
			}
			assert.Equal(t, tt.args.issuer, got.Issuer)
			if tt.wantFields.UILocalesSupported {
				assert.NotEmpty(t, got.UILocalesSupported)
			}
		})
	}
}

type mockRevokeCaller struct {
	endpoint   string
	httpClient *http.Client
}

func (m *mockRevokeCaller) GetRevokeEndpoint() string {
	return m.endpoint
}

func (m *mockRevokeCaller) HttpClient() *http.Client {
	return m.httpClient
}

type mockEndSessionCaller struct {
	endpoint   string
	httpClient *http.Client
}

func (m *mockEndSessionCaller) GetEndSessionEndpoint() string {
	return m.endpoint
}

func (m *mockEndSessionCaller) HttpClient() *http.Client {
	return m.httpClient
}

type mockDeviceAuthorizationCaller struct {
	endpoint   string
	httpClient *http.Client
}

func (m *mockDeviceAuthorizationCaller) GetDeviceAuthorizationEndpoint() string {
	return m.endpoint
}

func (m *mockDeviceAuthorizationCaller) HttpClient() *http.Client {
	return m.httpClient
}

func TestCallDeviceAuthorizationEndpointOptions(t *testing.T) {
	tests := []struct {
		name    string
		opts    []DeviceAuthorizationOption
		wantJKT string
	}{
		{name: "without options"},
		{name: "with dpop_jkt", opts: []DeviceAuthorizationOption{WithDPoPJKT("thumbprint")}, wantJKT: "thumbprint"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				form     url.Values
				parseErr error
			)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				parseErr = r.ParseForm()
				if parseErr != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				form = r.PostForm
				_, _ = w.Write([]byte("{}"))
			}))
			defer server.Close()

			caller := &mockDeviceAuthorizationCaller{endpoint: server.URL, httpClient: server.Client()}
			request := &oidc.ClientCredentialsRequest{ClientID: "client", Scope: []string{"openid"}}
			_, err := CallDeviceAuthorizationEndpoint(context.Background(), request, caller, nil, tt.opts...)
			require.NoError(t, err)
			require.NoError(t, parseErr)
			assert.Equal(t, "client", form.Get("client_id"))
			assert.Equal(t, "openid", form.Get("scope"))
			assert.Equal(t, tt.wantJKT, form.Get("dpop_jkt"))
		})
	}
}

func TestCallTokenEndpoint_PreservesExtraFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token": "new-access-token",
			"token_type": "Bearer",
			"refresh_token": "new-refresh-token",
			"expires_in": 3600,
			"id_token": "new-id-token",
			"refresh_expires_in": 7200,
			"session_state": "session-1"
		}`))
	}))
	defer server.Close()

	caller := &mockTokenCaller{endpoint: server.URL, httpClient: server.Client()}
	token, err := CallTokenEndpoint(context.Background(), &oidc.RefreshTokenRequest{RefreshToken: "old-refresh-token"}, caller)
	require.NoError(t, err)

	assert.Equal(t, "new-access-token", token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Equal(t, "new-refresh-token", token.RefreshToken)
	assert.Equal(t, "new-id-token", token.Extra("id_token"))
	assert.Equal(t, float64(7200), token.Extra("refresh_expires_in"))
	assert.Equal(t, "session-1", token.Extra("session_state"))
}

func TestCallTokenEndpoint_InvalidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`["not", "an", "object"]`))
	}))
	defer server.Close()

	caller := &mockTokenCaller{endpoint: server.URL, httpClient: server.Client()}
	_, err := CallTokenEndpoint(context.Background(), &oidc.RefreshTokenRequest{RefreshToken: "old-refresh-token"}, caller)
	require.Error(t, err)
}

type mockTokenCaller struct {
	endpoint   string
	httpClient *http.Client
}

func (m *mockTokenCaller) TokenEndpoint() string {
	return m.endpoint
}

func (m *mockTokenCaller) HttpClient() *http.Client {
	return m.httpClient
}

func TestCallRevokeEndpoint_CheckRedirectUnchanged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	customErr := errors.New("custom redirect error")
	customRedirect := func(_ *http.Request, _ []*http.Request) error {
		return customErr
	}

	tests := []struct {
		name          string
		initialClient *http.Client
		checkFn       func(t *testing.T, client *http.Client)
	}{
		{
			name:          "nil CheckRedirect",
			initialClient: &http.Client{CheckRedirect: nil},
			checkFn: func(t *testing.T, client *http.Client) {
				assert.Nil(t, client.CheckRedirect)
			},
		},
		{
			name:          "custom CheckRedirect",
			initialClient: &http.Client{CheckRedirect: customRedirect},
			checkFn: func(t *testing.T, client *http.Client) {
				require.NotNil(t, client.CheckRedirect)
				assert.Equal(t, reflect.ValueOf(customRedirect).Pointer(), reflect.ValueOf(client.CheckRedirect).Pointer())
				assert.ErrorIs(t, client.CheckRedirect(nil, nil), customErr)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caller := &mockRevokeCaller{
				endpoint:   server.URL,
				httpClient: tt.initialClient,
			}
			req := &RevokeRequest{
				Token: "test-token",
			}
			err := CallRevokeEndpoint(context.Background(), req, nil, caller)
			require.NoError(t, err)
			tt.checkFn(t, tt.initialClient)
		})
	}
}

func TestCallEndSessionEndpoint_CheckRedirectUnchanged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/callback", http.StatusFound)
	}))
	defer server.Close()

	customErr := errors.New("custom redirect error")
	customRedirect := func(_ *http.Request, _ []*http.Request) error {
		return customErr
	}

	tests := []struct {
		name          string
		initialClient *http.Client
		checkFn       func(t *testing.T, client *http.Client)
	}{
		{
			name:          "nil CheckRedirect",
			initialClient: &http.Client{CheckRedirect: nil},
			checkFn: func(t *testing.T, client *http.Client) {
				assert.Nil(t, client.CheckRedirect)
			},
		},
		{
			name:          "custom CheckRedirect",
			initialClient: &http.Client{CheckRedirect: customRedirect},
			checkFn: func(t *testing.T, client *http.Client) {
				require.NotNil(t, client.CheckRedirect)
				assert.Equal(t, reflect.ValueOf(customRedirect).Pointer(), reflect.ValueOf(client.CheckRedirect).Pointer())
				assert.ErrorIs(t, client.CheckRedirect(nil, nil), customErr)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caller := &mockEndSessionCaller{
				endpoint:   server.URL,
				httpClient: tt.initialClient,
			}
			req := &oidc.EndSessionRequest{
				IdTokenHint: "test-id-token",
			}
			loc, err := CallEndSessionEndpoint(context.Background(), req, nil, caller)
			require.NoError(t, err)
			require.NotNil(t, loc)
			assert.Equal(t, "https://example.com/callback", loc.String())
			tt.checkFn(t, tt.initialClient)
		})
	}
}

func TestSignedJWTProfileAssertion_JWTID(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	require.NoError(t, err)

	jti := func() string {
		assertion, err := SignedJWTProfileAssertion("client", []string{"https://issuer.example"}, time.Minute, signer)
		require.NoError(t, err)
		var claims oidc.JWTTokenRequest
		_, err = oidc.ParseToken(assertion, &claims)
		require.NoError(t, err)
		return claims.JWTID
	}
	// OpenID Connect Core 1.0, section 9 (private_key_jwt): jti is required
	// and must be unique, so the authorization server can refuse a replay.
	first, second := jti(), jti()
	assert.NotEmpty(t, first)
	assert.NotEqual(t, first, second)
}

// pollStep is one scripted server behaviour for a single poll round.
type pollStep int

const (
	stepPending pollStep = iota
	stepSlowDown
	stepTimeout
	stepAccessDenied
	stepSuccess
)

// pollRound records what the test server observed of one poll request.
type pollRound struct {
	at time.Time // when the request arrived
}

// scriptedDeviceTokenServer answers poll requests following the script, one
// step per round, and records every round it sees.
func scriptedDeviceTokenServer(t *testing.T, script []pollStep) (*httptest.Server, func() []pollRound) {
	t.Helper()
	var (
		mu     sync.Mutex
		rounds []pollRound
		calls  int
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		step := script[min(calls, len(script)-1)]
		calls++
		rounds = append(rounds, pollRound{at: time.Now()})
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch step {
		case stepPending:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
		case stepSlowDown:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"slow_down"}`))
		case stepTimeout:
			// Simulate a token endpoint slower than the per-round request
			// timeout: outlast every per-round timeout used in this test.
			// The client gives up long before this handler returns.
			select {
			case <-r.Context().Done():
			case <-time.After(time.Second):
			}
			return
		case stepAccessDenied:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"access_denied"}`))
		case stepSuccess:
			_, _ = w.Write([]byte(`{"access_token":"poll-token","token_type":"Bearer","expires_in":3600}`))
		}
	}))
	t.Cleanup(server.Close)
	return server, func() []pollRound {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(rounds)
	}
}

func TestPollDeviceAccessTokenEndpointWithAuthFn(t *testing.T) {
	// Shrink the backoff so the table runs in milliseconds; the production
	// default stays the 5 seconds of RFC 8628, section 3.5.
	const (
		initialInterval = 50 * time.Millisecond
		backoff         = 100 * time.Millisecond
		// Tolerance for timer scheduling jitter when comparing durations.
		slop = 30 * time.Millisecond
	)
	restore := devicePollBackoff
	devicePollBackoff = backoff
	t.Cleanup(func() { devicePollBackoff = restore })

	tests := []struct {
		name    string
		script  []pollStep
		wantErr string // oidc error type; empty means the poll must recover a token
	}{
		{
			name:   "authorization_pending keeps the interval",
			script: []pollStep{stepPending, stepPending, stepSuccess},
		},
		{
			name:   "slow_down recovers with one increment",
			script: []pollStep{stepSlowDown, stepSuccess},
		},
		{
			name:   "transport timeout recovers with one increment",
			script: []pollStep{stepTimeout, stepSuccess},
		},
		{
			name: "slow_down and timeout interleave and accumulate",
			script: []pollStep{
				stepPending, stepSlowDown, stepTimeout, stepSlowDown, stepPending, stepSuccess,
			},
		},
		{
			name:    "access_denied aborts polling",
			script:  []pollStep{stepPending, stepAccessDenied},
			wantErr: string(oidc.AccessDenied),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, getRounds := scriptedDeviceTokenServer(t, tt.script)
			caller := &mockTokenCaller{endpoint: server.URL, httpClient: server.Client()}
			req := &DeviceAccessTokenRequest{
				DeviceAccessTokenRequest: oidc.DeviceAccessTokenRequest{
					GrantType:  oidc.GrantTypeDeviceCode,
					DeviceCode: "device-code",
				},
				ClientCredentialsRequest: &oidc.ClientCredentialsRequest{ClientID: "client"},
			}

			resp, err := PollDeviceAccessTokenEndpointWithAuthFn(context.Background(), initialInterval, req, caller, nil)

			rounds := getRounds()
			if tt.wantErr != "" {
				require.Error(t, err)
				var oidcErr *oidc.Error
				require.ErrorAs(t, err, &oidcErr)
				assert.Equal(t, tt.wantErr, string(oidcErr.ErrorType))
				assert.Len(t, rounds, len(tt.script))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "poll-token", resp.AccessToken)
			require.Len(t, rounds, len(tt.script))

			// Expected interval per round: it grows by backoff for every
			// slow_down or transport timeout seen in earlier rounds, and
			// never shrinks.
			expected := make([]time.Duration, len(tt.script))
			interval := initialInterval
			for i, step := range tt.script {
				expected[i] = interval
				if step == stepSlowDown || step == stepTimeout {
					interval += backoff
				}
			}
			for i := 1; i < len(rounds); i++ {
				// Round i arrives after round i-1's request finished — which
				// takes the full per-request timeout on a timeout round —
				// plus the wait of the current interval. The gap therefore
				// proves that the accumulated backoff feeds both the request
				// timeout and the wait between rounds.
				want := expected[i]
				if tt.script[i-1] == stepTimeout {
					want += expected[i-1]
				}
				gap := rounds[i].at.Sub(rounds[i-1].at)
				assert.GreaterOrEqual(t, gap, want-slop, "round %d poll gap (interval monotonic, backoff cumulative)", i)
			}
		})
	}
}

func TestPollDeviceAccessTokenEndpointWithAuthFn_TransportErrorFailsFast(t *testing.T) {
	// A transport failure other than a timeout (here: connection refused on a
	// closed server) is not recoverable and must abort polling immediately.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	endpoint := server.URL
	server.Close()

	caller := &mockTokenCaller{endpoint: endpoint, httpClient: server.Client()}
	req := &DeviceAccessTokenRequest{
		DeviceAccessTokenRequest: oidc.DeviceAccessTokenRequest{
			GrantType:  oidc.GrantTypeDeviceCode,
			DeviceCode: "device-code",
		},
		ClientCredentialsRequest: &oidc.ClientCredentialsRequest{ClientID: "client"},
	}

	start := time.Now()
	_, err := PollDeviceAccessTokenEndpointWithAuthFn(context.Background(), 20*time.Millisecond, req, caller, nil)
	require.Error(t, err)
	// Failing fast means no retry waits: the first round's interval at most.
	assert.Less(t, time.Since(start), 5*time.Second)
	var oidcErr *oidc.Error
	assert.False(t, errors.As(err, &oidcErr), "transport error must not be wrapped as oidc.Error")
}
