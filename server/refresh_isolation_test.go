// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

func refreshIsolationServer(t *testing.T) *IDPServer {
	t.Helper()
	s := setupTestServer(t, nil)
	s.refreshToken = make(map[string]*AuthRequest)
	for _, token := range []string{"session-a", "session-b"} {
		s.refreshToken[token] = &AuthRequest{
			ClientID: "test-client", FunnelRP: s.funnelClients["test-client"],
			ValidTill: time.Now().Add(time.Hour),
			Resources: []string{"https://resource.example/mcp"},
			RemoteUser: &apitype.WhoIsResponse{
				Node:        &tailcfg.Node{ID: 1, Name: "test.example.ts.net", User: tailcfg.UserID(1)},
				UserProfile: &tailcfg.UserProfile{LoginName: "synthetic@example.com"},
			},
		}
	}
	return s
}

func refreshRequest(s *IDPServer, token, secret, resource string) *httptest.ResponseRecorder {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}
	if resource != "" {
		form.Set("resource", resource)
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("test-client", secret)
	rr := httptest.NewRecorder()
	s.serveToken(rr, req)
	return rr
}

func TestRejectedRefreshPreservesLegitimateSession(t *testing.T) {
	for _, tc := range []struct{ name, secret, resource string }{
		{"wrong secret", "synthetic-wrong-secret", ""},
		{"invalid resource", "test-secret", "not-a-resource"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := refreshIsolationServer(t)
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
			defer slog.SetDefault(previous)
			rejected := refreshRequest(s, "session-a", tc.secret, tc.resource)
			if rejected.Code == http.StatusOK {
				t.Fatal("invalid refresh accepted")
			}
			if strings.Contains(rejected.Body.String(), "synthetic-wrong-secret") {
				t.Fatal("response exposed client secret")
			}
			if strings.Contains(logs.String(), "synthetic-wrong-secret") || strings.Contains(logs.String(), "session-a") {
				t.Fatal("rejection log exposed credentials")
			}
			if !strings.Contains(logs.String(), "refresh rejected") {
				t.Fatal("missing refresh rejection diagnostic at default log level")
			}
			if _, ok := s.refreshToken["session-a"]; !ok {
				t.Fatal("rejected request consumed legitimate refresh token")
			}
			if got := refreshRequest(s, "session-a", "test-secret", ""); got.Code != http.StatusOK {
				t.Fatalf("legitimate retry status %d", got.Code)
			}
		})
	}
}

func TestConcurrentRefreshHasOneWinnerAndPreservesOtherSession(t *testing.T) {
	s := refreshIsolationServer(t)
	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 2)
	start := make(chan struct{})
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; results <- refreshRequest(s, "session-a", "test-secret", "") }()
	}
	close(start)
	wg.Wait()
	close(results)
	success, rejected := 0, 0
	for rr := range results {
		switch rr.Code {
		case http.StatusOK:
			success++
			var token oidcTokenResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &token); err != nil {
				t.Fatal(err)
			}
			if _, ok := s.refreshToken[token.RefreshToken]; !ok {
				t.Fatal("winner's refresh token missing")
			}
		case http.StatusBadRequest:
			rejected++
		default:
			t.Fatalf("unexpected status %d", rr.Code)
		}
	}
	if success != 1 || rejected != 1 {
		t.Fatalf("success=%d rejected=%d", success, rejected)
	}
	if got := refreshRequest(s, "session-b", "test-secret", ""); got.Code != http.StatusOK {
		t.Fatalf("other session status %d", got.Code)
	}
}
