// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// A relying party must identify the same user through all three token interfaces.
func TestSubjectConsistentAcrossTokenInterfaces(t *testing.T) {
	who := &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{User: 12345, Name: "user.test.ts.net", Key: key.NewNode().Public(), Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")}},
		UserProfile: &tailcfg.UserProfile{ID: 12345, LoginName: "user@example.com"},
	}
	s := setupTestServer(t, newTestWhoIsClient(t, who, false))
	ar := &AuthRequest{RemoteUser: who, ClientID: "test-client", FunnelRP: s.funnelClients["test-client"], Scopes: []string{"openid", "profile", "email"}}
	tokensRecorder := httptest.NewRecorder()
	s.issueTokens(tokensRecorder, httptest.NewRequest(http.MethodPost, "/token", nil), ar)
	if tokensRecorder.Code != http.StatusOK {
		t.Fatalf("token issuance status = %d", tokensRecorder.Code)
	}
	var tokens oidcTokenResponse
	if err := json.Unmarshal(tokensRecorder.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	token, err := jwt.ParseSigned(tokens.IDToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	var claims jwt.Claims
	if err := token.Claims(oidcTestingPublicKey(t), &claims); err != nil {
		t.Fatalf("ID token signature verification: %v", err)
	}
	if claims.Subject != "userid:12345" {
		t.Fatalf("existing ID token subject changed: %q", claims.Subject)
	}

	userinfoRecorder := httptest.NewRecorder()
	userinfoRequest := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	userinfoRequest.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	s.serveUserInfo(userinfoRecorder, userinfoRequest)
	if userinfoRecorder.Code != http.StatusOK {
		t.Fatalf("userinfo status = %d", userinfoRecorder.Code)
	}
	var userinfo map[string]any
	if err := json.Unmarshal(userinfoRecorder.Body.Bytes(), &userinfo); err != nil {
		t.Fatal(err)
	}
	if userinfo["sub"] != claims.Subject {
		t.Errorf("userinfo sub = %v, signed ID token sub = %q", userinfo["sub"], claims.Subject)
	}

	form := url.Values{"token": {tokens.AccessToken}}
	introspectionRequest := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	introspectionRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introspectionRequest.SetBasicAuth("test-client", "test-secret")
	introspectionRecorder := httptest.NewRecorder()
	s.serveIntrospect(introspectionRecorder, introspectionRequest)
	if introspectionRecorder.Code != http.StatusOK {
		t.Fatalf("introspection status = %d", introspectionRecorder.Code)
	}
	var introspection map[string]any
	if err := json.Unmarshal(introspectionRecorder.Body.Bytes(), &introspection); err != nil {
		t.Fatal(err)
	}
	if introspection["active"] != true {
		t.Fatal("issued token is not active")
	}
	if introspection["sub"] != claims.Subject {
		t.Errorf("introspection sub = %v, signed ID token/userinfo sub = %q", introspection["sub"], claims.Subject)
	}
}
