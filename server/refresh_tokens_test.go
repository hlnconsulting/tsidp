// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRefreshTokenPersistenceAcrossServerRestart(t *testing.T) {
	stateDir := t.TempDir()
	issuedAt := time.Unix(1_700_000_000, 0).UTC()

	s1 := New(nil, stateDir, false, false, false)
	s1.refreshToken["refresh-token"] = &AuthRequest{
		ClientID:  "client-id",
		ValidTill: issuedAt.Add(time.Hour),
		IssuedAt:  issuedAt,
		Resources: []string{"https://resource.example/mcp"},
	}
	s1.mu.Lock()
	if err := s1.storeRefreshTokensLocked(); err != nil {
		s1.mu.Unlock()
		t.Fatalf("store refresh tokens: %v", err)
	}
	s1.mu.Unlock()

	s2 := New(nil, stateDir, false, false, false)
	if err := s2.LoadRefreshTokens(); err != nil {
		t.Fatalf("load refresh tokens: %v", err)
	}

	s2.mu.Lock()
	loaded, ok := s2.refreshToken["refresh-token"]
	s2.mu.Unlock()
	if !ok {
		t.Fatal("refresh token was not restored")
	}
	if loaded.ClientID != "client-id" || !loaded.ValidTill.Equal(issuedAt.Add(time.Hour)) {
		t.Fatalf("restored token metadata = %#v", loaded)
	}
	if len(loaded.Resources) != 1 || loaded.Resources[0] != "https://resource.example/mcp" {
		t.Fatalf("restored resources = %#v", loaded.Resources)
	}

	info, err := os.Stat(filepath.Join(stateDir, refreshTokensFile))
	if err != nil {
		t.Fatalf("stat refresh-token store: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("refresh-token store mode = %o, want 600", got)
	}
}

func TestCleanupExpiredTokensPersistsRefreshTokenDeletion(t *testing.T) {
	stateDir := t.TempDir()
	s := New(nil, stateDir, false, false, false)
	s.refreshToken["expired"] = &AuthRequest{ValidTill: time.Now().Add(-time.Minute)}
	s.refreshToken["valid"] = &AuthRequest{ValidTill: time.Now().Add(time.Hour)}

	s.CleanupExpiredTokens()

	s2 := New(nil, stateDir, false, false, false)
	if err := s2.LoadRefreshTokens(); err != nil {
		t.Fatalf("load refresh tokens after cleanup: %v", err)
	}
	if _, ok := s2.refreshToken["expired"]; ok {
		t.Fatal("expired refresh token was persisted")
	}
	if _, ok := s2.refreshToken["valid"]; !ok {
		t.Fatal("valid refresh token was not persisted")
	}
}
