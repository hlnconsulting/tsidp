// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const refreshTokensFile = "oidc-refresh-tokens.json"

// getRefreshTokensPath returns the path to the persisted refresh-token store.
func (s *IDPServer) getRefreshTokensPath() string {
	if s.stateDir != "" {
		return filepath.Join(s.stateDir, refreshTokensFile)
	}
	return refreshTokensFile
}

// LoadRefreshTokens loads refresh tokens from the configured state directory.
// A missing file is treated as an empty store for first startup.
func (s *IDPServer) LoadRefreshTokens() error {
	if s.stateDir == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := os.ReadFile(s.getRefreshTokensPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var tokens map[string]*AuthRequest
	if err := json.Unmarshal(b, &tokens); err != nil {
		return fmt.Errorf("decode refresh tokens: %w", err)
	}
	if tokens == nil {
		tokens = make(map[string]*AuthRequest)
	}
	s.refreshToken = tokens
	return nil
}

// storeRefreshTokensLocked persists refresh tokens to the configured state
// directory. The caller must hold s.mu. A temporary file and rename prevent a
// restart from observing a partially written JSON document.
func (s *IDPServer) storeRefreshTokensLocked() error {
	if s.stateDir == "" {
		return nil
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(s.refreshToken); err != nil {
		return fmt.Errorf("encode refresh tokens: %w", err)
	}

	path := s.getRefreshTokensPath()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".oidc-refresh-tokens-*.tmp")
	if err != nil {
		return fmt.Errorf("create refresh-token temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("set refresh-token permissions: %w", err)
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return fmt.Errorf("write refresh tokens: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync refresh tokens: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close refresh-token temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace refresh-token store: %w", err)
	}
	return nil
}
