// Copyright 2026 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Keyring holds AES-256 key-encryption keys by id. The active id encrypts new
// writes; any listed id decrypts, so a rotation is: add the new key, make it
// active, let refreshes re-seal every row, then drop the old id.
//
// Key material enters only through KeyringFromEnv, which reads two NAMED
// environment variables. Nothing in this package names or logs a value.
type Keyring struct {
	active string
	keys   map[string][]byte
}

// NewKeyring validates and copies the keys.
func NewKeyring(active string, keys map[string][]byte) (*Keyring, error) {
	if active == "" || len(keys) == 0 {
		return nil, errors.New("glovo session: keyring needs an active id and a key")
	}
	k := &Keyring{active: active, keys: make(map[string][]byte, len(keys))}
	for id, key := range keys {
		if id == "" || len(key) != 32 {
			return nil, errors.New("glovo session: every key must be 32 bytes with a non-empty id")
		}
		k.keys[id] = append([]byte(nil), key...)
	}
	if _, ok := k.keys[active]; !ok {
		return nil, errors.New("glovo session: active key id is not in the keyring")
	}
	return k, nil
}

// KeyringFromEnv builds a Keyring from two environment variable NAMES:
// idVar holds the active key id, keyVar holds "id=base64key,id2=base64key2".
// The error text names the variables, never their contents.
func KeyringFromEnv(getenv func(string) string, idVar, keyVar string) (*Keyring, error) {
	active, raw := getenv(idVar), getenv(keyVar)
	if active == "" || raw == "" {
		return nil, fmt.Errorf("glovo session: %s and %s must both be set", idVar, keyVar)
	}
	keys := map[string][]byte{}
	for _, part := range splitComma(raw) {
		eq := -1
		for i := 0; i < len(part); i++ {
			if part[i] == '=' {
				eq = i
				break
			}
		}
		if eq <= 0 {
			return nil, fmt.Errorf("glovo session: %s is malformed", keyVar)
		}
		b, err := base64.StdEncoding.DecodeString(part[eq+1:])
		if err != nil {
			return nil, fmt.Errorf("glovo session: %s is malformed", keyVar)
		}
		keys[part[:eq]] = b
	}
	return NewKeyring(active, keys)
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

// ActiveID is the id new writes are sealed under.
func (k *Keyring) ActiveID() string { return k.active }

type payload struct {
	A string `json:"a"`
	R string `json:"r"`
	E int64  `json:"e"`
}

// aad binds a ciphertext to its row: a blob copied to another tenant,
// principal, connection or generation does not authenticate.
func aad(key Key, generation int64, keyID string) []byte {
	return []byte("glovo-session/v1\x00" + key.TenantID + "\x00" + key.PrincipalID + "\x00" +
		key.ConnectionID + "\x00" + strconv.FormatInt(generation, 10) + "\x00" + keyID)
}

// seal returns nonce||ciphertext under the active key.
func (k *Keyring) seal(key Key, generation int64, t Tokens) (keyID string, blob []byte, err error) {
	p, err := json.Marshal(payload{A: t.Access.Reveal(), R: t.Refresh.Reveal(), E: t.AccessExpiresAt.UnixMilli()})
	if err != nil {
		return "", nil, err
	}
	gcm, err := k.gcm(k.active)
	if err != nil {
		return "", nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, err
	}
	return k.active, gcm.Seal(nonce, nonce, p, aad(key, generation, k.active)), nil
}

func (k *Keyring) open(key Key, generation int64, keyID string, blob []byte) (Tokens, error) {
	gcm, err := k.gcm(keyID)
	if err != nil || len(blob) < gcm.NonceSize() {
		return Tokens{}, ErrCorrupt
	}
	plain, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], aad(key, generation, keyID))
	if err != nil {
		return Tokens{}, ErrCorrupt
	}
	var p payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return Tokens{}, ErrCorrupt
	}
	return Tokens{Access: Secret(p.A), Refresh: Secret(p.R), AccessExpiresAt: time.UnixMilli(p.E).UTC()}, nil
}

func (k *Keyring) gcm(id string) (cipher.AEAD, error) {
	raw, ok := k.keys[id]
	if !ok {
		return nil, ErrCorrupt
	}
	b, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
