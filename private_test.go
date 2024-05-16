// Copyright (c) 2024 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package minisign

import (
	"bytes"
	"os"
	"testing"
)

func TestPrivateKey_Unmarshal(t *testing.T) {
	raw, err := os.ReadFile("./internal/testdata/minisign_unencrypted.key")
	if err != nil {
		t.Fatalf("Failed to read private key: %v", err)
	}

	keys := bytes.Split(raw, []byte("\n\n")) // Private keys are separated by a newline
	for _, k := range keys {
		var key PrivateKey
		if err := key.UnmarshalText(k); err != nil {
			t.Fatalf("Failed to unmarshal private key: %v\nPrivate key:\n%s", err, string(k))
		}
	}
}
