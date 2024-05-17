// Copyright (c) 2024 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package minisign

import (
	"bytes"
	"encoding/base64"
	"os"
	"strconv"
	"testing"
)

var marshalPrivateKeyTests = []struct {
	ID    uint64
	Bytes []byte
}{
	{
		ID:    htoi("3728470A8118E56E"),
		Bytes: b64("JpjEI/XIKqIVl99tT611AxXwlVjlw2afJC8Nv6o7uuipyNvC3DmgO2csDT+bw1bZR3ss4rd5cXqoq0uftlCJqw=="),
	},
	{
		ID:    htoi("D7E531EE76B2FC6F"),
		Bytes: b64("L24Gi2UbWOb/MBb4MzJLysgC1F1FnE/m72qhb7r5FMlHzHe6M6mCLPMzmj6ln+hI51kqpDqTkIg9VCaToAhZtA=="),
	},
}

func TestPrivateKey_Marshal(t *testing.T) {
	raw, err := os.ReadFile("./internal/testdata/unencrypted.key")
	if err != nil {
		t.Fatalf("Failed to read private key: %v", err)
	}
	raw = bytes.ReplaceAll(raw, []byte{'\r', '\n'}, []byte{'\n'})
	raw = bytes.TrimSuffix(raw, []byte{'\n'})

	keys := bytes.Split(raw, []byte{'\n', '\n'}) // Private keys are separated by a newline
	if len(keys) != len(marshalPrivateKeyTests) {
		t.Fatalf("Test vectors don't match: got %d - want %d", len(marshalPrivateKeyTests), len(keys))
	}
	for i, test := range marshalPrivateKeyTests {
		key := PrivateKey{
			id: test.ID,
		}
		copy(key.bytes[:], test.Bytes)

		text, err := key.MarshalText()
		if err != nil {
			t.Fatalf("Test %d: failed to marshal private key: %v", i, err)
		}
		if !bytes.Equal(text, keys[i]) {
			t.Log(len(text), len(keys[i]))
			t.Log(string(keys[i][len(keys[i])-1]))
			t.Fatalf("Test %d: failed to marshal private key:\nGot: %v\nWant: %v\n", i, text, keys[i])
		}
	}
}

func TestPrivateKey_Unmarshal(t *testing.T) {
	raw, err := os.ReadFile("./internal/testdata/unencrypted.key")
	if err != nil {
		t.Fatalf("Failed to read private key: %v", err)
	}
	raw = bytes.ReplaceAll(raw, []byte{'\r', '\n'}, []byte{'\n'})
	raw = bytes.TrimSuffix(raw, []byte{'\n'})

	keys := bytes.Split(raw, []byte{'\n', '\n'}) // Private keys are separated by a newline
	for _, k := range keys {
		var key PrivateKey
		if err := key.UnmarshalText(k); err != nil {
			t.Fatalf("Failed to unmarshal private key: %v\nPrivate key:\n%s", err, string(k))
		}

		// Print test vector for marshaling:
		// t.Logf("\n{\n\tID: htoi(\"%X\"),\n\tBytes: b64(\"%s\"),\n}", key.id, base64.StdEncoding.EncodeToString(key.bytes[:]))
	}
}

func htoi(s string) uint64 {
	i, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		panic(err)
	}
	return i
}

func b64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
