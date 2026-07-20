package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestValidateSlug(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		slug string
		ok   bool
	}{
		{"lowercase", "myapp", true},
		{"with hyphen", "app-prod", true},
		{"with digits", "web2", true},
		{"leading digit", "2web", true},
		{"single char", "a", true},
		{"max length", strings.Repeat("a", 64), true},

		{"empty", "", false},
		{"too long", strings.Repeat("a", 65), false},
		{"uppercase", "MyApp", false},
		{"leading hyphen", "-app", false},
		{"underscore", "app_prod", false},
		{"dot", "app.prod", false},
		{"slash", "app/prod", false},
		{"space", "my app", false},
		{"trailing newline", "myapp\n", false},
		{"non-ascii", "アプリ", false},
		{"path traversal", "..", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateSlug(tt.slug)
			if tt.ok && err != nil {
				t.Errorf("ValidateSlug(%q) = %v, want nil", tt.slug, err)
			}
			if !tt.ok && err == nil {
				t.Errorf("ValidateSlug(%q) = nil, want error", tt.slug)
			}
		})
	}
}

func TestValidateItemKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  string
		ok   bool
	}{
		{"typical", "DATABASE_URL", true},
		{"with digit", "API_KEY2", true},
		{"leading underscore", "_INTERNAL", true},
		{"single char", "X", true},
		{"max length", strings.Repeat("A", 128), true},

		{"empty", "", false},
		{"too long", strings.Repeat("A", 129), false},
		{"lowercase", "database_url", false},
		{"leading digit", "2FA_KEY", false},
		{"hyphen", "API-KEY", false},
		{"equals sign", "API=KEY", false},
		{"trailing newline", "API_KEY\n", false},
		{"non-ascii", "キー", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateItemKey(tt.key)
			if tt.ok && err != nil {
				t.Errorf("ValidateItemKey(%q) = %v, want nil", tt.key, err)
			}
			if !tt.ok && err == nil {
				t.Errorf("ValidateItemKey(%q) = nil, want error", tt.key)
			}
		})
	}
}

func TestValidateSecretValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value []byte
		ok    bool
	}{
		{"ascii", []byte("s3cr3t"), true},
		{"empty", []byte{}, true},
		{"nil", nil, true},
		{"utf-8", []byte("パスワード"), true},
		{"newlines", []byte("line1\nline2\n"), true},
		{"max size", bytes.Repeat([]byte("a"), MaxSecretValueBytes), true},

		{"over max size", bytes.Repeat([]byte("a"), MaxSecretValueBytes+1), false},
		{"invalid utf-8", []byte{0xff, 0xfe}, false},
		{"nul byte", []byte("abc\x00def"), false},
		{"trailing nul", []byte("abc\x00"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateSecretValue(tt.value)
			if tt.ok && err != nil {
				t.Errorf("ValidateSecretValue(%s) = %v, want nil", tt.name, err)
			}
			if !tt.ok && err == nil {
				t.Errorf("ValidateSecretValue(%s) = nil, want error", tt.name)
			}
		})
	}
}

// エラーメッセージに secret の値そのものを含めてはならない(AGENTS.md ルール 20)。
func TestValidateSecretValueErrorOmitsValue(t *testing.T) {
	t.Parallel()

	const marker = "sup3rs3cr3t"

	for _, value := range [][]byte{
		append([]byte(marker), 0x00),
		append([]byte(marker), 0xff),
		bytes.Repeat([]byte(marker), MaxSecretValueBytes/len(marker)+1),
	} {
		err := ValidateSecretValue(value)
		if err == nil {
			t.Fatal("expected a validation error")
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("error message leaks the secret value: %v", err)
		}
	}
}
