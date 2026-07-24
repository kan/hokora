package main

import (
	"bytes"
	"errors"
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

// **machine(サーバー) の表示名は必須で、制御文字・不正 UTF-8・上限超えを弾く。**
//
// 名前は一覧での唯一の識別子(client_id を出さない #7)なので空を許さない。
// ValidateMachineName は **正規化済み** の値を受け取る前提なので、ここでは
// NormalizeMachineName を通さず直接叩き、制御文字の扱いを厳密に固定する
// (前後空白の除去は TestNormalizeMachineName が見る)。
func TestValidateMachineName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"ascii", "billing-batch", nil},
		{"japanese", "請求バッチ", nil},
		{"japanese with internal space", "請求 バッチ", nil},
		{"ascii with internal space", "app server", nil},
		{"max length", strings.Repeat("a", MaxMachineNameBytes), nil},

		{"empty", "", errMachineNameEmpty},
		{"over max length", strings.Repeat("a", MaxMachineNameBytes+1), errMachineNameTooLong},
		{"internal newline", "line\nbreak", errMachineNameControl},
		{"internal tab", "a\tb", errMachineNameControl},
		{"nul byte", "a\x00b", errMachineNameControl},
		{"escape", "esc\x1bhere", errMachineNameControl},
		{"invalid utf-8", string([]byte{0xff, 0xfe}), errMachineNameControl},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateMachineName(tt.input)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateMachineName(%q) = %v, want %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// **NormalizeMachineName は前後の空白だけを削り、内部の空白と多バイト文字は残す。**
//
// 名前は秘密ではないので MK(ルール13)と違い trim してよい。空白のみの入力は
// 空になり、そのまま検証すると errMachineNameEmpty で弾かれる(必須である)。
func TestNormalizeMachineName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"leading and trailing spaces", "  app  ", "app"},
		{"tabs and newlines", "\tapp\n", "app"},
		{"internal space preserved", "a  b", "a  b"},
		{"multibyte preserved", "請求バッチ", "請求バッチ"},
		{"multibyte with internal space", "請求 バッチ", "請求 バッチ"},
		{"multibyte trimmed", "  請求バッチ  ", "請求バッチ"},
		{"whitespace only", "   ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeMachineName(tt.input); got != tt.want {
				t.Errorf("NormalizeMachineName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}

	// **空白のみは trim で空になり、検証で弾かれる**(呼び出し側の順序を固定)。
	if err := ValidateMachineName(NormalizeMachineName("   ")); !errors.Is(err, errMachineNameEmpty) {
		t.Errorf("whitespace-only name = %v, want errMachineNameEmpty", err)
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
