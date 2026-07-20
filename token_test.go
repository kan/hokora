package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

var tokenBase = time.Unix(1700000000, 0)

// newTestToken は決まった内容のトークンを作る(内容そのものに意味はない)。
func newTestToken(t *testing.T, fill byte) []byte {
	t.Helper()
	return bytes.Repeat([]byte{fill}, TokenBytes)
}

func TestGenerateTokenIsRandom(t *testing.T) {
	t.Parallel()

	const iterations = 64
	seen := make(map[string]struct{}, iterations)
	for range iterations {
		raw, encoded, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		if len(raw) != TokenBytes {
			t.Fatalf("raw token length = %d, want %d", len(raw), TokenBytes)
		}
		// 運用者や HTTP ヘッダを通るので、パディングや改行を含まない。
		if bytes.ContainsAny([]byte(encoded), "=+/\r\n ") {
			t.Fatalf("encoded token contains an unexpected character: %q", encoded)
		}
		if _, dup := seen[encoded]; dup {
			t.Fatal("GenerateToken repeated a value")
		}
		seen[encoded] = struct{}{}
	}
}

// DecodeToken は「store の lookup に到達させる前に形式を落とす」入口である。
// ここが緩むと、長さも符号化も違う値で無駄な計算をさせられる口が残る。
func TestDecodeToken(t *testing.T) {
	t.Parallel()

	raw, encoded, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	// 43 文字目(最後)は余り 2 ビットが 0 でなければならない。'B' は
	// index 1 なので非正規表現になる。Strict() でなければ黙って通る。
	zeroToken := base64.RawURLEncoding.EncodeToString(make([]byte, TokenBytes))
	nonCanonical := zeroToken[:len(zeroToken)-1] + "B"

	tests := []struct {
		name    string
		encoded string
		want    []byte // nil なら ErrInvalidToken を期待する
	}{
		{"valid", encoded, raw},
		{"empty", "", nil},
		{"padded", base64.URLEncoding.EncodeToString(raw), nil},
		{"standard base64 alphabet", "+/" + encoded[2:], nil},
		{"too short", base64.RawURLEncoding.EncodeToString(make([]byte, TokenBytes-1)), nil},
		{"too long", base64.RawURLEncoding.EncodeToString(make([]byte, TokenBytes+1)), nil},
		{"non-canonical trailing bits", nonCanonical, nil},
		{"leading space", " " + encoded, nil},
		{"not base64 at all", "not a token!", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := DecodeToken(tt.encoded)
			if tt.want == nil {
				if !errors.Is(err, ErrInvalidToken) {
					t.Fatalf("DecodeToken(%q) = (%x, %v), want ErrInvalidToken", tt.encoded, got, err)
				}
				if got != nil {
					t.Errorf("DecodeToken returned %x along with an error", got)
				}
				// エラーにトークンの中身が混ざらない(AGENTS.md ルール 20)。
				if tt.encoded != "" && strings.Contains(err.Error(), tt.encoded) {
					t.Errorf("error = %v, want it not to echo the input", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeToken(%q): %v", tt.encoded, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("DecodeToken = %x, want %x", got, tt.want)
			}
		})
	}
}

// **改行入りのトークンは拒否する。**
//
// encoding/base64 のデコーダは入力中の CR / LF をスキップする(Strict() が
// 見るのは末尾の余りビットだけ)。DecodeMasterKey はこれを知っていて明示的に
// 弾いており(crypto.go)、DecodeToken にも同じ手当てが要る。片方だけ直すと、
// 同じ罠が別の場所に残る(AGENTS.md 冒頭の教訓)。
//
// 直ちに危険ではない(攻撃者が既に持っているトークンの別表現が通るだけ)が、
// 1 つのトークンに複数の表現が存在する状態そのものを作らない。
func TestDecodeTokenRejectsNewlines(t *testing.T) {
	t.Parallel()

	_, encoded, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	for _, in := range []string{
		encoded + "\n",
		encoded + "\r\n",
		encoded[:10] + "\n" + encoded[10:],
		"\n" + encoded,
	} {
		if got, err := DecodeToken(in); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("DecodeToken(%q) = (%x, %v), want ErrInvalidToken", in, got, err)
		}
	}
}

// DecodeToken を通した値がそのまま Lookup に使えること(往復の確認)。
func TestDecodeTokenRoundTripsThroughStore(t *testing.T) {
	t.Parallel()

	raw, encoded, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	s := newTokenStore(16)
	if err := s.Add(raw, 9, tokenBase.Add(TokenTTL), tokenBase); err != nil {
		t.Fatalf("Add: %v", err)
	}

	decoded, err := DecodeToken(encoded)
	if err != nil {
		t.Fatalf("DecodeToken: %v", err)
	}
	if id, ok := s.Lookup(decoded, tokenBase); !ok || id != 9 {
		t.Fatalf("Lookup = (%d, %v), want (9, true)", id, ok)
	}
}

func TestTokenStoreAddAndLookup(t *testing.T) {
	t.Parallel()

	s := newTokenStore(16)
	raw := newTestToken(t, 0x01)
	expires := tokenBase.Add(TokenTTL)

	if err := s.Add(raw, 42, expires, tokenBase); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, ok := s.Lookup(raw, tokenBase)
	if !ok || got != 42 {
		t.Fatalf("Lookup = (%d, %v), want (42, true)", got, ok)
	}
	// 別のトークンは当たらない。
	if _, ok := s.Lookup(newTestToken(t, 0x02), tokenBase); ok {
		t.Error("Lookup matched an unknown token")
	}
	// 1 バイト違いも当たらない。
	if _, ok := s.Lookup(flipByte(raw, 0), tokenBase); ok {
		t.Error("Lookup matched a modified token")
	}
}

// **期限は Lookup が検査する。** sweep を一度も呼ばない状態で確認する
// (sweep に期限判定を任せていないことの検証。DESIGN §7.1)。
func TestTokenStoreLookupChecksExpiryWithoutSweep(t *testing.T) {
	t.Parallel()

	s := newTokenStore(16)
	raw := newTestToken(t, 0x03)
	expires := tokenBase.Add(TokenTTL)

	if err := s.Add(raw, 7, expires, tokenBase); err != nil {
		t.Fatalf("Add: %v", err)
	}

	tests := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"before expiry", expires.Add(-time.Nanosecond), true},
		{"at expiry", expires, false},
		{"after expiry", expires.Add(time.Second), false},
		{"long after expiry", expires.Add(24 * time.Hour), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := s.Lookup(raw, tt.now); ok != tt.want {
				t.Errorf("Lookup at %v = %v, want %v", tt.now, ok, tt.want)
			}
		})
	}

	// 期限切れでも sweep するまで map には残っている(掃除と期限判定は別)。
	if s.Len() != 1 {
		t.Errorf("Len = %d, want 1 (sweep has not run)", s.Len())
	}
	if n := s.Sweep(expires.Add(time.Second)); n != 1 {
		t.Errorf("Sweep removed %d entries, want 1", n)
	}
	if s.Len() != 0 {
		t.Errorf("Len = %d after sweep, want 0", s.Len())
	}
}

func TestTokenStoreDeleteByMachine(t *testing.T) {
	t.Parallel()

	s := newTokenStore(16)
	expires := tokenBase.Add(TokenTTL)

	a1, a2 := newTestToken(t, 0x10), newTestToken(t, 0x11)
	b1 := newTestToken(t, 0x20)
	for _, tok := range [][]byte{a1, a2} {
		if err := s.Add(tok, 1, expires, tokenBase); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	if err := s.Add(b1, 2, expires, tokenBase); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if n := s.DeleteByMachine(1); n != 2 {
		t.Errorf("DeleteByMachine removed %d, want 2", n)
	}
	for _, tok := range [][]byte{a1, a2} {
		if _, ok := s.Lookup(tok, tokenBase); ok {
			t.Error("a token of the revoked machine is still valid")
		}
	}
	// 他の machine のトークンは巻き込まれない。
	if _, ok := s.Lookup(b1, tokenBase); !ok {
		t.Error("a token of another machine was deleted")
	}
	// 存在しない machine の削除は 0 件で、エラーにもならない。
	if n := s.DeleteByMachine(999); n != 0 {
		t.Errorf("DeleteByMachine(999) removed %d, want 0", n)
	}
}

func TestTokenStoreClear(t *testing.T) {
	t.Parallel()

	s := newTokenStore(16)
	raw := newTestToken(t, 0x30)
	if err := s.Add(raw, 1, tokenBase.Add(TokenTTL), tokenBase); err != nil {
		t.Fatalf("Add: %v", err)
	}

	s.Clear()

	if s.Len() != 0 {
		t.Errorf("Len = %d after Clear, want 0", s.Len())
	}
	if _, ok := s.Lookup(raw, tokenBase); ok {
		t.Error("a token survived Clear")
	}
	// Clear 後も使える(map を nil にしていない)。
	if err := s.Add(raw, 1, tokenBase.Add(TokenTTL), tokenBase); err != nil {
		t.Fatalf("Add after Clear: %v", err)
	}
}

// 上限に達したら、まず期限切れを掃除し、それでも空かなければ最も古いものを
// 追い出す。**新しい発行を拒否しない**(拒否すると、上限まで発行するだけで
// 正規の machine を締め出せてしまう)。
func TestTokenStoreEnforcesMax(t *testing.T) {
	t.Parallel()

	t.Run("expired entries are reclaimed first", func(t *testing.T) {
		t.Parallel()

		s := newTokenStore(2)
		expired := newTestToken(t, 0x40)
		live := newTestToken(t, 0x41)
		if err := s.Add(expired, 1, tokenBase.Add(time.Minute), tokenBase); err != nil {
			t.Fatalf("Add: %v", err)
		}
		if err := s.Add(live, 2, tokenBase.Add(time.Hour), tokenBase); err != nil {
			t.Fatalf("Add: %v", err)
		}

		now := tokenBase.Add(30 * time.Minute) // expired だけが期限切れ
		fresh := newTestToken(t, 0x42)
		if err := s.Add(fresh, 3, now.Add(TokenTTL), now); err != nil {
			t.Fatalf("Add: %v", err)
		}

		if s.Len() != 2 {
			t.Errorf("Len = %d, want 2 (max)", s.Len())
		}
		if _, ok := s.Lookup(live, now); !ok {
			t.Error("a live token was evicted while an expired one remained")
		}
		if _, ok := s.Lookup(fresh, now); !ok {
			t.Error("the new token was not stored")
		}
	})

	t.Run("oldest live entry is evicted", func(t *testing.T) {
		t.Parallel()

		s := newTokenStore(2)
		oldest := newTestToken(t, 0x50)
		newer := newTestToken(t, 0x51)
		if err := s.Add(oldest, 1, tokenBase.Add(time.Hour), tokenBase); err != nil {
			t.Fatalf("Add: %v", err)
		}
		if err := s.Add(newer, 2, tokenBase.Add(2*time.Hour), tokenBase); err != nil {
			t.Fatalf("Add: %v", err)
		}

		fresh := newTestToken(t, 0x52)
		if err := s.Add(fresh, 3, tokenBase.Add(3*time.Hour), tokenBase); err != nil {
			t.Fatalf("Add: %v", err)
		}

		if s.Len() != 2 {
			t.Fatalf("Len = %d, want 2", s.Len())
		}
		if _, ok := s.Lookup(oldest, tokenBase); ok {
			t.Error("the oldest token was not evicted")
		}
		for _, tok := range [][]byte{newer, fresh} {
			if _, ok := s.Lookup(tok, tokenBase); !ok {
				t.Error("a newer token was evicted instead of the oldest")
			}
		}
	})

	t.Run("re-adding an existing token does not evict", func(t *testing.T) {
		t.Parallel()

		s := newTokenStore(1)
		raw := newTestToken(t, 0x60)
		if err := s.Add(raw, 1, tokenBase.Add(time.Hour), tokenBase); err != nil {
			t.Fatalf("Add: %v", err)
		}
		if err := s.Add(raw, 2, tokenBase.Add(2*time.Hour), tokenBase); err != nil {
			t.Fatalf("Add (same token): %v", err)
		}
		if s.Len() != 1 {
			t.Errorf("Len = %d, want 1", s.Len())
		}
		// 再登録は上書きである。machine ID も期限も新しい値になる
		// (古い entry が残ると、失効済み machine のトークンが生き延びる)。
		id, ok := s.Lookup(raw, tokenBase.Add(90*time.Minute))
		if !ok {
			t.Fatal("the re-added token expired at the old expiry")
		}
		if id != 2 {
			t.Errorf("machine id = %d, want 2 (the re-added value)", id)
		}
	})
}

// ErrTokenStoreFull は「追い出す相手すらいない」場合に返る。
func TestTokenStoreFull(t *testing.T) {
	t.Parallel()

	s := newTokenStore(-1) // 既定値にフォールバックすること
	if s.max != defaultMaxTokens {
		t.Fatalf("max = %d, want %d", s.max, defaultMaxTokens)
	}

	// max = 0 は newTokenStore が既定値に倒すため作れない。内部状態を直接
	// 作って、追い出せない状況を再現する。
	empty := &tokenStore{tokens: map[[32]byte]tokenInfo{}, max: 0}
	err := empty.Add(newTestToken(t, 0x70), 1, tokenBase.Add(TokenTTL), tokenBase)
	if !errors.Is(err, ErrTokenStoreFull) {
		t.Fatalf("error = %v, want ErrTokenStoreFull", err)
	}
}

// 生のトークンを保持していないこと。map の key は SHA-256 ハッシュである。
func TestTokenStoreDoesNotKeepRawTokens(t *testing.T) {
	t.Parallel()

	s := newTokenStore(16)
	raw := newTestToken(t, 0x80)
	if err := s.Add(raw, 1, tokenBase.Add(TokenTTL), tokenBase); err != nil {
		t.Fatalf("Add: %v", err)
	}

	var key [32]byte
	for k := range s.tokens {
		key = k
	}
	if bytes.Equal(key[:], raw) {
		t.Error("the raw token is used as the map key")
	}

	// 呼び出し側がトークンをゼロクリアしても、store の内容は壊れない
	// (Add がハッシュを取ってからコピーを持たないことの確認)。
	lookup := bytes.Clone(raw)
	Zero(raw)
	if _, ok := s.Lookup(lookup, tokenBase); !ok {
		t.Error("Lookup failed after the caller zeroed its own buffer")
	}
}
