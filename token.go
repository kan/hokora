package main

import (
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

// TokenBytes は machine token の長さである。crypto/rand 由来の 32 バイトなので、
// 検証は SHA-256 で足りる(DESIGN §7.1。argon2 は DoS 増幅器にしかならない)。
const TokenBytes = 32

// TokenTTL はトークンの有効期限である。更新機構は持たない(DESIGN §7.1)。
const TokenTTL = 15 * time.Minute

// defaultMaxTokens はメモリ上に保持するトークン数の上限である。
//
// 上限は「メモリ枯渇を防ぐ」ためのものであって、「制限を保証する」ものでは
// ない(DESIGN §7.4)。
const defaultMaxTokens = 4096

var (
	// ErrTokenStoreFull はトークンを追加できないことを示す。
	ErrTokenStoreFull = errors.New("token store is full")
	// ErrInvalidToken はトークンの形式が不正であることを示す。
	// 値は返さない(AGENTS.md ルール 20)。
	ErrInvalidToken = errors.New("invalid token")
)

// tokenInfo はトークン 1 件の情報である。生のトークンは保持しない。
type tokenInfo struct {
	machineID int64
	expiresAt time.Time
}

// tokenStore は machine token を **SHA-256 ハッシュのまま** 保持する
// (AGENTS.md ルール 46 と同じ理由。bearer credential を平文で持たない)。
//
// map の lookup key に暗号学的ハッシュを使うのは、秘密同士の比較とは別問題
// であり、ConstantTimeCompare の対象ではない(AGENTS.md ルール 4)。ハッシュ値が
// 一致した時点で元のトークンが一致しており、比較で分岐する余地がない。
//
// **ロックの取得順序は Vault.mu → tokenStore.mu で固定する**(C7)。
// tokenStore は Vault を参照しない。この向きを崩さないこと。
type tokenStore struct {
	mu     sync.Mutex
	tokens map[[32]byte]tokenInfo
	max    int
}

func newTokenStore(maxTokens int) *tokenStore {
	if maxTokens <= 0 {
		maxTokens = defaultMaxTokens
	}
	return &tokenStore{
		tokens: make(map[[32]byte]tokenInfo),
		max:    maxTokens,
	}
}

// GenerateToken は新しいトークンを生成し、生の値と base64url 表現を返す。
func GenerateToken() (raw []byte, encoded string, err error) {
	return generateRandomToken(TokenBytes)
}

// DecodeToken は base64url のトークンを生バイト列に戻す。
//
// 長さが違うものはここで落とす。**存在しないトークンとして扱うのではなく
// 形式エラーにする**のは、store の lookup に到達させないためである
// (到達させても害はないが、無駄な計算をさせる口を残さない)。
func DecodeToken(encoded string) ([]byte, error) {
	raw, ok := decodeFixedLengthToken(encoded, TokenBytes)
	if !ok {
		return nil, ErrInvalidToken
	}
	return raw, nil
}

// Add はトークンを登録する。
//
// 上限に達している場合は、まず期限切れを掃除し、それでも空かなければ
// **最も早く期限が切れるものを追い出す**。全トークンの TTL は同じなので、
// これは最も古い発行を落とすことと同じである。新しい発行を拒否する方式だと、
// 攻撃者が上限まで発行するだけで正規の machine を締め出せてしまう。
func (s *tokenStore) Add(raw []byte, machineID int64, expiresAt time.Time, now time.Time) error {
	h := sha256.Sum256(raw)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tokens[h]; !exists && len(s.tokens) >= s.max {
		s.sweepLocked(now)
		if len(s.tokens) >= s.max {
			if !s.evictOldestLocked() {
				return ErrTokenStoreFull
			}
		}
	}
	s.tokens[h] = tokenInfo{machineID: machineID, expiresAt: expiresAt}
	return nil
}

// Lookup はトークンに対応する machine ID を返す。
//
// **期限は必ずここで検査する。** sweep はメモリの掃除であって認証上の期限判定
// ではない(DESIGN §7.1)。sweep だけに頼ると、sweep 間隔のぶんトークンが
// 余分に使えてしまう。
//
// なお、これは認証の確認にすぎない。machine の disabled、grant、祖先の
// deleted_at は、リクエストごとに別途再検査する(DESIGN §4.5)。
func (s *tokenStore) Lookup(raw []byte, now time.Time) (int64, bool) {
	h := sha256.Sum256(raw)

	s.mu.Lock()
	defer s.mu.Unlock()

	info, ok := s.tokens[h]
	if !ok || !now.Before(info.expiresAt) {
		return 0, false
	}
	return info.machineID, true
}

// DeleteByMachine は当該 machine のトークンを全て削除し、削除件数を返す。
//
// credential 再発行・無効化時の唯一の遮断手段である(DESIGN §7.5)。
// **呼び出しは Vault の write lock 内で行うこと**(C8)。そうしないと、
// 削除の直後に、旧 credential で進行中だった発行がすり抜ける。
func (s *tokenStore) DeleteByMachine(machineID int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for h, info := range s.tokens {
		if info.machineID == machineID {
			delete(s.tokens, h)
			n++
		}
	}
	return n
}

// Clear は全トークンを破棄する。Seal() から呼ぶ(C5)。
func (s *tokenStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = make(map[[32]byte]tokenInfo)
}

// Sweep は期限切れのトークンを削除し、削除件数を返す。
// これはメモリの掃除であり、期限判定は Lookup が行う。
func (s *tokenStore) Sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepLocked(now)
}

// Len は保持しているトークン数を返す(テストと運用の観測用)。
func (s *tokenStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens)
}

func (s *tokenStore) sweepLocked(now time.Time) int {
	n := 0
	for h, info := range s.tokens {
		if !now.Before(info.expiresAt) {
			delete(s.tokens, h)
			n++
		}
	}
	return n
}

// evictOldestLocked は最も早く期限が切れるトークンを 1 件削除する。
func (s *tokenStore) evictOldestLocked() bool {
	var (
		oldest  [32]byte
		oldestT time.Time
		found   bool
	)
	for h, info := range s.tokens {
		if !found || info.expiresAt.Before(oldestT) {
			oldest, oldestT, found = h, info.expiresAt, true
		}
	}
	if found {
		delete(s.tokens, oldest)
	}
	return found
}
