package main

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// 各構造体の時刻フィールドは、DB では Unix 秒(INTEGER)として保存される。
// 変換は store 層で行う。

// Project は secret の最上位のまとまりである。
type Project struct {
	ID        int64
	Slug      string
	Name      string
	DeletedAt *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Environment は Project 配下の環境(prod / stg 等)である。
// machine への grant はこの単位で与える。
type Environment struct {
	ID        int64
	ProjectID int64
	Slug      string
	Name      string
	DeletedAt *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Item は Environment 配下の 1 つの secret である。値は ItemVersion が持つ。
//
// コメント / メモ欄は持たない(THREAT_MODEL §8.2。自由記述欄には必ず秘密が書かれる)。
type Item struct {
	ID             int64
	EnvironmentID  int64
	Key            string
	CurrentVersion int64
	DeletedAt      *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ItemVersion は Item の 1 バージョンの暗号化された値である。追記専用。
type ItemVersion struct {
	ItemID     int64
	Version    int64
	ValueEnc   []byte
	Nonce      []byte
	DEKVersion int64
	CreatedAt  time.Time
	CreatedBy  string
}

// User は Web UI にログインする人間である。ロールは admin のみ。
// 削除は Disabled で行い、deleted_at は持たない(監査ログの actor 参照を保つ)。
type User struct {
	ID           int64
	Username     string
	PasswordHash string // argon2id、PHC 文字列形式
	MustChangePW bool
	Disabled     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Session は Web UI のログインセッションである。
// TokenHash は SHA-256(生トークン)。生トークンは保存しない。
type Session struct {
	TokenHash  []byte
	UserID     int64
	CreatedAt  time.Time
	ExpiresAt  time.Time // 絶対期限
	LastSeenAt time.Time // idle 期限の判定用
	RemoteAddr string
}

// Machine は Machine API を利用するクライアント(アプリケーションサーバー)である。
// SecretHash は SHA-256(client_secret)。client_secret は高エントロピーな
// crypto/rand 由来の値に限られるため、argon2 は使わない(DESIGN §7.1)。
type Machine struct {
	ID         int64
	ClientID   string
	SecretHash []byte
	Name       string
	Disabled   bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
	LastAuthAt *time.Time
}

// MachineGrant は Machine が読める Environment を表す。物理 DELETE を許可する。
type MachineGrant struct {
	MachineID     int64
	EnvironmentID int64
	CreatedAt     time.Time
}

// Keyring は暗号化された DEK を保持する。行は常に 1 行のみ。
type Keyring struct {
	DEKWrapped []byte
	DEKNonce   []byte
	KDFSalt    []byte
	DEKVersion int64
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// ---- バリデーション ----

// MaxSecretValueBytes は secret 値の最大バイト数である(DESIGN §5.3)。
const MaxSecretValueBytes = 64 << 10

// MaxMachineNameBytes は machine(サーバー) 表示名の最大バイト数である。
const MaxMachineNameBytes = 200

// slug は URL パス(/ui/projects/{slug})にそのまま載る。大文字小文字の同一視や
// パス記号の解釈で混乱しないよう、英小文字・数字・ハイフンに限る。
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// key は環境変数名として展開されうるため、POSIX の変数名として安全な文字に限る。
var itemKeyPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// secret 値そのものはエラーメッセージに絶対に含めない(AGENTS.md ルール 20)。
var (
	errSecretValueTooLarge = fmt.Errorf("secret value exceeds %d bytes", MaxSecretValueBytes)
	errSecretValueNotUTF8  = errors.New("secret value is not valid UTF-8")
	errSecretValueHasNUL   = errors.New("secret value contains a NUL byte")
)

// machine 名は秘密ではないため、エラーに値は含めない方針だけ揃える。
var (
	errMachineNameEmpty   = errors.New("machine name is required")
	errMachineNameTooLong = fmt.Errorf("machine name exceeds %d bytes", MaxMachineNameBytes)
	errMachineNameControl = errors.New("machine name is not valid UTF-8 or contains control characters")
)

// NormalizeMachineName は前後の空白を除いた machine(サーバー) 表示名を返す。
//
// 名前は秘密ではないので、MK(ルール13)と違い trim してよい。
func NormalizeMachineName(name string) string {
	return strings.TrimSpace(name)
}

// ValidateMachineName は machine(サーバー) の表示名を検証する。
//
// **名前は必須である。** 一覧では client_id を出さず、名前が唯一の識別子に
// なるため(#7)。監査ログには machine の immutable ID を記録し name は入れない
// ため(ルール24/25)、文字種は緩く許すが、表示やログ整形を乱す制御文字は拒否する。
// 呼び出し側は NormalizeMachineName で trim した値を渡すこと。
func ValidateMachineName(name string) error {
	if name == "" {
		return errMachineNameEmpty
	}
	if len(name) > MaxMachineNameBytes {
		return errMachineNameTooLong
	}
	if !utf8.ValidString(name) {
		return errMachineNameControl
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errMachineNameControl
		}
	}
	return nil
}

// validatePattern は識別子を正規表現で検証する。slug / key は秘密ではないため、
// 直せるようにエラーへ値とパターンを含める。
func validatePattern(kind, value string, pattern *regexp.Regexp) error {
	if !pattern.MatchString(value) {
		return fmt.Errorf("invalid %s %q: must match %s", kind, value, pattern)
	}
	return nil
}

// ValidateSlug は project / environment の slug を検証する。
func ValidateSlug(slug string) error {
	return validatePattern("slug", slug, slugPattern)
}

// ValidateItemKey は item の key を検証する。
func ValidateItemKey(key string) error {
	return validatePattern("key", key, itemKeyPattern)
}

// ValidateSecretValue は secret の平文を検証する(DESIGN §5.3)。
//
// エラーには値を含めない。空の値は許可する(空文字を持つ環境変数は正当なため)。
func ValidateSecretValue(value []byte) error {
	if len(value) > MaxSecretValueBytes {
		return errSecretValueTooLarge
	}
	if !utf8.Valid(value) {
		// JSON にエンコードするため、有効な UTF-8 であることを要求する。
		return errSecretValueNotUTF8
	}
	// 環境変数として展開するため、NUL バイトを許可しない。
	if bytes.IndexByte(value, 0x00) >= 0 {
		return errSecretValueHasNUL
	}
	return nil
}
