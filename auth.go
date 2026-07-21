package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ClientSecretBytes は client_secret の長さである。
//
// **client_secret はサーバーが crypto/rand で生成したものに限る**
// (AGENTS.md ルール 8)。ユーザーによる指定・インポートを許す API / 画面を
// 実装してはならない。これは「検証に SHA-256 を使ってよい」というルール 7 が
// 成立するための不変条件である。低エントロピーな値が混ざった瞬間、
// SHA-256 では守れなくなる。
const ClientSecretBytes = 32

var (
	// ErrInvalidCredentials は認証に失敗したことを示す。
	//
	// **client_id 不在と secret 不一致を区別しない**(DESIGN §8.1)。
	// 区別すると、有効な client_id の一覧を作れてしまう。
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrForbidden は認可されていないことを示す。grant なし・論理削除済み・
	// 存在しないのいずれもこれに潰す(AGENTS.md ルール 54)。
	ErrForbidden = errors.New("forbidden")
)

// dummySecretHash は存在しない client_id に対する比較相手である。
//
// 実在しない client_id でも同じだけ比較を行い、応答時間で存在を漏らさない
// (AGENTS.md ルール 21)。値そのものに意味はない。
var dummySecretHash = sha256.Sum256([]byte("hokora/dummy-secret/v1"))

// GenerateClientSecret は client_secret を生成し、生の値と保存用ハッシュを返す。
//
// crypto/rand 由来の 32 バイトなので、保存は SHA-256 で足りる(DESIGN §7.1)。
// argon2 を使うと、未認証で高頻度に呼べる経路に 64 MB × 数百 ms を持ち込む
// ことになり、DoS 増幅器にしかならない。
func GenerateClientSecret() (encoded string, hash []byte, err error) {
	raw, err := randomBytes(ClientSecretBytes)
	if err != nil {
		return "", nil, err
	}
	defer Zero(raw)

	// **ハッシュを取るのは、クライアントが実際に提示する文字列に対してである。**
	// 生バイト列に対して取ると、検証側(提示された文字列をハッシュする)と
	// 食い違い、正しい credential でも認証が通らない。エントロピーは
	// エンコードしても変わらない。
	encoded = base64.RawURLEncoding.EncodeToString(raw)
	return encoded, hashClientSecret(encoded), nil
}

// clientIDLen は自動生成する client_id の長さである(base32 小文字 20 文字)。
//
// **slug 制約 ^[a-z0-9][a-z0-9-]{0,63}$ に収まる。** base32 の文字集合は
// a-z2-7 で、全て slug の許可文字である。20 文字で 100 ビットの乱数から
// 作るので、UNIQUE 制約に対する衝突は事実上起きない。
const clientIDLen = 20

// clientIDRandomBytes は 20 文字を得るのに必要な乱数バイト数である。
// 13 バイト = 104 ビットを base32 化すると 21 文字になり、先頭 20 文字を使う。
const clientIDRandomBytes = 13

// GenerateClientID はサーバー側で client_id を生成する。
//
// **client_id は machine を識別するための公開値である**(secret とは違い、
// 常時表示してよい)。ユーザーに決めさせず自動生成するのは、命名の一貫性を
// 保ち、既存 ID との重複や打ち間違いを避けるためである。
func GenerateClientID() (string, error) {
	raw, err := randomBytes(clientIDRandomBytes)
	if err != nil {
		return "", err
	}
	defer Zero(raw)

	// 小文字の base32(a-z2-7)にする。大文字や記号を含む base64url とは違い、
	// これはそのまま slug として通る。
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	return encoded[:clientIDLen], nil
}

// hashClientSecret は提示された client_secret のハッシュを計算する。
func hashClientSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// verifyMachineCredentials は client_id / client_secret を検証し、machine を返す。
//
// **存在しない client_id でも必ず比較を行う。** 早期 return すると、応答時間の
// 差から「その client_id は存在する」ことが分かる。
//
// disabled な machine も、存在しない場合と同じエラーに潰す。
func verifyMachineCredentials(ctx context.Context, q querier, clientID, secret string) (*Machine, error) {
	machine, err := FindMachineByClientID(ctx, q, clientID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		// DB 障害。認証は通さない。
		return nil, err
	}

	want := dummySecretHash[:]
	if machine != nil {
		want = machine.SecretHash
	}
	// 生の秘密由来の digest 同士の比較なので定数時間で行う(AGENTS.md ルール 4)。
	ok := constantTimeEqual(hashClientSecret(secret), want)

	switch {
	case machine == nil, !ok, machine.Disabled:
		return nil, ErrInvalidCredentials
	default:
		return machine, nil
	}
}

// ---- machine の管理 ----
//
// 管理画面(M5)から呼ばれるが、**C8 の competition はここで決まる**ので
// M4 で実装し、テストで性質を固定する。

// CreateMachine は machine を作り、生成した client_secret を返す。
//
// **client_secret は戻り値でしか渡らない。** 保存されるのは SHA-256 の
// ハッシュだけなので、呼び出し側がここで表示しなければ二度と取り出せない。
//
// 監査は fail closed(作成はセキュリティを下げる方向の操作である)。
func CreateMachine(ctx context.Context, db *sql.DB, clientID, name string, ac auditCtx) (id int64, secret string, err error) {
	secret, hash, err := GenerateClientSecret()
	if err != nil {
		return 0, "", err
	}

	err = withTx(ctx, db, func(tx *sql.Tx) error {
		at := ac.Now.Unix()
		res, err := tx.ExecContext(ctx, `
			INSERT INTO machines (client_id, secret_hash, name, disabled, created_at, updated_at)
			VALUES (?, ?, ?, 0, ?, ?)`, clientID, hash, name, at, at)
		if err != nil {
			return fmt.Errorf("insert machine: %w", err)
		}
		if id, err = res.LastInsertId(); err != nil {
			return fmt.Errorf("insert machine: %w", err)
		}
		// fail closed: 監査が書けなければ machine も作らない。
		return RecordAudit(ctx, tx, ac.machineEntry(ActionMachineCreate, id))
	})
	if err != nil {
		return 0, "", err
	}
	return id, secret, nil
}

// DisableMachine は machine を無効化し、そのトークンを全て失効させる(C8)。
//
// **「DB 更新 → トークン削除」を Vault の write lock 内で実行する。**
// 分けると、旧 credential で進行中だった発行が削除をすり抜け、無効化後も
// 最大 15 分トークンが生き残る(DESIGN §4.4)。
//
// **監査は fail open。** 緊急遮断操作を監査 DB の障害で止めてはならない
// (THREAT_MODEL §10.4)。本体(DB 更新とトークン削除)が失敗した場合は
// エラーを返す。「DB 更新失敗を無視する」という意味ではない。
func DisableMachine(ctx context.Context, v *Vault, machineID int64, ac auditCtx) error {
	return revokeMachine(ctx, v, machineID, ac, ActionMachineDisable,
		`UPDATE machines SET disabled = 1, updated_at = ? WHERE id = ?`, ac.Now.Unix(), machineID)
}

// RotateMachineSecret は client_secret を再発行し、旧トークンを失効させる(C8)。
//
// **これは「漏洩したから回す」操作である。** まさに攻撃者が旧 credential を
// 持っている状況で実行されるため、発行のすり抜けが起きると緩和策そのものが
// 破れる。DisableMachine と同じく write lock 内で完結させる。
//
// **監査は fail open**(漏洩対応の緊急操作である)。
func RotateMachineSecret(ctx context.Context, v *Vault, machineID int64, ac auditCtx) (secret string, err error) {
	secret, hash, err := GenerateClientSecret()
	if err != nil {
		return "", err
	}

	err = revokeMachine(ctx, v, machineID, ac, ActionMachineRotateSecret,
		`UPDATE machines SET secret_hash = ?, updated_at = ? WHERE id = ?`, hash, ac.Now.Unix(), machineID)
	if err != nil {
		return "", err
	}
	return secret, nil
}

// revokeMachine は「DB 更新 → トークン削除」を write lock 内で実行する(C8)。
//
// **DisableMachine と RotateMachineSecret で共通の骨格である。** 同型の
// 競合に対する同型の対処なので、片方だけ直る余地を残さない
// (AGENTS.md の教訓「原則を立てたら、全ての適用箇所を点検する」)。
//
// 監査は fail open。緊急遮断操作を監査 DB の障害で止めてはならない。
// 本体(DB 更新とトークン削除)の失敗はエラーとして返す。
func revokeMachine(ctx context.Context, v *Vault, machineID int64, ac auditCtx, action Action, query string, args ...any) error {
	return v.WithWriteLock(func(tokens *tokenStore) error {
		res, err := v.db.ExecContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("%s: %w", action, err)
		}
		if err := requireOneRow(res, "machine"); err != nil {
			return err
		}

		tokens.DeleteByMachine(machineID)

		RecordAuditBestEffort(ctx, v.db, v.logger, ac.machineEntry(action, machineID))
		return nil
	})
}

// requireOneRow は UPDATE が 1 行に当たったことを確かめる。
func requireOneRow(res sql.Result, what string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if n != 1 {
		return fmt.Errorf("%s: %w", what, ErrNotFound)
	}
	return nil
}

// ---- 認可の再検査(DESIGN §4.5) ----

// authorizeEnvironment は「このトークンでこの environment を読んでよいか」を
// 毎リクエスト検査する。
//
// **トークンは認証の証明であって、認可の証明ではない。** 発行時に通った
// ことは、いま通ることを意味しない。以下を毎回読み直す:
//
//   - machine が disabled になっていないか
//   - project / environment が論理削除されていないか
//   - 対象 environment への grant が残っているか
//
// トークンの期限は tokenStore.Lookup が検査する(sweep に依存しない)。
//
// **失敗の理由を呼び出し側に区別させない。** 「grant が無い」と「論理削除
// 済み」と「存在しない」を分けると、そこから存在情報が漏れる。
func authorizeEnvironment(ctx context.Context, db *sql.DB, machineID int64, projectSlug, envSlug string) (*EnvironmentRef, error) {
	active, err := MachineIsActive(ctx, db, machineID)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, ErrForbidden
	}

	ref, err := ResolveEnvironment(ctx, db, projectSlug, envSlug)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrForbidden
	}
	if err != nil {
		return nil, err
	}

	granted, err := HasGrant(ctx, db, machineID, ref.EnvironmentID)
	if err != nil {
		return nil, err
	}
	if !granted {
		return nil, ErrForbidden
	}
	return ref, nil
}

// machineAudit は machine が actor である監査コンテキストを作る。
func machineAudit(machineID int64, remoteAddr string, now time.Time) auditCtx {
	return auditCtx{
		Actor:          actorMachine(machineID),
		ActorMachineID: &machineID,
		RemoteAddr:     &remoteAddr,
		Now:            now,
	}
}

// anonymousAudit は認証されていない主体の監査コンテキストを作る。
//
// **生の client_id は入れない**(DESIGN §5.5)。相関が要るときは
// detail.subject_digest を使う。
func anonymousAudit(remoteAddr string, now time.Time) auditCtx {
	return auditCtx{Actor: ActorAnonymous, RemoteAddr: &remoteAddr, Now: now}
}
