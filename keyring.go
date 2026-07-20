package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// InitialDEKVersion は最初の DEK に与えるバージョンである。
// DEK のローテーション(DESIGN §6.8)で増える。
const InitialDEKVersion = 1

// NewKeyring は DEK を生成し、MK から導出した KEK でラップした keyring を返す
// (DESIGN §6.3)。
//
// 返り値の dek は unsealed 状態の Vault が保持するものであり、呼び出し側が
// 責任を持って Zero する。MK は呼び出し側が保持したままである(この関数は
// 消さない)。KEK はこの関数の中で使い切り、必ず消す。
//
// now を引数で受けるのは、テストから時刻を固定できるようにするためである。
func NewKeyring(mk []byte, now time.Time) (kr *Keyring, dek []byte, err error) {
	salt, err := randomBytes(kdfSaltBytes)
	if err != nil {
		return nil, nil, err
	}

	dek, err = GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	// 以降で失敗したら DEK は誰にも渡らないので、その場で消す。
	defer func() {
		if err != nil {
			Zero(dek)
			dek = nil
		}
	}()

	wrapped, nonce, err := wrapDEK(mk, salt, dek)
	if err != nil {
		return nil, nil, err
	}

	at := now.UTC().Truncate(time.Second)
	return &Keyring{
		DEKWrapped: wrapped,
		DEKNonce:   nonce,
		KDFSalt:    salt,
		DEKVersion: InitialDEKVersion,
		CreatedAt:  at,
		UpdatedAt:  at,
	}, dek, nil
}

// UnwrapDEK は MK から KEK を導出し、keyring の DEK を取り出す。
//
// **MK の検証はここで行われる**(DESIGN §6.3)。誤った MK から導出した KEK では
// GCM の認証タグ検証が失敗するので、ErrDecrypt が返る。KEK は使い切って消す。
//
// 返り値の DEK は呼び出し側が Zero する。
func (k *Keyring) UnwrapDEK(mk []byte) ([]byte, error) {
	kek, err := DeriveKEK(mk, k.KDFSalt)
	if err != nil {
		return nil, fmt.Errorf("derive kek: %w", err)
	}
	defer Zero(kek)

	dek, err := openBytes(kek, k.DEKNonce, k.DEKWrapped, keyringAAD())
	if err != nil {
		return nil, err
	}
	if len(dek) != MasterKeyBytes {
		// ラップされていたのが DEK でない。DB の取り違えや復元ミスを疑う。
		Zero(dek)
		return nil, ErrDecrypt
	}
	return dek, nil
}

// wrapDEK は MK と salt から KEK を導出し、DEK をラップする。KEK は消す。
func wrapDEK(mk, salt, dek []byte) (wrapped, nonce []byte, err error) {
	kek, err := DeriveKEK(mk, salt)
	if err != nil {
		return nil, nil, fmt.Errorf("derive kek: %w", err)
	}
	defer Zero(kek)

	wrapped, nonce, err = sealBytes(kek, dek, keyringAAD())
	if err != nil {
		return nil, nil, fmt.Errorf("wrap dek: %w", err)
	}
	return wrapped, nonce, nil
}

// ---- 状態機械と並行制御(DESIGN §4.4) ----

// State は Vault の状態である。
type State int

const (
	// StateSealed では DEK を保持しない。secret の復号はできない。
	StateSealed State = iota
	// StateUnsealed では DEK のみを保持する(MK / KEK は保持しない)。
	StateUnsealed
)

func (s State) String() string {
	if s == StateUnsealed {
		return "unsealed"
	}
	return "sealed"
}

var (
	// ErrSealed は sealed 状態で暗号操作が要求されたことを示す。
	ErrSealed = errors.New("vault is sealed")
	// ErrAlreadyUnsealed は unsealed 状態で unseal が要求されたことを示す。
	ErrAlreadyUnsealed = errors.New("vault is already unsealed")
)

// Vault はサーバーの鍵状態を持つ。
//
// **要求される性質(DESIGN §4.4)。go test -race では検出できないため、
// keyring_concurrency_test.go で明示的に検証する:**
//
//	C1 暗号操作は開始から完了まで read lock を保持する
//	C2 Seal() は write lock を取り、進行中の暗号操作の完了を待つ
//	C3 Seal() 完了後、DEK を参照している goroutine が存在しない
//	C4 Unseal() はローカル変数で検証し、成功してから一度に公開する
//	C5 Seal() 時に token store を空にする
//	C6 トークン発行処理全体が read lock 内で完結する
//	C7 ロックの取得順序は Vault.mu → tokenStore.mu(逆順で取らない)
//	C8 「DB 更新 → トークン削除」は write lock 内で実行する
//	C10 rotate-master 全体を専用 mutex で直列化する
type Vault struct {
	db     *sql.DB
	logger *slog.Logger

	mu         sync.RWMutex
	state      State
	dek        []byte
	dekVersion int64

	tokens *tokenStore

	// rotateMu は rotate-master を直列化する(C10)。mu とは独立しており、
	// rotate は DB 上のラップだけを差し替えるので、進行中の暗号操作を
	// 止める必要がない。
	rotateMu sync.Mutex
}

// NewVault は sealed 状態の Vault を作る。
func NewVault(db *sql.DB, logger *slog.Logger, maxTokens int) *Vault {
	return &Vault{
		db:     db,
		logger: logger,
		state:  StateSealed,
		tokens: newTokenStore(maxTokens),
	}
}

// VaultStatus は observability 用の状態のスナップショットである。
// **鍵素材は含めない。**
type VaultStatus struct {
	State      State
	DEKVersion int64
	Tokens     int
}

// Status は現在の状態を返す。
func (v *Vault) Status() VaultStatus {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return VaultStatus{
		State:      v.state,
		DEKVersion: v.dekVersion,
		// C7: Vault.mu を保持したまま tokenStore.mu を取る。この向きで固定する。
		Tokens: v.tokens.Len(),
	}
}

// Unseal は MK から DEK を復元し、unsealed 状態にする。
//
// **監査は fail closed である**(THREAT_MODEL §10.4)。unseal はセキュリティを
// 下げる操作なので、監査ログを書けなければ unseal しない。
//
// **MK と KEK は関数を抜けるまでに消える**(AGENTS.md ルール 14)。保持するのは
// DEK のみ。mk そのもののゼロクリアは呼び出し側の責務である(受け取った
// バッファの寿命を知っているのは呼び出し側なので)。
//
// C4: 鍵はローカル変数で検証し、完全に成功してから write lock 内で一度に公開する。
func (v *Vault) Unseal(ctx context.Context, mk []byte, ac auditCtx) (err error) {
	// 先に状態を見て、無駄な argon2 を避ける。公開時に再確認する(下記)ので、
	// ここでの判定が競合しても最終的な整合性は壊れない。
	if v.Status().State == StateUnsealed {
		return ErrAlreadyUnsealed
	}

	// 失敗も監査対象である(DESIGN §10.1)。fail closed なので、記録できない
	// 場合はそのエラーを返す(いずれにせよ unseal はしない)。
	defer func() {
		if err != nil && !errors.Is(err, ErrAlreadyUnsealed) {
			reason := ReasonInvalidMasterKey
			if !errors.Is(err, ErrDecrypt) {
				// 復号以外の失敗(DB 障害等)は理由を特定しない。
				reason = ""
			}
			v.recordUnsealFailure(ctx, ac, reason, &err)
		}
	}()

	kr, err := LoadKeyring(ctx, v.db)
	if err != nil {
		return err
	}

	// argon2 の同時実行数を制限する(DESIGN §7.4)。64MB × 並列数の
	// メモリ確保が unseal の同時試行で積み上がるのを防ぐ。
	dek, err := unwrapWithArgon2Slot(ctx, kr, mk)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			Zero(dek)
		}
	}()

	// 監査を先に確定させる。ここで失敗したら unsealed にしない(fail closed)。
	if err := RecordAudit(ctx, v.db, ac.entry(ActionUnsealAttempt, ResultSuccess, nil)); err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.state == StateUnsealed {
		// 判定から公開までの間に他の unseal が完了していた。復元した DEK は
		// 捨てる(同じ MK なら同じ DEK なので、実害はなく状態も変えない)。
		Zero(dek)
		return ErrAlreadyUnsealed
	}
	v.state = StateUnsealed
	v.dek = dek
	v.dekVersion = kr.DEKVersion
	return nil
}

// Seal は DEK を破棄し、sealed 状態に戻す。
//
// **監査は fail open である**(THREAT_MODEL §10.4)。seal は緊急遮断操作であり、
// 監査 DB の障害で止めてはならない。監査の失敗は運用ログに出す。
//
// C2 / C3: write lock を取るので、進行中の暗号操作の完了を待ってから DEK を消す。
// 戻った時点で DEK を参照している goroutine は存在しない。
// C5: token store を空にする。
func (v *Vault) Seal(ctx context.Context, ac auditCtx) {
	v.mu.Lock()
	Zero(v.dek)
	v.dek = nil
	v.dekVersion = 0
	v.state = StateSealed
	// C5 / C7: write lock を保持したまま token store を空にする。
	v.tokens.Clear()
	v.mu.Unlock()

	// 監査はロックの外で書く。DB が固まっているときにロックを持ち続けると、
	// 遮断そのものは終わっているのに他の操作を巻き込んで止めてしまう。
	RecordAuditBestEffort(ctx, v.db, v.logger, ac.entry(ActionSeal, ResultSuccess, nil))
}

// WithDEK は DEK を使う処理を read lock の下で実行する(C1)。
//
// **fn の実行中は Seal() が完了しない。** 逆に言えば、fn の中で長い処理
// (ネットワーク待ち等)をしてはならない。fn を抜けた後に dek を参照し続けて
// もいけない(Seal() 後にゼロクリア済みのバッファを読むことになる)。
func (v *Vault) WithDEK(fn func(dek []byte, dekVersion int64) error) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.state != StateUnsealed {
		return ErrSealed
	}
	return fn(v.dek, v.dekVersion)
}

// IssueToken は machine token を発行する(C6)。
//
// **unsealed の確認・credential の検証・store への追加が read lock 内で
// 完結する。** これを分けると次の競合が起きる:
//
//	auth:  unsealed を確認
//	seal:                write lock、token store を clear、sealed へ
//	auth:  token を store に追加   ← seal をすり抜けた
//
// verify は「credential を検証し、machine ID を返す」関数である。監査
// (fail closed)も verify の中で行う。read lock 内で呼ばれるため、
// **verify の中で Vault のメソッドを呼んではならない**(自己デッドロック)。
func (v *Vault) IssueToken(now time.Time, verify func() (machineID int64, err error)) (encoded string, expiresAt time.Time, err error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.state != StateUnsealed {
		return "", time.Time{}, ErrSealed
	}

	machineID, err := verify()
	if err != nil {
		return "", time.Time{}, err
	}

	raw, encoded, err := GenerateToken()
	if err != nil {
		return "", time.Time{}, err
	}
	defer Zero(raw)

	expiresAt = now.Add(TokenTTL)
	// C7: Vault.mu(read)を保持したまま tokenStore.mu を取る。
	if err := v.tokens.Add(raw, machineID, expiresAt, now); err != nil {
		return "", time.Time{}, err
	}
	return encoded, expiresAt, nil
}

// LookupToken はトークンを検証し、machine ID を返す。
//
// これは認証の確認にすぎない。machine の disabled、grant、祖先の deleted_at は
// リクエストごとに別途再検査する(DESIGN §4.5)。
func (v *Vault) LookupToken(raw []byte, now time.Time) (int64, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.tokens.Lookup(raw, now)
}

// WithWriteLock は「DB 更新 → トークン削除」を write lock 内で実行する(C8)。
//
// machine.rotate_secret / machine.disable で使う。**C6 と同型の競合である:**
//
//	auth:   旧 client_secret で検証成功
//	rotate: secret_hash 更新 + 監査を commit
//	rotate: DeleteByMachine       ← 削除実行
//	auth:   token を store に追加  ← 削除をすり抜けた
//
// C6 により発行は read lock 内で完結しているので、write lock は進行中の発行の
// 完了を待つ。結果として、発行済みトークンは必ず削除対象に含まれる。
//
// sealed でも実行できる。無効化は unsealed であることを前提としない。
func (v *Vault) WithWriteLock(fn func(tokens *tokenStore) error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	// C7: Vault.mu → tokenStore.mu の順で取る。fn の中で Vault のメソッドを
	// 呼ぶと自己デッドロックになるので、tokenStore だけを渡す。
	return fn(v.tokens)
}

// SweepTokens は期限切れトークンを掃除する。**期限判定ではない**
// (それは Lookup が行う)。掃除の件数は運用上の意味を持たないので返さない。
func (v *Vault) SweepTokens(now time.Time) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	v.tokens.Sweep(now)
}

// RotateMaster は MK を差し替える(DESIGN §6.7、C10)。
//
// **新 MK を生成しない。** 生成は `hokora gen-key` の責務である。
// 「生成 → DB 更新 → 1Password 保存前にクラッシュ」で全データが復旧不能に
// なる事故を防ぐため、人間が保存を確認してからこの操作を実行する。
//
// **監査は fail closed。** 緊急操作ではないので、記録できないなら実行しない。
//
// DEK は変わらないため、secret の再暗号化は不要であり、unsealed 状態の
// Vault が保持している DEK もそのまま有効である。
func (v *Vault) RotateMaster(ctx context.Context, oldMK, newMK []byte, ac auditCtx) error {
	// C10: 全体を直列化する。並行実行を許すと、両方が旧 keyring を読んで
	// 検証に成功し、最後に commit した方の MK だけが有効になる。データは
	// 失われないが、「どの MK が有効か」という運用上の認識が壊れる。
	v.rotateMu.Lock()
	defer v.rotateMu.Unlock()

	kr, err := LoadKeyring(ctx, v.db)
	if err != nil {
		return err
	}

	// 手順 6: 現行 MK で DEK を取り出す。失敗したら中止(現行 MK が誤り)。
	dek, err := unwrapWithArgon2Slot(ctx, kr, oldMK)
	if err != nil {
		return err
	}
	defer Zero(dek)

	// 手順 7: 新 MK で再ラップする。salt も引き直す。
	salt, err := randomBytes(kdfSaltBytes)
	if err != nil {
		return err
	}
	next := &Keyring{
		KDFSalt:    salt,
		DEKVersion: kr.DEKVersion,
		CreatedAt:  kr.CreatedAt,
		UpdatedAt:  ac.Now.UTC().Truncate(time.Second),
	}
	if err := withArgon2Slot(ctx, func() error {
		wrapped, nonce, err := wrapDEK(newMK, salt, dek)
		if err != nil {
			return err
		}
		next.DEKWrapped, next.DEKNonce = wrapped, nonce
		return nil
	}); err != nil {
		return err
	}

	// 手順 8: 書き込む前に、新しいラップから DEK を復元できることを確かめる。
	if err := verifyRewrap(ctx, next, newMK, dek); err != nil {
		return err
	}

	// 手順 9: keyring の更新と監査を同一トランザクションで確定させる。
	// 途中で失敗しても旧 MK が引き続き有効である。
	if err := v.rotateInTx(ctx, next, ac); err != nil {
		return err
	}

	// 手順 10: commit 後の keyring から、もう一度 DEK を復元して検証する。
	// ここまで通って初めて「新 MK で開ける DB」になったと言える。
	stored, err := LoadKeyring(ctx, v.db)
	if err != nil {
		return fmt.Errorf("rotate-master committed but the keyring could not be re-read: %w", err)
	}
	if err := verifyRewrap(ctx, stored, newMK, dek); err != nil {
		return fmt.Errorf("rotate-master committed but verification failed: %w", err)
	}
	return nil
}

// rotateInTx は keyring の更新と監査を 1 トランザクションで確定させる。
func (v *Vault) rotateInTx(ctx context.Context, next *Keyring, ac auditCtx) (err error) {
	tx, err := v.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin rotate-master transaction: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, ignoreTxDone(tx.Rollback()))
		}
	}()

	if err := UpdateKeyringWrap(ctx, tx, next); err != nil {
		return err
	}
	// fail closed: 監査が書けなければ rotate も確定させない。
	if err := RecordAudit(ctx, tx, ac.entry(ActionMasterRotate, ResultSuccess, nil)); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit rotate-master: %w", err)
	}
	return nil
}

// verifyRewrap は keyring から DEK を復元し、元の DEK と一致するか確かめる。
func verifyRewrap(ctx context.Context, kr *Keyring, mk, want []byte) error {
	got, err := unwrapWithArgon2Slot(ctx, kr, mk)
	if err != nil {
		return fmt.Errorf("verify rewrapped keyring: %w", err)
	}
	defer Zero(got)

	// 生の鍵同士の比較なので定数時間で行う(AGENTS.md ルール 4)。
	if !constantTimeEqual(got, want) {
		return errors.New("verify rewrapped keyring: recovered dek does not match")
	}
	return nil
}

// unwrapWithArgon2Slot は argon2 の同時実行数を制限しつつ DEK を取り出す。
func unwrapWithArgon2Slot(ctx context.Context, kr *Keyring, mk []byte) ([]byte, error) {
	var dek []byte
	err := withArgon2Slot(ctx, func() error {
		var err error
		dek, err = kr.UnwrapDEK(mk)
		return err
	})
	if err != nil {
		return nil, err
	}
	return dek, nil
}

// recordUnsealFailure は unseal 失敗の監査を書く。
//
// fail closed なので、記録できなければその失敗を呼び出し元のエラーに合流させる
// (どのみち unseal は拒否されるが、「記録されない失敗試行」を残さない)。
func (v *Vault) recordUnsealFailure(ctx context.Context, ac auditCtx, reason string, outErr *error) {
	var detail *AuditDetail
	if reason != "" {
		detail = &AuditDetail{Reason: &reason}
	}
	if err := RecordAudit(ctx, v.db, ac.entry(ActionUnsealAttempt, ResultFailure, detail)); err != nil {
		*outErr = errors.Join(*outErr, err)
	}
}

// ignoreTxDone は「既に commit / rollback 済み」を無視する。
func ignoreTxDone(err error) error {
	if errors.Is(err, sql.ErrTxDone) {
		return nil
	}
	return err
}
