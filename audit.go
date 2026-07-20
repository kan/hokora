package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// Action は監査ログの action である。**allowlist に無い値は記録できない**
// (DESIGN §5.4)。文字列を自由に入れられるようにすると、そこが攻撃者制御の
// 文字列の入口になる。
type Action string

const (
	ActionSecretRead   Action = "secret.read"
	ActionSecretWrite  Action = "secret.write"
	ActionSecretDelete Action = "secret.delete"
	ActionSecretReveal Action = "secret.reveal"

	ActionUnsealAttempt Action = "unseal.attempt"
	ActionSeal          Action = "seal"
	ActionMasterRotate  Action = "master.rotate"

	ActionAuthMachine Action = "auth.machine"
	ActionAuthUser    Action = "auth.user"
	ActionLogout      Action = "logout"

	ActionUserCreate         Action = "user.create"
	ActionUserDisable        Action = "user.disable"
	ActionUserPasswordChange Action = "user.password_change"

	ActionMachineCreate       Action = "machine.create"
	ActionMachineDisable      Action = "machine.disable"
	ActionMachineRotateSecret Action = "machine.rotate_secret"

	ActionGrantCreate Action = "grant.create"
	ActionGrantDelete Action = "grant.delete"

	ActionProjectCreate Action = "project.create"
	ActionProjectDelete Action = "project.delete"

	ActionEnvironmentCreate Action = "environment.create"
	ActionEnvironmentDelete Action = "environment.delete"
)

// auditActions は記録を許す action の集合である(DESIGN §5.4)。
var auditActions = map[Action]struct{}{
	ActionSecretRead: {}, ActionSecretWrite: {}, ActionSecretDelete: {}, ActionSecretReveal: {},
	ActionUnsealAttempt: {}, ActionSeal: {}, ActionMasterRotate: {},
	ActionAuthMachine: {}, ActionAuthUser: {}, ActionLogout: {},
	ActionUserCreate: {}, ActionUserDisable: {}, ActionUserPasswordChange: {},
	ActionMachineCreate: {}, ActionMachineDisable: {}, ActionMachineRotateSecret: {},
	ActionGrantCreate: {}, ActionGrantDelete: {},
	ActionProjectCreate: {}, ActionProjectDelete: {},
	ActionEnvironmentCreate: {}, ActionEnvironmentDelete: {},
}

// Result は監査ログの result である。
//
// success は「認可を通過し、復号に成功し、レスポンスの送信を開始した」を
// 意味する。「クライアントが受信した」ではない(THREAT_MODEL §10.5)。
type Result string

const (
	ResultSuccess Result = "success"
	ResultFailure Result = "failure"
)

// Reason は detail.reason に入れてよい値である(DESIGN §5.4)。
// 自由記述にすると、失敗理由の説明という体裁で攻撃者制御の文字列が入る。
//
//nolint:gosec // G101: 認証情報ではなく、監査ログに記録する理由コードである
const (
	ReasonInvalidCredentials = "invalid_credentials"
	ReasonRateLimited        = "rate_limited"
	ReasonForbidden          = "forbidden"
	ReasonSealed             = "sealed"
	ReasonDisabled           = "disabled"
	ReasonExpired            = "expired"
	ReasonInvalidCSRF        = "invalid_csrf"
	ReasonInvalidMasterKey   = "invalid_master_key"
)

var auditReasons = map[string]struct{}{
	ReasonInvalidCredentials: {}, ReasonRateLimited: {}, ReasonForbidden: {},
	ReasonSealed: {}, ReasonDisabled: {}, ReasonExpired: {},
	ReasonInvalidCSRF: {}, ReasonInvalidMasterKey: {},
}

// Via は操作がどの経路から来たかを表す。
const (
	ViaSocket = "socket"
	ViaWeb    = "web"
)

// ActorAnonymous は認証されていない主体である。
//
// **存在しない client_id / username での認証失敗もこれを使う。** 生の入力値を
// actor に入れない(DESIGN §5.5)。相関が必要なときは Detail.SubjectDigest に
// subjectDigest() の結果を入れる。
const ActorAnonymous = "anonymous"

// AuditDetail は detail カラムに入れてよい構造である(DESIGN §5.4)。
//
// **UserAgent フィールドは持たない。** 攻撃者が自由に設定できる文字列であり、
// 型付き allowlist はフィールド名を制限するだけで値の安全性を保証しない
// (AGENTS.md ルール 25)。
type AuditDetail struct {
	Version       *int    `json:"version,omitempty"`
	Reason        *string `json:"reason,omitempty"`
	Via           *string `json:"via,omitempty"`
	Count         *int    `json:"count,omitempty"`
	SubjectDigest *string `json:"subject_digest,omitempty"`
}

// AuditEntry は監査ログの 1 行である。
//
// slug / key は再利用できるため、表示用の Target 文字列だけでは追跡できない。
// **immutable な ID を併せて記録する**(THREAT_MODEL §10.2)。
type AuditEntry struct {
	At                  time.Time
	Actor               string
	ActorUserID         *int64
	ActorMachineID      *int64
	Action              Action
	Target              *string
	TargetProjectID     *int64
	TargetEnvironmentID *int64
	TargetItemID        *int64
	TargetUserID        *int64
	TargetMachineID     *int64
	Result              Result
	RemoteAddr          *string
	Detail              *AuditDetail
}

// actorUser / actorMachine は actor 文字列を組み立てる。
// 形式は schema.sql のコメントに合わせる('user:1' | 'machine:3' | 'anonymous')。
func actorUser(id int64) string    { return fmt.Sprintf("user:%d", id) }
func actorMachine(id int64) string { return fmt.Sprintf("machine:%d", id) }

// subjectDigest は攻撃者制御の入力を、相関に使える固定長の値へ潰す
// (DESIGN §5.5)。
//
// 16 文字の hex なので制御文字も改行も入らない。「同じ存在しない client_id が
// 繰り返し試行された」ことは追えるが、生の入力値は DB に入らない。
func subjectDigest(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:8])
}

// auditCtx は「誰が・どこから・いつ」をまとめる。
//
// 監査対象の操作は必ずこの 3 つを要求するので、個別の引数で引き回すと
// 呼び出し側で順序を取り違えたり、actor と actor id が食い違ったりする。
// M5 で Web UI 経路(actor = user:N、remote_addr あり)が加わると、この
// 組み合わせは更に増える。
type auditCtx struct {
	Actor          string
	ActorUserID    *int64
	ActorMachineID *int64
	Via            string
	RemoteAddr     *string
	Now            time.Time
}

// socketAudit は admin socket 経由の操作の監査コンテキストである。
//
// socket は 0600 で hokora ユーザーのみが到達できるが、**そこに居るのが誰か
// までは分からない**。したがって actor は anonymous であり、remote_addr は
// 持たない(unix socket に送信元アドレスは無い)。
func socketAudit(now time.Time) auditCtx {
	return auditCtx{Actor: ActorAnonymous, Via: ViaSocket, Now: now}
}

// entry は監査コンテキストから 1 行を組み立てる。
//
// **detail は値でコピーしてから触る。** 呼び出し側の構造体を書き換えると、
// 1 つの AuditDetail を使い回した呼び出しで、前の呼び出しの Via が次の行に
// 残る(そして呼び出し側は自分の構造体が変わったことに気付かない)。
func (c auditCtx) entry(action Action, result Result, detail *AuditDetail) AuditEntry {
	var d AuditDetail
	if detail != nil {
		d = *detail
	}
	if d.Via == nil && c.Via != "" {
		via := c.Via
		d.Via = &via
	}
	return AuditEntry{
		At:             c.Now,
		Actor:          c.Actor,
		ActorUserID:    c.ActorUserID,
		ActorMachineID: c.ActorMachineID,
		Action:         action,
		Result:         result,
		RemoteAddr:     c.RemoteAddr,
		Detail:         &d,
	}
}

// machineEntry は machine を対象とする成功の監査行を作る。
//
// target_machine_id は immutable な ID であり、client_id(再利用されうる)
// では追跡できない(THREAT_MODEL §10.2)。付け忘れる余地を無くすため、
// 呼び出し側でフィールドを埋めさせない。
func (c auditCtx) machineEntry(action Action, machineID int64) AuditEntry {
	entry := c.entry(action, ResultSuccess, nil)
	entry.TargetMachineID = &machineID
	return entry
}

// execer は *sql.DB と *sql.Tx の共通部分である。
//
// fail closed の監査は本体の処理と同じトランザクションに載せる必要があるため、
// 書き込み口は両方を受け取れなければならない。
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

const insertAuditSQL = `
INSERT INTO audit_logs (
    at, actor, actor_user_id, actor_machine_id, action, target,
    target_project_id, target_environment_id, target_item_id,
    target_user_id, target_machine_id, result, remote_addr, detail
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// RecordAudit は監査ログを 1 件書く。
//
// **fail closed の経路で使う**(secret の読み書き、認証、unseal、各種 create、
// master.rotate)。呼び出し側は本体の処理と同じトランザクションを渡し、
// この関数がエラーを返したら commit しないこと(THREAT_MODEL §10.4)。
func RecordAudit(ctx context.Context, ex execer, e AuditEntry) error {
	if err := e.validate(); err != nil {
		return err
	}
	detail, err := e.marshalDetail()
	if err != nil {
		return err
	}

	_, err = ex.ExecContext(ctx, insertAuditSQL,
		e.At.Unix(), e.Actor, e.ActorUserID, e.ActorMachineID, string(e.Action), e.Target,
		e.TargetProjectID, e.TargetEnvironmentID, e.TargetItemID,
		e.TargetUserID, e.TargetMachineID, string(e.Result), e.RemoteAddr, detail,
	)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return nil
}

// RecordAuditBestEffort は監査ログを書き、失敗しても呼び出し側を止めない。
//
// **fail open の経路で使う**(seal、machine.disable / user.disable、grant.delete、
// rotate_secret / password_change、token / session の失効、logout)。
// これらは緊急遮断操作であり、**監査 DB の障害で止めてはならない**
// (THREAT_MODEL §10.4)。
//
// fail open は「DB 更新失敗を無視する」という意味ではない。本体の処理が
// 成功したのに監査 INSERT だけが失敗した場合に本体を rollback しない、という
// 意味である。失敗は非機密の運用ログに出す。
func RecordAuditBestEffort(ctx context.Context, ex execer, logger *slog.Logger, e AuditEntry) {
	if err := RecordAudit(ctx, ex, e); err != nil {
		// ログに出すのは action と result だけにする。AuditEntry 全体を
		// 出すと、将来 detail に足したフィールドがそのまま運用ログへ漏れる。
		logger.ErrorContext(ctx, "audit log write failed (continuing: fail open)",
			slog.String("action", string(e.Action)),
			slog.String("result", string(e.Result)),
			slog.String("error", err.Error()),
		)
	}
}

// validate は allowlist と整合性を検査する。ここを通らない値は DB に入らない。
//
// 違反は運用時の入力ミスではなく実装のバグなので、エラーにして落とす。
func (e AuditEntry) validate() error {
	if _, ok := auditActions[e.Action]; !ok {
		return fmt.Errorf("audit: action %q is not in the allowlist", e.Action)
	}
	if e.Result != ResultSuccess && e.Result != ResultFailure {
		return fmt.Errorf("audit: result %q is not valid", e.Result)
	}
	if e.At.IsZero() {
		return fmt.Errorf("audit: at is zero for action %q", e.Action)
	}

	// actor と actor_*_id が食い違っていると、後から追跡できない行になる。
	switch {
	case e.ActorUserID != nil && e.ActorMachineID != nil:
		return fmt.Errorf("audit: actor cannot be both a user and a machine")
	case e.ActorUserID != nil:
		if want := actorUser(*e.ActorUserID); e.Actor != want {
			return fmt.Errorf("audit: actor %q does not match actor_user_id (want %q)", e.Actor, want)
		}
	case e.ActorMachineID != nil:
		if want := actorMachine(*e.ActorMachineID); e.Actor != want {
			return fmt.Errorf("audit: actor %q does not match actor_machine_id (want %q)", e.Actor, want)
		}
	case e.Actor != ActorAnonymous:
		// 認証されていない主体は必ず anonymous。生の入力値は入れない。
		return fmt.Errorf("audit: actor %q must be %q when no actor id is set", e.Actor, ActorAnonymous)
	}

	return e.Detail.validate()
}

// validate は detail の値が allowlist に収まっているかを検査する。
func (d *AuditDetail) validate() error {
	if d == nil {
		return nil
	}
	if d.Reason != nil {
		if _, ok := auditReasons[*d.Reason]; !ok {
			return fmt.Errorf("audit: reason %q is not in the allowlist", *d.Reason)
		}
	}
	if d.Via != nil && *d.Via != ViaSocket && *d.Via != ViaWeb {
		return fmt.Errorf("audit: via %q is not valid", *d.Via)
	}
	// subject_digest は subjectDigest() が作る 16 文字の hex に限る。
	// 生の入力をそのまま入れる呼び出しをここで止める。
	if d.SubjectDigest != nil {
		if _, err := hex.DecodeString(*d.SubjectDigest); err != nil || len(*d.SubjectDigest) != 16 {
			return fmt.Errorf("audit: subject_digest must be 16 hex characters")
		}
	}
	return nil
}

// marshalDetail は detail カラムに入れる JSON を返す。全て空なら NULL にする。
func (e AuditEntry) marshalDetail() (any, error) {
	if e.Detail == nil || *e.Detail == (AuditDetail{}) {
		return nil, nil
	}
	b, err := json.Marshal(e.Detail)
	if err != nil {
		return nil, fmt.Errorf("marshal audit detail: %w", err)
	}
	return string(b), nil
}
