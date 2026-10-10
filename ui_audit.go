package main

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// auditPageSizes は監査ログ画面で選べる 1 ページの件数である。
//
// **保持期間は既定で無限**(Q4)なので、全件を描画しない。件数は選択肢に限る
// (任意の数を受け付けると、1 リクエストで表全体を読ませられる)。
// batch は 1 件として数えるので、実際に描画する行はこれより多くなりうる。
var auditPageSizes = []int{50, 100, 200}

const auditDefaultPageSize = 100

// errAuditQuery は監査ログ画面のクエリ文字列が不正であることを示す。
//
// **入力の値をエラーに含めない。** このエラーは運用ログに出るので、含めると
// 利用者が制御できる文字列がログに入る。
var errAuditQuery = errors.New("invalid audit query")

// auditOption は絞り込みの選択肢(<option>)である。
type auditOption struct {
	Value string
	Label string
}

// auditView は監査ログ画面の、絞り込みフォームとページ送りの状態である。
//
// 文字列のフィールドは、**検証を通ったクエリ文字列の値そのもの**である
// (フォームに選択状態を戻し、ページ送りの URL に持ち回るために使う)。
// 検証は正規形しか通さないので、同じ絞り込みを指す値は 1 通りしかない。
type auditView struct {
	From, To string // YYYY-MM-DD
	Actor    string // "" | "anonymous" | "user:1" | "machine:3"
	Action   string
	Result   string
	Env      string // environment の id

	PageSize  int
	PageSizes []int

	Actors  []auditOption
	Actions []string
	Envs    []auditOption

	// ページ送りのリンク。空なら、その方向には行が無い。
	// NewestURL は最新のページ以外で出す。
	NewestURL string
	NewerURL  string
	OlderURL  string
}

// filterParams は絞り込みの条件を、クエリ文字列の名前と値の組で返す。
// **絞り込みを足したら、ここに足す**(Filtered と pageURL がここから導く)。
func (v auditView) filterParams() [][2]string {
	return [][2]string{
		{"from", v.From}, {"to", v.To}, {"actor", v.Actor},
		{"action", v.Action}, {"result", v.Result}, {"env", v.Env},
	}
}

// Filtered は絞り込みが 1 つでも指定されていることを示す。
func (v auditView) Filtered() bool {
	return slices.ContainsFunc(v.filterParams(), func(p [2]string) bool { return p[1] != "" })
}

// pageURL は、いまの絞り込みと件数を保ったまま、別のページを指す URL を作る。
// pos が nil なら最新のページを指す。
//
// 値は全て検証済みのものを url.Values で組み立てる(文字列の連結で作らない)。
func (v auditView) pageURL(key string, pos *AuditCursor) string {
	q := url.Values{}
	for _, p := range v.filterParams() {
		if p[1] != "" {
			q.Set(p[0], p[1])
		}
	}
	if v.PageSize != auditDefaultPageSize {
		q.Set("n", strconv.Itoa(v.PageSize))
	}
	if pos != nil {
		q.Set(key, pos.String())
	}
	if len(q) == 0 {
		return "/ui/audit"
	}
	return "/ui/audit?" + q.Encode()
}

// parseAuditQuery はクエリ文字列を検証し、問い合わせと画面の状態に変換する。
//
// **全ての値を型か allowlist に落とす。** 文字列のまま SQL や画面に流さない。
// 1 つでも不正なら全体を拒否する(黙って無視すると、利用者は絞り込めている
// つもりで全件を見ることになる)。
// 日付は loc(サーバーのローカル時刻。画面の時刻表示と同じ)で解釈する。
//
// rawQuery は URL のクエリ文字列そのものである。**http.Request.URL.Query() を
// 使わない。** あれは解釈できなかった組(壊れた % エスケープ、';' を含む組)を
// 黙って捨てるので、`?action=secret.reveal%zz` が「絞り込みなし」として通って
// しまう。同じ名前が 2 回あるクエリも、どちらを採ったか利用者に見えないので拒否する。
//
// エラーのとき、戻り値の q と view は途中まで埋まっている。使わないこと。
func parseAuditQuery(rawQuery string, loc *time.Location) (q AuditQuery, view auditView, err error) {
	v, err := url.ParseQuery(rawQuery)
	if err != nil {
		return q, view, errAuditQuery
	}
	for _, values := range v {
		if len(values) > 1 {
			return q, view, errAuditQuery
		}
	}

	q.Limit = auditDefaultPageSize
	view.PageSize, view.PageSizes = auditDefaultPageSize, auditPageSizes

	if view.From = v.Get("from"); view.From != "" {
		from, err := time.ParseInLocation(time.DateOnly, view.From, loc)
		if err != nil {
			return q, view, errAuditQuery
		}
		q.Filter.From = &from
	}
	if view.To = v.Get("to"); view.To != "" {
		end, err := time.ParseInLocation(time.DateOnly, view.To, loc)
		if err != nil {
			return q, view, errAuditQuery
		}
		// 終了日はその日を含める(翌日の 0 時より前)。
		to := end.AddDate(0, 0, 1)
		q.Filter.To = &to
	}

	if view.Actor = v.Get("actor"); view.Actor != "" {
		if err := parseAuditActor(view.Actor, &q.Filter); err != nil {
			return q, view, err
		}
	}
	if view.Action = v.Get("action"); view.Action != "" {
		if _, ok := auditActions[Action(view.Action)]; !ok {
			return q, view, errAuditQuery
		}
		q.Filter.Action = Action(view.Action)
	}
	if view.Result = v.Get("result"); view.Result != "" {
		q.Filter.Result = Result(view.Result)
		if q.Filter.Result != ResultSuccess && q.Filter.Result != ResultFailure {
			return q, view, errAuditQuery
		}
	}
	if view.Env = v.Get("env"); view.Env != "" {
		id, err := parsePositiveID(view.Env)
		if err != nil {
			return q, view, err
		}
		q.Filter.EnvironmentID = &id
	}

	if s := v.Get("n"); s != "" {
		// 選択肢の値と文字列として一致するものだけを通す("050" や "+50" を
		// 通さない。ID と同じく、同じ指定を表す書き方を 1 通りにする)。
		n, err := strconv.Atoi(s)
		if err != nil || !slices.Contains(auditPageSizes, n) || s != strconv.Itoa(n) {
			return q, view, errAuditQuery
		}
		q.Limit, view.PageSize = n, n
	}

	before, after := v.Get("before"), v.Get("after")
	if before != "" && after != "" {
		return q, view, errAuditQuery
	}
	if q.Before, err = parseAuditCursor(before); err != nil {
		return q, view, err
	}
	if q.After, err = parseAuditCursor(after); err != nil {
		return q, view, err
	}
	return q, view, nil
}

// parseAuditActor は "anonymous" | "user:<id>" | "machine:<id>" を読む。
// 監査行の actor と同じ書き方である(actorUser / actorMachine)。
func parseAuditActor(s string, f *AuditFilter) error {
	if s == ActorAnonymous {
		f.ActorAnonymous = true
		return nil
	}
	kind, rest, ok := strings.Cut(s, ":")
	if !ok {
		return errAuditQuery
	}
	id, err := parsePositiveID(rest)
	if err != nil {
		return err
	}
	switch kind {
	case "user":
		f.ActorUserID = &id
	case "machine":
		f.ActorMachineID = &id
	default:
		return errAuditQuery
	}
	return nil
}

// parsePositiveID は正の整数の ID を読む。
//
// **正規形と一致する値だけを通す**("01" や "+1" を通さない)。通すと、同じ
// 絞り込みを指す URL が何通りもでき、フォームの選択状態も戻らない
// (選択肢の値は正規形である)。
func parsePositiveID(s string) (int64, error) {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil || id <= 0 || s != strconv.FormatInt(id, 10) {
		return 0, errAuditQuery
	}
	return id, nil
}

// parseAuditCursor は "<at>-<id>" を読む。空文字なら nil(指定なし)。
func parseAuditCursor(s string) (*AuditCursor, error) {
	if s == "" {
		return nil, nil
	}
	atStr, idStr, ok := strings.Cut(s, "-")
	if !ok {
		return nil, errAuditQuery
	}
	at, err := strconv.ParseInt(atStr, 10, 64)
	if err != nil || at < 0 || atStr != strconv.FormatInt(at, 10) {
		return nil, errAuditQuery
	}
	id, err := parsePositiveID(idStr)
	if err != nil {
		return nil, err
	}
	return &AuditCursor{At: at, ID: id}, nil
}

func (c AuditCursor) String() string {
	return strconv.FormatInt(c.At, 10) + "-" + strconv.FormatInt(c.ID, 10)
}

func (u *uiServer) handleAudit(w http.ResponseWriter, r *http.Request, req uiRequest) {
	q, view, err := parseAuditQuery(r.URL.RawQuery, time.Local)
	if err != nil {
		u.badRequest(w, r, "絞り込みの指定が不正です", err)
		return
	}

	page, err := ListAuditLogs(r.Context(), u.vault.db, q)
	if err != nil {
		u.internalError(w, r, "list audit logs", err)
		return
	}
	if err := u.loadAuditOptions(r, &view); err != nil {
		u.internalError(w, r, "list audit filter options", err)
		return
	}

	if q.Before != nil || q.After != nil {
		view.NewestURL = view.pageURL("", nil)
	}
	if page.Newer != nil {
		view.NewerURL = view.pageURL("after", page.Newer)
	}
	if page.Older != nil {
		view.OlderURL = view.pageURL("before", page.Older)
	}

	data := u.page(req, "監査ログ")
	data.Audit = page.Rows
	data.AuditView = &view
	u.render(w, r, "audit.html", data)
}

// handleAuditBatch は 1 つの batch の key を、省略せずに全て見せる。
//
// 一覧は 1 つの batch の key を途中までしか出さない(auditBatchInlineLimit)。
// 読まれた key は監査の中身そのものなので、全てを見る画面を別に持つ。
func (u *uiServer) handleAuditBatch(w http.ResponseWriter, r *http.Request, req uiRequest) {
	id, ok := u.pathID(w, r, "id")
	if !ok {
		return
	}
	batch, err := ListAuditBatch(r.Context(), u.vault.db, id)
	if errors.Is(err, ErrNotFound) {
		u.renderError(w, r, http.StatusNotFound, "見つかりません")
		return
	}
	if err != nil {
		u.internalError(w, r, "list audit batch", err)
		return
	}

	data := u.page(req, "監査ログ")
	data.AuditBatch = batch
	u.render(w, r, "audit_batch.html", data)
}

// loadAuditOptions は絞り込みフォームの選択肢を埋める。
//
// **無効化された user / machine と、削除された environment も選べる。**
// 監査は過去の記録であり、いま使えないものほど調べる理由がある。
func (u *uiServer) loadAuditOptions(r *http.Request, view *auditView) error {
	db := u.vault.db

	users, err := ListUsers(r.Context(), db)
	if err != nil {
		return err
	}
	machines, err := ListMachines(r.Context(), db)
	if err != nil {
		return err
	}
	envs, err := ListAuditEnvironments(r.Context(), db)
	if err != nil {
		return err
	}

	// 表記は一覧の「実行者」列と揃える(auditSubject)。
	view.Actors = make([]auditOption, 0, len(users)+len(machines)+1)
	for _, user := range users {
		ident := actorUser(user.ID)
		view.Actors = append(view.Actors, auditOption{Value: ident, Label: auditSubject(ident, user.Username)})
	}
	for _, m := range machines {
		ident := actorMachine(m.ID)
		view.Actors = append(view.Actors, auditOption{Value: ident, Label: auditSubject(ident, m.Name)})
	}
	view.Actors = append(view.Actors, auditOption{Value: ActorAnonymous, Label: ActorAnonymous})

	view.Actions = make([]string, 0, len(auditActions))
	for action := range auditActions {
		view.Actions = append(view.Actions, string(action))
	}
	slices.Sort(view.Actions)

	view.Envs = make([]auditOption, 0, len(envs))
	for _, e := range envs {
		label := e.ProjectSlug + "/" + e.EnvSlug
		if e.Deleted {
			// slug は再利用できるので、削除済みのものは区別して見せる。
			label += "(削除済み)"
		}
		view.Envs = append(view.Envs, auditOption{Value: strconv.FormatInt(e.EnvironmentID, 10), Label: label})
	}
	return nil
}
