package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// argon2Slots は argon2 の同時実行数の上限である(DESIGN §7.4)。
//
// argon2 は 1 回あたり 64 MB を確保する。同時実行を野放しにすると、
// unseal の連打だけでメモリを食い潰せてしまう。
//
// argon2 が走るのは unseal / rotate-master の KEK 導出と、Web UI の
// パスワード検証だけである。**Machine API の認証は SHA-256 なのでここを
// 通らない**(AGENTS.md ルール 7)。
const argon2Slots = 4

var argon2Sem = make(chan struct{}, argon2Slots)

// withArgon2Slot は argon2 のスロットを確保して fn を実行する。
//
// ctx がキャンセルされたら待たずに戻る。待ち行列に無制限に積み上がると、
// 上限を設けた意味が薄れるため。
func withArgon2Slot(ctx context.Context, fn func() error) error {
	select {
	case argon2Sem <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("waiting for an argon2 slot: %w", ctx.Err())
	}
	defer func() { <-argon2Sem }()
	return fn()
}

// constantTimeEqual は秘密同士を定数時間で比較する(AGENTS.md ルール 4)。
//
// ConstantTimeCompare は長さが違うと 0 を返すが、**長さの違いは分岐で漏れる**。
// 秘密の長さは固定であることが前提なので、長さ不一致は先に落としてよい。
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ---- レート制限(DESIGN §7.4) ----

// rateWindow はレート制限のウィンドウである。
//
// DESIGN §7.4 の制限は全て「回/分」で定義されているので、ウィンドウは
// 固定にしてある。異なるウィンドウが必要になったら、そのときに
// パラメータへ戻すこと(使われない設定項目を先回りで作らない)。
const rateWindow = time.Minute

// unsealRate は unseal の制限である。**グローバル**に効かせる。
const unsealRate = 3

// Machine API の認証に対する制限(DESIGN §7.4)。
//
// **第一段は送信元 IP である**(AGENTS.md ルール 35)。client_id はリクエスト
// ボディに入っている攻撃者制御の値なので、そちらだけで制限すると、値を
// 変えるだけで無制限に試行できてしまう。第二段の client_id 制限は、1 つの
// credential に対する総当たりを鈍らせるための追加の網である。
//
// **第二段の上限は、machine ごとに変えられる**(machines.auth_rate_per_minute)。
// authTokenRatePerClientID は既定値であり、設定できる値の下限でもある。上限は
// authTokenRatePerIP である: 第一段は変えないので、それを超える値は効かない
// (効かない値を設定できると、「上げたのに弾かれる」になる)。
const (
	authTokenRatePerIP       = 30
	authTokenRatePerClientID = 10
)

// authRateOf は、保存された値(machines.auth_rate_per_minute)から、実際に
// 使う上限を返す。NULL は既定値である。
//
// **範囲の外の値は、範囲に収める。** 画面からは範囲の外の値を保存できない。
// それでも読む側で収めるのは、定数を変えた後に、古い範囲で保存された値が
// 残るためである。
func authRateOf(stored sql.NullInt64) int {
	if !stored.Valid {
		return authTokenRatePerClientID
	}
	return int(min(max(stored.Int64, authTokenRatePerClientID), authTokenRatePerIP))
}

// globalKey は「キーで分けない」制限に使う固定キーである。
//
// unseal をグローバルに制限するのは、送信元 IP でも MK 入力でも分けたくない
// ためである。攻撃者制御の値でキーを分けると、その値を変えるだけで制限を
// 回避できる(AGENTS.md ルール 35 と同じ理由)。
const globalKey = "global"

// bucket は固定ウィンドウのカウンタである。
type bucket struct {
	count      int
	windowEnds time.Time
}

// rateLimiter はキーごとの固定ウィンドウ制限である。
//
// **上限つき map は制限の回避手段にもなる。** 多数のキーを持つ攻撃者は map を
// 埋めることで正規のバケットを追い出し、カウンタをリセットできる。これは
// プロセス内レート制限の原理的限界であり、N7 の枠内として受容する
// (DESIGN §7.4)。上限は「メモリ枯渇を防ぐ」ためのものであって、
// 「制限を保証する」ものではない。
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	limit   int
	max     int
}

// defaultMaxBuckets はレート制限の map に保持するキー数の上限である。
const defaultMaxBuckets = 4096

func newRateLimiter(limit, maxKeys int) *rateLimiter {
	if maxKeys <= 0 {
		maxKeys = defaultMaxBuckets
	}
	return &rateLimiter{
		buckets: make(map[string]*bucket),
		limit:   limit,
		max:     maxKeys,
	}
}

// Allow は 1 回ぶんの試行を記録し、許可するかどうかを返す。
func (r *rateLimiter) Allow(key string, now time.Time) bool {
	ok, _ := r.AllowWait(key, now)
	return ok
}

// AllowWait は Allow と同じで、拒否したときに、次に試してよくなるまでの時間も返す。
func (r *rateLimiter) AllowWait(key string, now time.Time) (bool, time.Duration) {
	return r.Take(key, r.limit, now)
}

// Take は、上限を呼び出しごとに指定して 1 回ぶんの試行を記録する。
// **作ったときの上限(Allow / AllowWait が使う値)は見ない。** キーごとに上限が
// 違う制限(machine ごとの認証の上限)のためのものである。
//
// 拒否したときは、**次に試してよくなるまでの時間**(窓が明けるまで)も返す。
//
// **limit は、攻撃者が変えられない値から決めること。** キーが攻撃者制御の値
// (client_id)でも、上限は DB に保存された設定から引く。上限を途中で下げた
// ときは、その窓の残りにもすぐ効く(数えた回数は持ち越す)。
func (r *rateLimiter) Take(key string, limit int, now time.Time) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.buckets[key]
	if !ok || !now.Before(b.windowEnds) {
		if !ok && len(r.buckets) >= r.max {
			r.sweepLocked(now)
			if len(r.buckets) >= r.max {
				// 新しいキーを受け入れられない。**拒否側に倒す。**
				// 追い出しを許すと、map を埋める攻撃で他のキーのカウンタを
				// リセットできてしまう。いつ空くかは分からないので、
				// 待ち時間は窓 1 つぶんを返す。
				return false, rateWindow
			}
		}
		b = &bucket{}
		r.buckets[key] = b
		b.windowEnds = now.Add(rateWindow)
		b.count = 0
	}

	if b.count >= limit {
		return false, b.windowEnds.Sub(now)
	}
	b.count++
	return true, 0
}

// retryAfterSeconds は Retry-After ヘッダに入れる秒数を返す。
//
// **切り上げる。** 切り捨てると、言われたとおりに待ったクライアントが、窓が
// 明ける直前にもう 1 回弾かれる。0 は「すぐ再試行してよい」と読めるので返さない。
func retryAfterSeconds(wait time.Duration) int {
	return max(1, int((wait+time.Second-1)/time.Second))
}

// Sweep は期限切れのバケットを削除し、削除件数を返す。
func (r *rateLimiter) Sweep(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sweepLocked(now)
}

// Len は保持しているバケット数を返す(テストと運用の観測用)。
func (r *rateLimiter) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets)
}

func (r *rateLimiter) sweepLocked(now time.Time) int {
	n := 0
	for key, b := range r.buckets {
		if !now.Before(b.windowEnds) {
			delete(r.buckets, key)
			n++
		}
	}
	return n
}
