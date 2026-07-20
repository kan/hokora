package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var rateBase = time.Unix(1700000000, 0)

func TestRateLimiterAllow(t *testing.T) {
	t.Parallel()

	r := newRateLimiter(3, 16)

	for i := range 3 {
		if !r.Allow(globalKey, rateBase) {
			t.Fatalf("attempt %d was rejected within the limit", i+1)
		}
	}
	if r.Allow(globalKey, rateBase) {
		t.Fatal("the 4th attempt was allowed")
	}
	// ウィンドウ内は何度試しても通らない。
	if r.Allow(globalKey, rateBase.Add(59*time.Second)) {
		t.Fatal("an attempt inside the window was allowed")
	}
	// ウィンドウが切り替われば再び通る。
	if !r.Allow(globalKey, rateBase.Add(time.Minute)) {
		t.Fatal("the first attempt in the next window was rejected")
	}
}

// unseal の制限はグローバルである。キーを変えて回避できない
// (攻撃者が変えられる値でキーを分けない。AGENTS.md ルール 35 と同じ理由)。
func TestUnsealLimiterIsGlobal(t *testing.T) {
	t.Parallel()

	r := newRateLimiter(unsealRate, 1)
	for range unsealRate {
		if !r.Allow(globalKey, rateBase) {
			t.Fatal("an attempt within the limit was rejected")
		}
	}
	if r.Allow(globalKey, rateBase) {
		t.Fatal("more than the configured number of unseal attempts was allowed")
	}
	if r.Len() != 1 {
		t.Errorf("Len = %d, want 1 (a single global bucket)", r.Len())
	}
}

// **拒否された試行はウィンドウを延ばさない。** 延びる実装だと、攻撃者が
// 連打し続けるだけで正規の操作(unseal)を永久に締め出せる。
func TestRateLimiterRejectionDoesNotExtendTheWindow(t *testing.T) {
	t.Parallel()

	r := newRateLimiter(2, 16)
	for range 2 {
		if !r.Allow(globalKey, rateBase) {
			t.Fatal("an attempt within the limit was rejected")
		}
	}
	// 上限に達した後、ウィンドウの終わりまで連打する。
	for i := range 10 {
		at := rateBase.Add(time.Duration(i) * time.Second)
		if r.Allow(globalKey, at) {
			t.Fatalf("an attempt over the limit was allowed at +%ds", i)
		}
	}
	// 最初の試行から 1 分後には、拒否の連打があっても通る。
	if !r.Allow(globalKey, rateBase.Add(rateWindow)) {
		t.Fatal("rejected attempts pushed the window forward")
	}
}

// ウィンドウ境界は「windowEnds を過ぎたら次のウィンドウ」である。
// 1 ナノ秒単位で確かめる(秒単位の確認では off-by-one を見逃す)。
func TestRateLimiterWindowBoundary(t *testing.T) {
	t.Parallel()

	windowEnds := rateBase.Add(rateWindow)

	tests := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"just before the window ends", windowEnds.Add(-time.Nanosecond), false},
		{"exactly at the window end", windowEnds, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := newRateLimiter(1, 16)
			if !r.Allow(globalKey, rateBase) {
				t.Fatal("the first attempt was rejected")
			}
			if got := r.Allow(globalKey, tt.now); got != tt.want {
				t.Errorf("Allow at %v = %v, want %v", tt.now, got, tt.want)
			}
		})
	}
}

// 新しいウィンドウではカウンタが 0 から始まる(繰り越されない)。
func TestRateLimiterResetsCountInTheNextWindow(t *testing.T) {
	t.Parallel()

	r := newRateLimiter(3, 16)
	for range 3 {
		r.Allow(globalKey, rateBase)
	}

	next := rateBase.Add(rateWindow)
	for i := range 3 {
		if !r.Allow(globalKey, next) {
			t.Fatalf("attempt %d in the new window was rejected", i+1)
		}
	}
	if r.Allow(globalKey, next) {
		t.Error("the limit was not applied in the new window")
	}
}

func TestRateLimiterSeparatesKeys(t *testing.T) {
	t.Parallel()

	r := newRateLimiter(1, 16)
	if !r.Allow("a", rateBase) || !r.Allow("b", rateBase) {
		t.Fatal("independent keys interfered with each other")
	}
	if r.Allow("a", rateBase) {
		t.Fatal("the limit was not applied per key")
	}
}

// map が埋まったら新しいキーを拒否する。**追い出さない。**
// 追い出しを許すと、map を埋める攻撃で他のキーのカウンタをリセットできる。
func TestRateLimiterRejectsNewKeysWhenFull(t *testing.T) {
	t.Parallel()

	r := newRateLimiter(5, 2)
	if !r.Allow("a", rateBase) || !r.Allow("b", rateBase) {
		t.Fatal("attempts within the limit were rejected")
	}
	if r.Allow("c", rateBase) {
		t.Fatal("a new key was accepted while the map was full")
	}
	// 既存のキーは引き続き使える(締め出されない)。
	if !r.Allow("a", rateBase) {
		t.Error("an existing key was rejected while the map was full")
	}

	// ウィンドウが切れれば掃除され、新しいキーが入る。
	next := rateBase.Add(time.Minute)
	if !r.Allow("c", next) {
		t.Error("a new key was rejected after the old buckets expired")
	}
}

func TestRateLimiterSweep(t *testing.T) {
	t.Parallel()

	r := newRateLimiter(1, 16)
	r.Allow("a", rateBase)
	r.Allow("b", rateBase.Add(30*time.Second))

	if n := r.Sweep(rateBase.Add(time.Minute)); n != 1 {
		t.Errorf("Sweep removed %d, want 1", n)
	}
	if r.Len() != 1 {
		t.Errorf("Len = %d, want 1", r.Len())
	}
}

func TestRateLimiterDefaultMaxKeys(t *testing.T) {
	t.Parallel()

	if r := newRateLimiter(1, 0); r.max != defaultMaxBuckets {
		t.Errorf("max = %d, want %d", r.max, defaultMaxBuckets)
	}
}

// argon2 の同時実行数が semaphore で制限されていること(DESIGN §7.4)。
// 制限が効いていないと、unseal の連打で 64 MB × n の確保が積み上がる。
func TestArgon2SemaphoreLimitsConcurrency(t *testing.T) {
	// argon2Sem はパッケージ全体で共有されるため、このテストは並列にしない。
	var (
		running atomic.Int32
		peak    atomic.Int32
		wg      sync.WaitGroup
	)

	release := make(chan struct{})
	const goroutines = argon2Slots * 3

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := withArgon2Slot(context.Background(), func() error {
				n := running.Add(1)
				for {
					old := peak.Load()
					if n <= old || peak.CompareAndSwap(old, n) {
						break
					}
				}
				<-release
				running.Add(-1)
				return nil
			})
			if err != nil {
				t.Errorf("withArgon2Slot: %v", err)
			}
		}()
	}

	// スロットが埋まるのを待ってから解放する。
	deadline := time.After(5 * time.Second)
	for running.Load() < argon2Slots {
		select {
		case <-deadline:
			t.Fatalf("only %d goroutines entered the semaphore", running.Load())
		default:
		}
	}
	close(release)
	wg.Wait()

	if got := peak.Load(); got > argon2Slots {
		t.Errorf("%d goroutines ran concurrently, want at most %d", got, argon2Slots)
	}
}

// スロットが空かないとき、ctx のキャンセルで待たずに戻る。
func TestArgon2SlotRespectsContext(t *testing.T) {
	// argon2Sem を埋めるので並列にしない。
	release := make(chan struct{})
	var wg sync.WaitGroup
	for range argon2Slots {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := withArgon2Slot(context.Background(), func() error {
				<-release
				return nil
			}); err != nil {
				t.Errorf("withArgon2Slot: %v", err)
			}
		}()
	}
	defer func() {
		close(release)
		wg.Wait()
	}()

	// 全スロットが埋まるまで待つ。
	for len(argon2Sem) < argon2Slots {
		time.Sleep(time.Millisecond)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	called := false
	err := withArgon2Slot(ctx, func() error {
		called = true
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
	if called {
		t.Error("fn ran even though the context was cancelled")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b []byte
		want bool
	}{
		{"equal", []byte("secret"), []byte("secret"), true},
		{"different", []byte("secret"), []byte("secrer"), false},
		{"different length", []byte("secret"), []byte("secrets"), false},
		{"empty", []byte{}, []byte{}, true},
		{"nil and empty", nil, []byte{}, true},
		{"one empty", []byte("x"), nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := constantTimeEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("constantTimeEqual = %v, want %v", got, tt.want)
			}
		})
	}
}
