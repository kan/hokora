//go:build !linux

package main

import (
	"strings"
	"testing"
)

// Linux 以外では **必ず失敗する**(mlock_other.go)。
//
// hokora は mlockall が効かない環境で起動してはならない(DESIGN §4.2)。
// 「開発機でビルドが通る」ことと「そこで serve してよい」ことは別である。
// このテストは linux ではビルド対象にならないため、CI が linux だけだと
// 実行されない。それでも置いておくのは、非 linux でスタブが「成功を返す」
// 実装に差し替わったときに気付ける唯一の場所だからである。
func TestLockMemoryFailsOnNonLinux(t *testing.T) {
	t.Parallel()

	err := lockMemory()
	if err == nil {
		t.Fatal("lockMemory succeeded on a platform without mlockall support")
	}
	if !strings.Contains(err.Error(), "mlockall") {
		t.Errorf("error = %v, want it to mention mlockall", err)
	}
}
