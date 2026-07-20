//go:build linux

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// lockMemory は プロセスの全メモリを RAM に固定する(DESIGN §4.2)。
//
// **失敗したら起動を中止する。** mlockall が効いていなければ、DEK を含む
// メモリが swap に書き出されうる。T3(ディスクを持ち去られる)に対する防御が
// 成立しないまま「動いている」状態が、最も危険である。
//
// 失敗の原因はほぼ RLIMIT_MEMLOCK の不足なので、エラーにその手当を書く。
// systemd unit には LimitMEMLOCK=infinity が必須である。
//
// mlockall は swap への流出を止めるだけで、core dump / kdump は止められない。
// そちらはホスト側で無効化する(THREAT_MODEL §5.3)。
func lockMemory() error {
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		return fmt.Errorf("mlockall failed (LimitMEMLOCK=infinity is required): %w", err)
	}
	return nil
}
