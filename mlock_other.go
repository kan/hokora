//go:build !linux

package main

import "errors"

// lockMemory は Linux 以外では常に失敗する。
//
// hokora は Linux + systemd を前提としたサーバーであり(DESIGN §4.3)、
// swap への流出を止められない環境で起動させない。開発機でビルドが通ることと、
// そこで serve できることは別である。
func lockMemory() error {
	return errors.New("mlockall is only supported on linux; hokora must not run without it")
}
