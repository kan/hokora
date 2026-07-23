module github.com/kan/hokora

go 1.26

toolchain go1.26.5

require (
	github.com/kan/hokora/sdk v0.0.0
	golang.org/x/crypto v0.54.0
	golang.org/x/sys v0.47.0
	modernc.org/sqlite v1.54.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/pprof v0.0.0-20260115054156-294ebfa9ad83 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/tools v0.48.0 // indirect
	modernc.org/libc v1.74.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

// SDK は別 module だが、サーバー本体は **常にツリー内の sdk/ をビルドする**。
// require の版と実際にビルドされる版がずれる経路(go install で published
// 版が引かれる等)を作らないための恒久的な replace である。
// このため `go install github.com/kan/hokora@version` は使えない。
// インストールは Releases のバイナリか clone + `make build`(README 参照)。
replace github.com/kan/hokora/sdk => ./sdk
