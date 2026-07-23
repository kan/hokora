// hokora の Go SDK。**アプリケーションに配る唯一の Go 依存であり、
// 標準ライブラリ以外に何も要求しない。**
//
// root(サーバー本体)とは別 module にしてある。同じ module に置くと、
// SDK しか import していない利用側にも modernc.org/sqlite などサーバーの
// 依存が module graph として伝播し、`go` ディレクティブ(利用側への最低
// 言語バージョン強制)もサーバー側の都合で引き上げられてしまうため。
//
// go 行は **利用側への最低要求** である。SDK 本体は go1.21 でもビルドできる
// が、テストが t.Context を使うため 1.24 を下限とする。安易に上げないこと。
// toolchain は root と揃える(`make toolchain-check` が検査する)。
module github.com/kan/hokora/sdk

go 1.24

toolchain go1.26.5
