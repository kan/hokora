# hokora SDK

Go client for a [hokora](https://github.com/kan/hokora) secret-management
server. It exchanges a machine credential for a short-lived token and returns
the granted secrets **in memory** — it never writes them to disk and keeps no
cache.

```
go get github.com/kan/hokora/sdk
```

**Full API reference:**
[pkg.go.dev/github.com/kan/hokora/sdk](https://pkg.go.dev/github.com/kan/hokora/sdk)

```go
import hokora "github.com/kan/hokora/sdk"

client, err := hokora.New()          // resolves $CREDENTIALS_DIRECTORY/hokora, then the env
secrets, err := client.Fetch(ctx)
dsn := secrets.MustGetString("DATABASE_URL")
defer secrets.Zero()                 // best effort; see the caveats below
```

Configuration is resolved in order: options → credentials file
(`$CREDENTIALS_DIRECTORY/hokora` under systemd, or `WithCredentialsFile`) → the
`HOKORA_ADDR` / `HOKORA_CLIENT_ID` / `HOKORA_CLIENT_SECRET` / `HOKORA_PROJECT` /
`HOKORA_ENV` environment variables.

This package depends on the **Go standard library only**.

## Security

This SDK does not defend against an attacker who has your application's OS user
— they can read the same credential and fetch the same secrets, or read your
process memory. It cannot stop the OS from writing memory to disk via swap, core
dumps, or kernel crash dumps, and `Zero` is best-effort (values obtained through
`GetString` are immutable Go strings and cannot be overwritten). It never
disables TLS verification. See the project's
[threat model](https://github.com/kan/hokora/blob/master/docs/THREAT_MODEL.md).
