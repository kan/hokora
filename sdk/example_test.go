package hokora_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	hokora "github.com/kan/hokora/sdk"
)

// The most common use: New resolves the credential from the environment set by
// systemd's LoadCredential=, then Fetch returns every granted secret. Keep the
// values in memory and Zero them when done.
func Example() {
	client, err := hokora.New() // reads $CREDENTIALS_DIRECTORY/hokora, then the environment
	if err != nil {
		log.Fatal(err)
	}

	secrets, err := client.Fetch(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer secrets.Zero()

	dsn := secrets.MustGetString("DATABASE_URL")
	fmt.Println(len(dsn))
}

// Configure the client explicitly instead of relying on the environment.
func ExampleNew_options() {
	client, err := hokora.New(
		hokora.WithAddress("https://hokora.example.com:9443"),
		hokora.WithCredentials("app-prod", os.Getenv("APP_HOKORA_SECRET")),
		hokora.WithProject("myapp"),
		hokora.WithEnv("prod"),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = client
}

// FetchKey retrieves a single secret. Prefer it over Fetch when you need one
// value: only that key is read and audited on the server. A key that does not
// exist is reported as ErrForbidden, indistinguishable from a missing grant.
func ExampleClient_FetchKey() {
	client, err := hokora.New()
	if err != nil {
		log.Fatal(err)
	}

	secrets, err := client.FetchKey(context.Background(), "DATABASE_URL")
	if err != nil {
		log.Fatal(err)
	}
	defer secrets.Zero()

	if v, ok := secrets.Get("DATABASE_URL"); ok {
		fmt.Println(len(v))
	}
}

// To trust a server certificate issued by an internal CA, load the CA into a
// pool and pass it with WithRootCAs. This replaces the system roots; seed the
// pool from x509.SystemCertPool first if you need both. There is no option to
// skip verification.
func ExampleWithRootCAs() {
	pem, err := os.ReadFile("/etc/hokora/internal-ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		log.Fatal("no certificates found in the CA file")
	}

	client, err := hokora.New(hokora.WithRootCAs(pool))
	if err != nil {
		log.Fatal(err)
	}
	_ = client
}

// Fetch does not cache; call it again to pick up rotated values. Give each
// call a bounded context.
func ExampleClient_Fetch_refresh() {
	client, err := hokora.New()
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	secrets, err := client.Fetch(ctx)
	if err != nil {
		log.Print(err)
		return
	}
	defer secrets.Zero()

	fmt.Println(secrets.Len())
}
