// certd is the certchain daemon.
//
// It manages a certchain blockchain node: polls AppViewX for new or revoked
// certificates, maintains the local chain and cert store, syncs with peers,
// and exposes the HTTP query API on :9879.
//
// Usage:
//
//	certd [--config <dir>] [--avx-url <url>] [--avx-key <key>]
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/amosdavis/certchain/internal/certd"
)

func main() {
	cfg := certd.ParseFlags(os.Args[1:])
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := certd.Run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}
