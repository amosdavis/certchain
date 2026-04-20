// Package certd implements the core certchain daemon logic.
//
// It provides configuration parsing, HTTP server setup, blockchain
// management, AppViewX polling, and Kubernetes integration. The package
// separates concerns across multiple files:
//
//   - config.go: flag parsing and configuration
//   - server.go: Server orchestration and lifecycle
//   - http.go: HTTP handlers and authentication
//   - chain.go: blockchain initialization and persistence
//   - signing.go: transaction signing and block submission
//   - readiness.go: readiness probe handling
//
// The main certd binary (cmd/certd) is a thin wrapper that calls
// ParseFlags and Run.
package certd
