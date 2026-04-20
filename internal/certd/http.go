package certd

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// resolveSecret returns the secret material from the first available
// source: a file (preferred, to keep secrets off argv and environment),
// then a flag value, then an environment variable. A missing file path
// produces no error (secret simply stays empty); an unreadable path is
// fatal because the caller explicitly asked for file-based config.
// Trailing CR/LF are trimmed so operators can `echo "$SECRET" > file`
// without accidentally embedding a newline in the credential. See CM-26.
func resolveSecret(path, flagValue, envKey string) ([]byte, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return bytes.TrimRight(data, "\r\n"), nil
	}
	if flagValue != "" {
		return []byte(flagValue), nil
	}
	if envKey != "" {
		if v := os.Getenv(envKey); v != "" {
			return []byte(v), nil
		}
	}
	return nil, nil
}

// queryAuthMiddleware Bearer-token-protects the HTTP query API (CM-26).
//
// Requests to paths in the allowlist (/healthz, /readyz, /metrics) are
// always passed through so Kubernetes probes and Prometheus scrapes keep
// working without credentials. When token is empty the middleware is a
// no-op (legacy / dev mode); callers are expected to log a WARN at
// startup so operators notice the degraded posture.
//
// Tokens are compared with crypto/subtle.ConstantTimeCompare to close
// the timing side-channel on a per-byte string comparison.
func queryAuthMiddleware(next http.Handler, token []byte) http.Handler {
	allow := map[string]struct{}{
		"/healthz": {},
		"/readyz":  {},
		"/metrics": {},
	}
	const bearerPrefix = "Bearer "
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := allow[r.URL.Path]; ok {
			next.ServeHTTP(w, r)
			return
		}
		if len(token) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, bearerPrefix) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="certchain"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		provided := []byte(authz[len(bearerPrefix):])
		if subtle.ConstantTimeCompare(provided, token) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="certchain"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
