// certctl is the certchain command-line client.
//
// Usage:
//
//	certctl [--api <url>] <command> [args...]
//
// Commands:
//
//	status                  Print chain height, peers, and cert count.
//	cert list               List active certificates.
//	cert get <cn>           Print metadata for the certificate with common name <cn>.
//	cert get-id <hex>       Print metadata for the certificate with cert_id <hex>.
//	cert der <hex>          Download and print DER bytes (or save with --out <file>).
//	cert status <cn>        Print status of the certificate with common name <cn>.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const defaultAPI = "http://localhost:9879"

var apiBase string

func main() {
	flag.StringVar(&apiBase, "api", defaultAPI, "certchain query API base URL")
	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	cmd := args[0]
	rest := args[1:]

	var err error
	switch cmd {
	case "status":
		err = runStatus()
	case "cert":
		err = runCert(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n", cmd)
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// ---- subcommand dispatch ----

func runStatus() error {
	body, err := apiGet("/status", nil)
	if err != nil {
		return err
	}
	prettyPrint(body)
	return nil
}

func runCert(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("cert requires a subcommand: list, get, get-id, der, status")
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "list":
		return runCertList(rest)
	case "get":
		return runCertGet(rest)
	case "get-id":
		return runCertGetByID(rest)
	case "der":
		return runCertDER(rest)
	case "status":
		return runCertStatus(rest)
	default:
		return fmt.Errorf("unknown cert subcommand: %q", sub)
	}
}

func runCertList(args []string) error {
	fs := flag.NewFlagSet("cert list", flag.ExitOnError)
	page := fs.Int("page", 1, "page number")
	limit := fs.Int("limit", 50, "results per page")
	_ = fs.Parse(args)

	params := url.Values{}
	params.Set("page", fmt.Sprint(*page))
	params.Set("limit", fmt.Sprint(*limit))

	body, err := apiGet("/cert/list", params)
	if err != nil {
		return err
	}
	prettyPrint(body)
	return nil
}

func runCertGet(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("cert get requires a common name")
	}
	params := url.Values{}
	params.Set("cn", args[0])
	body, err := apiGet("/cert", params)
	if err != nil {
		return err
	}
	prettyPrint(body)
	return nil
}

func runCertGetByID(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("cert get-id requires a cert_id hex")
	}
	params := url.Values{}
	params.Set("id", args[0])
	body, err := apiGet("/cert", params)
	if err != nil {
		return err
	}
	prettyPrint(body)
	return nil
}

func runCertDER(args []string) error {
	fs := flag.NewFlagSet("cert der", flag.ExitOnError)
	out := fs.String("out", "", "output file (defaults to stdout)")
	_ = fs.Parse(args)
	rest := fs.Args()

	if len(rest) == 0 {
		return fmt.Errorf("cert der requires a cert_id hex")
	}
	hexID := rest[0]

	urlStr := fmt.Sprintf("%s/cert/%s/der", strings.TrimRight(apiBase, "/"), hexID)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(urlStr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if *out != "" {
		if err := os.WriteFile(*out, data, 0644); err != nil {
			return err
		}
		fmt.Printf("DER saved to %s (%d bytes)\n", *out, len(data))
	} else {
		_, _ = os.Stdout.Write(data)
	}
	return nil
}

func runCertStatus(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("cert status requires a common name")
	}
	params := url.Values{}
	params.Set("cn", args[0])
	body, err := apiGet("/cert", params)
	if err != nil {
		return err
	}

	// Extract just the status field for a quick summary.
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		prettyPrint(body)
		return nil
	}

	fmt.Printf("cn:          %v\n", m["cn"])
	fmt.Printf("cert_id:     %v\n", m["cert_id"])
	fmt.Printf("status:      %v\n", m["status"])
	fmt.Printf("not_before:  %v\n", unixToTime(m["not_before"]))
	fmt.Printf("not_after:   %v\n", unixToTime(m["not_after"]))
	return nil
}

// ---- helpers ----

func apiGet(path string, params url.Values) ([]byte, error) {
	u, err := url.Parse(strings.TrimRight(apiBase, "/") + path)
	if err != nil {
		return nil, err
	}
	if params != nil {
		u.RawQuery = params.Encode()
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func prettyPrint(data []byte) {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		fmt.Println(string(data))
		return
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func unixToTime(v interface{}) string {
	switch x := v.(type) {
	case float64:
		return time.Unix(int64(x), 0).UTC().Format(time.RFC3339)
	default:
		return fmt.Sprint(v)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `certctl — certchain CLI

Usage: certctl [--api <url>] <command> [args...]

Commands:
  status                  Chain height, peer count, cert count
  cert list               List active certificates
  cert get <cn>           Cert metadata by Common Name
  cert get-id <hex>       Cert metadata by cert_id
  cert der <hex>          Download DER (--out <file> to save)
  cert status <cn>        Certificate status summary

Flags:
`)
	flag.PrintDefaults()
}
