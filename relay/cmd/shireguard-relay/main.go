package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/shireguard/relay/internal/relay"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	showVersion := flag.Bool("version", false, "Print version and exit")
	port := flag.Int("port", 8080, "HTTP port for registration/health endpoints")
	udpBase := flag.Int("udp-base", 51821, "Base UDP port for relay slots")
	token := flag.String("token", "", "Shared secret for relay registration auth")
	host := flag.String("host", "", "Public hostname or IP of this relay server")
	tlsCert := flag.String("tls-cert", "", "Path to TLS certificate file (enables HTTPS)")
	tlsKey := flag.String("tls-key", "", "Path to TLS private key file (enables HTTPS)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("shireguard-relay %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	if *token == "" {
		log.Fatal("--token flag is required")
	}
	if *host == "" {
		log.Fatal("--host flag is required")
	}

	// Allow env vars as fallback for TLS paths (useful for systemd/Docker deployments)
	certFile := *tlsCert
	keyFile := *tlsKey
	if certFile == "" {
		certFile = os.Getenv("RELAY_TLS_CERT")
	}
	if keyFile == "" {
		keyFile = os.Getenv("RELAY_TLS_KEY")
	}

	srv := relay.NewServer(*host, *udpBase, *token, version, commit)
	proto := "HTTP"
	if certFile != "" && keyFile != "" {
		proto = "HTTPS"
	}
	log.Printf("Starting shireguard relay %s on %s: %s :%d, UDP base :%d", version, *host, proto, *port, *udpBase)
	log.Fatal(srv.ListenAndServe(fmt.Sprintf(":%d", *port), certFile, keyFile))
}
