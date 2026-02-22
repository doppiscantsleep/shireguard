package main

import (
	"flag"
	"fmt"
	"log"

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

	srv := relay.NewServer(*host, *udpBase, *token, version, commit)
	log.Printf("Starting shireguard relay %s on %s: HTTP :%d, UDP base :%d", version, *host, *port, *udpBase)
	log.Fatal(srv.ListenAndServe(fmt.Sprintf(":%d", *port)))
}
