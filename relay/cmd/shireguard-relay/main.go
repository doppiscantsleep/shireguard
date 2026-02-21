package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/shireguard/relay/internal/relay"
)

func main() {
	port := flag.Int("port", 8080, "HTTP port for registration/health endpoints")
	udpBase := flag.Int("udp-base", 51821, "Base UDP port for relay slots")
	token := flag.String("token", "", "Shared secret for relay registration auth")
	host := flag.String("host", "", "Public hostname or IP of this relay server")
	flag.Parse()

	if *token == "" {
		log.Fatal("--token flag is required")
	}
	if *host == "" {
		log.Fatal("--host flag is required")
	}

	srv := relay.NewServer(*host, *udpBase, *token)
	log.Printf("Starting shireguard relay on %s: HTTP :%d, UDP base :%d", *host, *port, *udpBase)
	log.Fatal(srv.ListenAndServe(fmt.Sprintf(":%d", *port)))
}
