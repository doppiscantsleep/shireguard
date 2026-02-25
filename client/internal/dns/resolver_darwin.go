//go:build darwin

package dns

import (
	"fmt"
	"net"
	"os"
)

const resolverDir = "/etc/resolver"
const resolverFile = "/etc/resolver/shireguard"

// InstallResolverStub writes the macOS per-domain resolver stub so that
// the OS forwards all *.shireguard queries to our local DNS server.
func InstallResolverStub(listenAddr string) error {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf("invalid listenAddr %q: %w", listenAddr, err)
	}

	if err := os.MkdirAll(resolverDir, 0755); err != nil {
		return fmt.Errorf("creating %s: %w", resolverDir, err)
	}

	content := fmt.Sprintf("nameserver %s\nport %s\n", host, port)
	if err := os.WriteFile(resolverFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", resolverFile, err)
	}
	return nil
}

// RemoveResolverStub removes the macOS per-domain resolver stub.
func RemoveResolverStub() error {
	err := os.Remove(resolverFile)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
