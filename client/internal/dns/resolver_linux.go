//go:build linux

package dns

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

const resolvedDropinDir = "/etc/systemd/resolved.conf.d"
const resolvedDropinFile = "/etc/systemd/resolved.conf.d/shireguard.conf"

// InstallResolverStub configures the OS to forward *.shireguard queries to
// our local DNS server. Prefers systemd-resolved; falls back to /etc/resolv.conf.
func InstallResolverStub(listenAddr string) error {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf("invalid listenAddr %q: %w", listenAddr, err)
	}

	if isSystemdResolved() {
		return installSystemdResolved(host, port)
	}
	return installResolvConf(host)
}

// RemoveResolverStub removes the resolver stub created by InstallResolverStub.
func RemoveResolverStub() error {
	// Try systemd-resolved dropin first
	err := os.Remove(resolvedDropinFile)
	if err == nil {
		_ = exec.Command("systemctl", "reload", "systemd-resolved").Run()
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	// Try /etc/resolv.conf cleanup
	return removeResolvConf()
}

func isSystemdResolved() bool {
	out, err := exec.Command("systemctl", "is-active", "systemd-resolved").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}

func installSystemdResolved(host, port string) error {
	if err := os.MkdirAll(resolvedDropinDir, 0755); err != nil {
		return fmt.Errorf("creating %s: %w", resolvedDropinDir, err)
	}

	content := fmt.Sprintf("[Resolve]\nDNS=%s:%s\nDomains=~shireguard\n", host, port)
	if err := os.WriteFile(resolvedDropinFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", resolvedDropinFile, err)
	}

	if err := exec.Command("systemctl", "reload", "systemd-resolved").Run(); err != nil {
		return fmt.Errorf("reloading systemd-resolved: %w", err)
	}
	return nil
}

const resolveConfMarker = "# shireguard-start"
const resolveConfMarkerEnd = "# shireguard-end"

func installResolvConf(host string) error {
	existing, _ := os.ReadFile("/etc/resolv.conf")
	if strings.Contains(string(existing), resolveConfMarker) {
		return nil // already installed
	}

	addition := fmt.Sprintf("\n%s\nnameserver %s\nsearch shireguard\n%s\n",
		resolveConfMarker, host, resolveConfMarkerEnd)

	f, err := os.OpenFile("/etc/resolv.conf", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening /etc/resolv.conf: %w", err)
	}
	defer f.Close()
	_, err = f.WriteString(addition)
	return err
}

func removeResolvConf() error {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	content := string(data)
	start := strings.Index(content, resolveConfMarker)
	if start == -1 {
		return nil // nothing to remove
	}
	end := strings.Index(content, resolveConfMarkerEnd)
	if end == -1 {
		content = content[:start]
	} else {
		content = content[:start] + content[end+len(resolveConfMarkerEnd):]
	}

	return os.WriteFile("/etc/resolv.conf", []byte(strings.TrimRight(content, "\n")+"\n"), 0644)
}
