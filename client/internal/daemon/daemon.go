package daemon

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/shireguard/shireguard/internal/api"
	"github.com/shireguard/shireguard/internal/config"
	"github.com/shireguard/shireguard/internal/wg"
)

const (
	heartbeatInterval = 30 * time.Second
	peerSyncInterval  = 15 * time.Second
)

type Daemon struct {
	cfg    *config.Config
	client *api.Client
	tunnel *wg.Tunnel
}

func New(cfg *config.Config) *Daemon {
	client := api.New(cfg.APIURL, cfg.AccessToken, cfg.RefreshToken, func(access, refresh string) {
		cfg.AccessToken = access
		cfg.RefreshToken = refresh
		_ = cfg.Save()
	})

	return &Daemon{
		cfg:    cfg,
		client: client,
		tunnel: wg.NewTunnel(),
	}
}

func (d *Daemon) Run(ctx context.Context) error {
	if !d.cfg.IsLoggedIn() {
		return fmt.Errorf("not logged in — run 'shireguard login' first")
	}
	if !d.cfg.IsRegistered() {
		return fmt.Errorf("device not registered — run 'shireguard register' first")
	}

	// Fetch peers and bring up tunnel
	peers, err := d.client.GetPeers(d.cfg.NetworkID)
	if err != nil {
		return fmt.Errorf("fetching peers: %w", err)
	}

	tunnelCfg := d.buildTunnelConfig(peers)
	if err := d.tunnel.Up(tunnelCfg); err != nil {
		return fmt.Errorf("starting tunnel: %w", err)
	}
	defer d.tunnel.Down()

	log.Printf("tunnel up on %s with IP %s", wg.InterfaceName, d.cfg.AssignedIP)
	log.Printf("connected to %d peer(s)", len(tunnelCfg.Peers))

	// Run background loops
	heartbeatTicker := time.NewTicker(heartbeatInterval)
	peerSyncTicker := time.NewTicker(peerSyncInterval)
	defer heartbeatTicker.Stop()
	defer peerSyncTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down tunnel")
			return nil

		case <-heartbeatTicker.C:
			if err := d.client.Heartbeat(d.cfg.DeviceID, ""); err != nil {
				log.Printf("heartbeat failed: %v", err)
			}

		case <-peerSyncTicker.C:
			d.syncPeers()
		}
	}
}

func (d *Daemon) syncPeers() {
	peers, err := d.client.GetPeers(d.cfg.NetworkID)
	if err != nil {
		log.Printf("peer sync failed: %v", err)
		return
	}

	var peerConfigs []wg.PeerConfig
	for _, p := range peers {
		if p.ID == d.cfg.DeviceID {
			continue
		}
		pc := wg.PeerConfig{
			PublicKey:  p.PublicKey,
			AllowedIPs: []string{p.AssignedIP + "/32"},
		}
		if p.Endpoint != nil {
			pc.Endpoint = *p.Endpoint
		}
		peerConfigs = append(peerConfigs, pc)
	}

	if err := d.tunnel.UpdatePeers(peerConfigs); err != nil {
		log.Printf("updating peers: %v", err)
	}
}

func (d *Daemon) buildTunnelConfig(peers []api.Peer) *wg.TunnelConfig {
	cfg := &wg.TunnelConfig{
		PrivateKey: d.cfg.PrivateKey,
		Address:    d.cfg.AssignedIP + "/24",
		ListenPort: 51820,
	}

	for _, p := range peers {
		if p.ID == d.cfg.DeviceID {
			continue
		}
		pc := wg.PeerConfig{
			PublicKey:  p.PublicKey,
			AllowedIPs: []string{p.AssignedIP + "/32"},
		}
		if p.Endpoint != nil {
			pc.Endpoint = *p.Endpoint
		}
		cfg.Peers = append(cfg.Peers, pc)
	}

	return cfg
}
