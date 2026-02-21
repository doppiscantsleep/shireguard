package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type Client struct {
	baseURL      string
	accessToken  string
	refreshToken string
	httpClient   *http.Client
	mu           sync.Mutex
	onTokens     func(access, refresh string)
}

func New(baseURL, accessToken, refreshToken string, onTokens func(access, refresh string)) *Client {
	return &Client{
		baseURL:      baseURL,
		accessToken:  accessToken,
		refreshToken: refreshToken,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		onTokens:     onTokens,
	}
}

// Auth

type AuthResponse struct {
	User struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
	Network *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		CIDR string `json:"cidr"`
	} `json:"network,omitempty"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (c *Client) Register(email, password string) (*AuthResponse, error) {
	var resp AuthResponse
	err := c.doPublic("POST", "/v1/auth/register", map[string]string{
		"email": email, "password": password,
	}, &resp)
	if err != nil {
		return nil, err
	}
	c.setTokens(resp.AccessToken, resp.RefreshToken)
	return &resp, nil
}

func (c *Client) Login(email, password string) (*AuthResponse, error) {
	var resp AuthResponse
	err := c.doPublic("POST", "/v1/auth/login", map[string]string{
		"email": email, "password": password,
	}, &resp)
	if err != nil {
		return nil, err
	}
	c.setTokens(resp.AccessToken, resp.RefreshToken)
	return &resp, nil
}

func (c *Client) Refresh() error {
	c.mu.Lock()
	rt := c.refreshToken
	c.mu.Unlock()

	var resp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	err := c.doPublic("POST", "/v1/auth/refresh", map[string]string{
		"refresh_token": rt,
	}, &resp)
	if err != nil {
		return err
	}
	c.setTokens(resp.AccessToken, resp.RefreshToken)
	return nil
}

// Devices

type Device struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Platform   string  `json:"platform"`
	PublicKey  string  `json:"public_key"`
	NetworkID  string  `json:"network_id"`
	AssignedIP string  `json:"assigned_ip"`
	Endpoint   *string `json:"endpoint"`
	LastSeenAt *string `json:"last_seen_at"`
	Online     bool    `json:"online"`
}

type RegisterDeviceRequest struct {
	Name      string `json:"name"`
	Platform  string `json:"platform"`
	PublicKey string `json:"public_key"`
	NetworkID string `json:"network_id"`
}

func (c *Client) RegisterDevice(req *RegisterDeviceRequest) (*Device, error) {
	var resp Device
	if err := c.do("POST", "/v1/devices", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ListDevices() ([]Device, error) {
	var resp struct {
		Devices []Device `json:"devices"`
	}
	if err := c.do("GET", "/v1/devices", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Devices, nil
}

func (c *Client) Heartbeat(deviceID string, endpoint string) error {
	body := map[string]string{}
	if endpoint != "" {
		body["endpoint"] = endpoint
	}
	var resp struct{}
	return c.do("POST", fmt.Sprintf("/v1/devices/%s/heartbeat", deviceID), body, &resp)
}

// Networks

type Network struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	CIDR        string `json:"cidr"`
	DeviceCount int    `json:"device_count"`
}

type Peer struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Platform   string  `json:"platform"`
	PublicKey  string  `json:"public_key"`
	AssignedIP string  `json:"assigned_ip"`
	Endpoint   *string `json:"endpoint"`
	Online     bool    `json:"online"`
	RelayHost  string  `json:"relay_host,omitempty"`
	RelayPort  int     `json:"relay_port,omitempty"`
}

// Relay represents a relay server returned by the control plane.
type Relay struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	AuthToken string `json:"auth_token"`
}

func (c *Client) ListNetworks() ([]Network, error) {
	var resp struct {
		Networks []Network `json:"networks"`
	}
	if err := c.do("GET", "/v1/networks", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Networks, nil
}

func (c *Client) GetPeers(networkID string) ([]Peer, error) {
	var resp struct {
		Peers []Peer `json:"peers"`
	}
	if err := c.do("GET", fmt.Sprintf("/v1/networks/%s/peers", networkID), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Peers, nil
}

// Relays

// GetRelays returns the list of active relay servers from the control plane.
func (c *Client) GetRelays() ([]Relay, error) {
	var resp struct {
		Relays []Relay `json:"relays"`
	}
	if err := c.do("GET", "/v1/relays", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Relays, nil
}

// RegisterWithRelay registers this device with a relay server and returns
// the assigned relay_port and relay_token (hex-encoded 16 bytes).
func (c *Client) RegisterWithRelay(relay Relay, deviceID string) (relayPort int, relayToken string, err error) {
	body := map[string]string{"device_id": deviceID}

	reqData, err := json.Marshal(body)
	if err != nil {
		return 0, "", err
	}

	req, err := http.NewRequest("POST", relay.Host+"/register", bytes.NewReader(reqData))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+relay.AuthToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("relay register: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, "", fmt.Errorf("relay register: status %d", resp.StatusCode)
	}

	var result struct {
		RelayHost  string `json:"relay_host"`
		RelayPort  int    `json:"relay_port"`
		RelayToken string `json:"relay_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, "", fmt.Errorf("relay register: decode: %w", err)
	}

	return result.RelayPort, result.RelayToken, nil
}

// StoreRelayEndpoint informs the control plane of this device's relay host and port
// so peers can discover it.
func (c *Client) StoreRelayEndpoint(deviceID, relayHost string, relayPort int) error {
	body := map[string]any{
		"relay_host": relayHost,
		"relay_port": relayPort,
	}
	var resp struct{}
	return c.do("POST", fmt.Sprintf("/v1/devices/%s/relay-endpoint", deviceID), body, &resp)
}

// Metrics

type MetricEntry struct {
	PeerDeviceID    string  `json:"peer_device_id"`
	LatencyMs       float64 `json:"latency_ms,omitempty"`
	JitterMs        float64 `json:"jitter_ms,omitempty"`
	PacketLossRatio float64 `json:"packet_loss_ratio,omitempty"`
	ThroughputTx    int64   `json:"throughput_tx_bytes,omitempty"`
	ThroughputRx    int64   `json:"throughput_rx_bytes,omitempty"`
	NATType         string  `json:"nat_type,omitempty"`
	ConnectionType  string  `json:"connection_type,omitempty"`
	Timestamp       string  `json:"timestamp"`
}

func (c *Client) PostMetrics(deviceID string, metrics []MetricEntry) error {
	body := map[string]any{
		"device_id": deviceID,
		"metrics":   metrics,
	}
	var resp struct{}
	return c.do("POST", "/v1/metrics", body, &resp)
}

// HTTP helpers

func (c *Client) setTokens(access, refresh string) {
	c.mu.Lock()
	c.accessToken = access
	c.refreshToken = refresh
	c.mu.Unlock()
	if c.onTokens != nil {
		c.onTokens(access, refresh)
	}
}

func (c *Client) doPublic(method, path string, body any, result any) error {
	return c.request(method, path, body, result, false)
}

func (c *Client) do(method, path string, body any, result any) error {
	err := c.request(method, path, body, result, true)
	if err != nil && isUnauthorized(err) {
		// Try refresh
		if refreshErr := c.Refresh(); refreshErr != nil {
			return fmt.Errorf("session expired, please login again")
		}
		return c.request(method, path, body, result, true)
	}
	return err
}

func (c *Client) request(method, path string, body any, result any, auth bool) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	if auth {
		c.mu.Lock()
		token := c.accessToken
		c.mu.Unlock()
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Error != "" {
			return &APIError{Status: resp.StatusCode, Message: apiErr.Error}
		}
		return &APIError{Status: resp.StatusCode, Message: string(respBody)}
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}

	return nil
}

type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error (%d): %s", e.Status, e.Message)
}

func isUnauthorized(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.Status == 401
	}
	return false
}
